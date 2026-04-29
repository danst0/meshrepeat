"""Tests für die in v0.1.0 ergänzten Companion-Endpoints:
Healthcheck, Cursor-Pagination, FTS5-Volltextsuche und SSE-Stream.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote
from uuid import UUID

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from meshcore_bridge.auth import passwords
from meshcore_bridge.config import AppConfig
from meshcore_bridge.db import CompanionContact, CompanionMessage, get_session
from meshcore_bridge.web import build_app
from meshcore_bridge.web.auth_routes import set_email_sender

pytestmark = [
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
]

PASSWORD = "longenoughpw1!"


class _RecordingEmailSender:
    def __init__(self) -> None:
        self.outbox: list[dict[str, str]] = []

    async def send(self, *, to: str, subject: str, body: str) -> None:
        self.outbox.append({"to": to, "subject": subject, "body": body})


@pytest.fixture(autouse=True)
def fast_argon2():
    original = passwords._DEFAULT_HASHER
    passwords._DEFAULT_HASHER = passwords.make_hasher(
        time_cost=1, memory_cost_kib=1024, parallelism=1
    )
    yield
    passwords._DEFAULT_HASHER = original


@pytest_asyncio.fixture
async def app_and_outbox(tmp_path: Path):
    cfg = AppConfig()
    cfg.storage.sqlite_path = tmp_path / "endpoints.sqlite"
    cfg.web.signup.require_email_verification = True
    cfg.web.base_url = "http://t"
    cfg.db_key = b"\x42" * 32

    sender = _RecordingEmailSender()
    app = build_app(cfg)
    async with app.router.lifespan_context(app):
        set_email_sender(sender)
        yield app, sender


async def _login_and_create_identity(
    client: AsyncClient, sender, *, email: str, name: str = "Antonia"
) -> str:
    await client.post("/signup", data={"email": email, "password": PASSWORD})
    verify_tok = sender.outbox[-1]["body"].split("token=")[1].strip()
    await client.get(f"/verify-email?token={verify_tok}")
    await client.post("/login", data={"email": email, "password": PASSWORD}, follow_redirects=False)
    resp = await client.post("/api/v1/companion/identities", data={"name": name, "scope": "public"})
    assert resp.status_code == 200, resp.text
    return resp.json()["id"]


async def _seed_dm_messages(identity_id: str, peer: bytes, n: int) -> None:
    """Direkt in die DB schreiben, ohne durch den Companion-Service zu gehen.
    base_ts liegt n Sekunden in der Vergangenheit damit ts unterschiedlich sind."""
    base = datetime.now(UTC) - timedelta(seconds=n + 1)
    async with get_session() as db:
        for i in range(n):
            db.add(
                CompanionMessage(
                    identity_id=UUID(identity_id),
                    direction="in",
                    payload_type=0,
                    peer_pubkey=peer,
                    peer_name="Bertha",
                    text=f"Nachricht {i:03d}: hallo Welt",
                    raw=b"\x00",
                    ts=base + timedelta(seconds=i),
                )
            )
        await db.commit()


@pytest.mark.asyncio
async def test_healthz_and_readyz(app_and_outbox) -> None:
    app, _ = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        r = await client.get("/healthz")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}

        r = await client.get("/readyz")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ready"
        assert body["db_ok"] is True


@pytest.mark.asyncio
async def test_dm_pagination_cursor(app_and_outbox) -> None:
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        ident_id = await _login_and_create_identity(client, sender, email="page@example.com")
        peer = bytes(range(32))
        await _seed_dm_messages(ident_id, peer, 80)

        r = await client.get(f"/api/v1/companion/identities/{ident_id}/dms/{peer.hex()}?limit=30")
        assert r.status_code == 200, r.text
        first = r.json()
        assert len(first["messages"]) == 30
        assert first["next_cursor"] is not None
        # älteste Page-Message zuerst (chronologisch)
        assert first["messages"][0]["text"].startswith("Nachricht ")
        first_ids = [m["id"] for m in first["messages"]]

        cursor = first["next_cursor"]
        r2 = await client.get(
            f"/api/v1/companion/identities/{ident_id}/dms/{peer.hex()}"
            f"?limit=30&before_ts={quote(cursor, safe='')}"
        )
        assert r2.status_code == 200, r2.text
        second = r2.json()
        assert len(second["messages"]) == 30
        # Sets müssen disjunkt sein — Cursor liefert echte ältere Page
        second_ids = [m["id"] for m in second["messages"]]
        assert set(first_ids).isdisjoint(second_ids)

        # dritte Page: nur 20 verbleibend → next_cursor=None
        cursor2 = second["next_cursor"]
        r3 = await client.get(
            f"/api/v1/companion/identities/{ident_id}/dms/{peer.hex()}"
            f"?limit=30&before_ts={quote(cursor2, safe='')}"
        )
        assert r3.status_code == 200, r3.text
        third = r3.json()
        assert len(third["messages"]) == 20
        assert third["next_cursor"] is None


@pytest.mark.asyncio
async def test_search_endpoint_finds_messages(app_and_outbox) -> None:
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        ident_id = await _login_and_create_identity(client, sender, email="search@example.com")
        peer = bytes(range(32))
        await _seed_dm_messages(ident_id, peer, 5)
        # eine spezielle Message
        async with get_session() as db:
            db.add(
                CompanionMessage(
                    identity_id=UUID(ident_id),
                    direction="in",
                    payload_type=0,
                    peer_pubkey=peer,
                    peer_name="Bertha",
                    text="Geheimwort: Pumpernickel zur Mittagszeit.",
                    raw=b"\x00",
                    ts=datetime.now(UTC),
                )
            )
            await db.commit()

        r = await client.get(f"/api/v1/companion/identities/{ident_id}/search?q=Pumpernickel")
        assert r.status_code == 200, r.text
        hits = r.json()["hits"]
        assert len(hits) >= 1
        h0 = hits[0]
        assert h0["kind"] == "dm"
        assert "Pumpernickel" in h0["snippet"] or "<mark>" in h0["snippet"]
        assert h0["peer_pubkey_hex"] == peer.hex()


@pytest.mark.asyncio
async def test_search_rejects_short_query(app_and_outbox) -> None:
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        ident_id = await _login_and_create_identity(client, sender, email="shortq@example.com")
        r = await client.get(f"/api/v1/companion/identities/{ident_id}/search?q=x")
        assert r.status_code == 422  # min_length=2


@pytest.mark.asyncio
async def test_sse_stream_subscribes_and_publishes(app_and_outbox) -> None:
    """Direkter EventBus-Test: subscribe → publish → Event landet in der
    Queue. Den HTTP-Stream selbst testen wir nicht via httpx — ASGITransport
    puffert StreamingResponse-Bodies, das Verhalten am echten Socket ist
    aber durch fastapi's StreamingResponse abgedeckt."""
    app, _ = app_and_outbox
    bus = app.state.companion_events
    from uuid import uuid4

    ident = uuid4()
    q = bus.subscribe(ident)
    await bus.publish(ident, {"type": "dm", "text": "hallo"})
    evt = await asyncio.wait_for(q.get(), timeout=1.0)
    assert evt["type"] == "dm"
    assert evt["text"] == "hallo"
    bus.unsubscribe(ident, q)
    # Keine Subscriber mehr → publish ist no-op (kein KeyError)
    await bus.publish(ident, {"type": "dm", "text": "still"})


@pytest.mark.asyncio
async def test_login_request_endpoint(app_and_outbox) -> None:
    """POST /contacts/{hex}/login: Endpoint funktioniert + Validierung +
    Pending-Tracker bekommt einen REQ_TYPE_LOGIN-Eintrag."""
    from meshcore_companion.crypto import LocalIdentity

    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        ident_id = await _login_and_create_identity(client, sender, email="login@example.com")
        peer_hex = LocalIdentity.generate().pub_key.hex()

        r = await client.post(
            f"/api/v1/companion/identities/{ident_id}/contacts/{peer_hex}/login",
            data={"password": ""},
        )
        assert r.status_code == 200, r.text
        assert r.json()["ok"] is True

        svc = app.state.companion_service
        login_pendings = [v for v in svc._pending_reqs.values() if v[1] == svc.REQ_TYPE_LOGIN]
        assert len(login_pendings) == 1


@pytest.mark.asyncio
async def test_status_request_endpoint(app_and_outbox) -> None:
    """POST /contacts/{hex}/status: Endpoint funktioniert + Validierung.
    Wir nutzen einen *echten* Ed25519-Pubkey, weil
    ``calc_shared_secret`` ihn zu Curve25519 konvertiert."""
    from meshcore_companion.crypto import LocalIdentity

    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        ident_id = await _login_and_create_identity(client, sender, email="status@example.com")
        peer_hex = LocalIdentity.generate().pub_key.hex()

        r = await client.post(f"/api/v1/companion/identities/{ident_id}/contacts/{peer_hex}/status")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ok"] is True

        # Tag in pending_reqs — bestätigt, dass Service den REQ getrackt hat
        svc = app.state.companion_service
        assert len(svc._pending_reqs) >= 1, "expected pending status request"

        # Falsches Pubkey-Format → 400
        r = await client.post(
            f"/api/v1/companion/identities/{ident_id}/contacts/notvalidhex/status"
        )
        assert r.status_code == 400


async def _seed_contacts(
    identity_id: str, points: list[tuple[bytes, float | None, float | None, str]]
) -> None:
    now = datetime.now(UTC)
    async with get_session() as db:
        for peer, lat, lon, name in points:
            db.add(
                CompanionContact(
                    identity_id=UUID(identity_id),
                    peer_pubkey=peer,
                    peer_name=name,
                    last_seen_at=now,
                    last_lat=lat,
                    last_lon=lon,
                )
            )
        await db.commit()


@pytest.mark.asyncio
async def test_map_endpoint_filters_outliers(app_and_outbox) -> None:
    """Cluster aus Berlin-nahen Punkten + Null-Insel + Antipode → der
    Endpoint liefert per Default nur die Cluster-Punkte; mit
    ``include_outliers=1`` alle gültigen."""
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        ident_id = await _login_and_create_identity(client, sender, email="map@example.com")
        # 11 Cluster-Punkte (Berlin-Region) — genug für cluster_outlier_mask
        points: list[tuple[bytes, float | None, float | None, str]] = [
            (
                bytes([i]) + bytes(31),
                52.5 + i * 0.01,
                13.4 + i * 0.01,
                f"berlin-{i}",
            )
            for i in range(11)
        ]
        # Null-Insel (Hard-Filter)
        points.append((b"\xaa" + bytes(31), 0.0, 0.0, "null-insel"))
        # Antipode (Cluster-Filter)
        points.append((b"\xbb" + bytes(31), -33.86, 151.21, "sydney"))
        await _seed_contacts(ident_id, points)

        r = await client.get(f"/api/v1/companion/identities/{ident_id}/map")
        assert r.status_code == 200, r.text
        names = {p["peer_name"] for p in r.json()}
        assert "null-insel" not in names
        assert "sydney" not in names
        assert names == {f"berlin-{i}" for i in range(11)}

        r2 = await client.get(f"/api/v1/companion/identities/{ident_id}/map?include_outliers=1")
        assert r2.status_code == 200, r2.text
        names2 = {p["peer_name"] for p in r2.json()}
        # Null-Insel kommt zurück (SQL filtert nur NULL), Sydney auch.
        assert "null-insel" in names2
        assert "sydney" in names2


@pytest.mark.asyncio
async def test_admin_cleanup_coords_dry_run_and_apply(app_and_outbox) -> None:
    """POST /api/v1/companion/admin/identities/{id}/cleanup-coords:
    dry_run=1 → liefert Kandidaten, ändert nichts; dry_run=0 → setzt
    last_lat/last_lon auf NULL."""
    app, _sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        # Admin-User direkt anlegen — Signup macht standardmäßig "user".
        from meshcore_bridge.db import User

        async with get_session() as db:
            db.add(
                User(
                    email="admin@example.com",
                    password_hash=passwords.hash_password(PASSWORD),
                    role="admin",
                    email_verified_at=datetime.now(UTC),
                )
            )
            await db.commit()
        await client.post(
            "/login",
            data={"email": "admin@example.com", "password": PASSWORD},
            follow_redirects=False,
        )
        resp = await client.post(
            "/api/v1/companion/identities",
            data={"name": "Antonia", "scope": "public"},
        )
        assert resp.status_code == 200, resp.text
        ident_id = resp.json()["id"]

        points: list[tuple[bytes, float | None, float | None, str]] = [
            (
                bytes([i]) + bytes(31),
                52.5 + i * 0.01,
                13.4 + i * 0.01,
                f"berlin-{i}",
            )
            for i in range(11)
        ]
        points.append((b"\xaa" + bytes(31), 0.0, 0.0, "null-insel"))
        points.append((b"\xbb" + bytes(31), -33.86, 151.21, "sydney"))
        await _seed_contacts(ident_id, points)

        r = await client.post(
            f"/api/v1/companion/admin/identities/{ident_id}/cleanup-coords?dry_run=1"
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["dry_run"] is True
        assert body["invalid"] == 1
        assert body["cluster_outliers"] == 1
        # Nichts in DB geändert.
        async with get_session() as db:
            from sqlalchemy import select as sa_select

            rows = list(
                (
                    await db.execute(
                        sa_select(CompanionContact).where(
                            CompanionContact.identity_id == UUID(ident_id),
                        )
                    )
                ).scalars()
            )
        assert sum(1 for r in rows if r.last_lat is not None) == 13

        r2 = await client.post(
            f"/api/v1/companion/admin/identities/{ident_id}/cleanup-coords?dry_run=0"
        )
        assert r2.status_code == 200, r2.text
        body2 = r2.json()
        assert body2["applied"] == 2
        async with get_session() as db:
            from sqlalchemy import select as sa_select

            rows = list(
                (
                    await db.execute(
                        sa_select(CompanionContact).where(
                            CompanionContact.identity_id == UUID(ident_id),
                        )
                    )
                ).scalars()
            )
        # 11 Berlin-Kontakte mit lat/lon übrig, 2 auf NULL gesetzt.
        with_coords = [r for r in rows if r.last_lat is not None]
        without_coords = [r for r in rows if r.last_lat is None]
        assert len(with_coords) == 11
        assert len(without_coords) == 2


@pytest.mark.asyncio
async def test_sse_endpoint_requires_auth(app_and_outbox) -> None:
    """Ohne Login redirected /stream auf /login (current_user_required).
    Den 200-Pfad testen wir nicht über ASGITransport — der puffert
    StreamingResponse-Bodies und blockiert bis EOF, was bei keep-alive nie
    eintritt. Echtes Verhalten ist über CompanionEventBus-Test abgedeckt."""
    app, _ = app_and_outbox
    transport = ASGITransport(app=app)
    from uuid import uuid4

    async with AsyncClient(transport=transport, base_url="http://t") as client:
        r = await client.get(
            f"/api/v1/companion/identities/{uuid4()}/stream",
            follow_redirects=False,
        )
        assert r.status_code in (303, 401, 403)
