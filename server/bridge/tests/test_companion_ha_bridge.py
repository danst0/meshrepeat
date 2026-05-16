"""Tests für die HA-Bridge-Settings (Phase 1, nur Datenmodell + CRUD).

Phase 2 hängt den DM-Inbound-Pfad daran — der Test-Scope hier
endet bei: Bridge-Defaults lazy anlegen, Whitelist-CRUD, Entity-Katalog-
CRUD, Caps, Auth (read vs. admin Scope, Identity-Lock).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from meshcore_bridge.auth import passwords
from meshcore_bridge.config import AppConfig
from meshcore_bridge.web import build_app
from meshcore_bridge.web.auth_routes import set_email_sender

pytestmark = [
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
]

PASSWORD = "longenoughpw1!"
PUBKEY_A = "aa" * 32
PUBKEY_B = "bb" * 32


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
    cfg.storage.sqlite_path = tmp_path / "ha_bridge.sqlite"
    cfg.web.signup.require_email_verification = True
    cfg.web.base_url = "http://t"
    cfg.db_key = b"\x42" * 32

    sender = _RecordingEmailSender()
    app = build_app(cfg)
    async with app.router.lifespan_context(app):
        set_email_sender(sender)
        yield app, sender


async def _signup_and_login(client: AsyncClient, sender, *, email: str) -> None:
    await client.post("/signup", data={"email": email, "password": PASSWORD})
    verify_tok = sender.outbox[-1]["body"].split("token=")[1].strip()
    await client.get(f"/verify-email?token={verify_tok}")
    await client.post(
        "/login",
        data={"email": email, "password": PASSWORD},
        follow_redirects=False,
    )


async def _create_identity(
    client: AsyncClient, *, name: str = "Antonia"
) -> str:
    resp = await client.post(
        "/api/v1/companion/identities",
        data={"name": name, "scope": "public"},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["id"]


@pytest.mark.asyncio
async def test_ha_bridge_lazy_default(app_and_outbox) -> None:
    """GET liefert Defaults ohne den Row anzulegen, PATCH legt ihn an."""
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="default@t")
        ident = await _create_identity(client)

        r = await client.get(
            f"/api/v1/companion/identities/{ident}/ha_bridge"
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["bridge"]["enabled"] is False
        assert body["bridge"]["max_entities_per_query"] == 3
        assert body["bridge"]["rate_limit_per_min"] == 5
        assert body["bridge"]["ollama_model"] == "llama3.1:8b"
        assert body["bridge"]["created_at"] is None  # Row existiert noch nicht
        assert body["allowed_pubkeys"] == []
        assert body["entities"] == []

        r2 = await client.patch(
            f"/api/v1/companion/identities/{ident}/ha_bridge",
            data={"enabled": "true", "max_entities_per_query": "2"},
        )
        assert r2.status_code == 200, r2.text
        assert r2.json()["enabled"] is True
        assert r2.json()["max_entities_per_query"] == 2

        r3 = await client.get(
            f"/api/v1/companion/identities/{ident}/ha_bridge"
        )
        assert r3.json()["bridge"]["enabled"] is True
        assert r3.json()["bridge"]["created_at"] is not None


@pytest.mark.asyncio
async def test_ha_bridge_caps_rejected(app_and_outbox) -> None:
    """Cap-Verstöße werfen 400."""
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="caps@t")
        ident = await _create_identity(client)
        r = await client.patch(
            f"/api/v1/companion/identities/{ident}/ha_bridge",
            data={"max_entities_per_query": "99"},
        )
        assert r.status_code == 400, r.text
        r = await client.patch(
            f"/api/v1/companion/identities/{ident}/ha_bridge",
            data={"rate_limit_per_min": "999"},
        )
        assert r.status_code == 400


@pytest.mark.asyncio
async def test_ha_bridge_allowed_pubkey_crud(app_and_outbox) -> None:
    """Whitelist: hinzufügen, doppelt, ungültig, löschen."""
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="wl@t")
        ident = await _create_identity(client)

        # Hinzufügen
        r = await client.post(
            f"/api/v1/companion/identities/{ident}/ha_bridge/allowed",
            data={"pubkey_hex": PUBKEY_A, "label": "phone"},
        )
        assert r.status_code == 200, r.text
        entry_id = r.json()["id"]
        assert r.json()["pubkey_hex"] == PUBKEY_A

        # Doppelt → idempotent (200, gleiche ID)
        r2 = await client.post(
            f"/api/v1/companion/identities/{ident}/ha_bridge/allowed",
            data={"pubkey_hex": PUBKEY_A},
        )
        assert r2.status_code == 200
        assert r2.json()["id"] == entry_id

        # Falsches Hex
        r3 = await client.post(
            f"/api/v1/companion/identities/{ident}/ha_bridge/allowed",
            data={"pubkey_hex": "zz" * 32},
        )
        assert r3.status_code == 400

        # Falsche Länge
        r4 = await client.post(
            f"/api/v1/companion/identities/{ident}/ha_bridge/allowed",
            data={"pubkey_hex": "aa" * 16},
        )
        assert r4.status_code == 400

        # GET liefert
        r5 = await client.get(
            f"/api/v1/companion/identities/{ident}/ha_bridge"
        )
        assert len(r5.json()["allowed_pubkeys"]) == 1

        # Löschen
        r6 = await client.delete(
            f"/api/v1/companion/ha_bridge/allowed/{entry_id}"
        )
        assert r6.status_code == 200
        assert r6.json()["deleted"] is True


@pytest.mark.asyncio
async def test_ha_bridge_exposed_entity_crud(app_and_outbox) -> None:
    """Entity-Katalog: anlegen, doppelte entity_id → 409, patch, delete."""
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="ent@t")
        ident = await _create_identity(client)

        r = await client.post(
            f"/api/v1/companion/identities/{ident}/ha_bridge/entities",
            data={
                "entity_id": "sensor.balkon_temp",
                "alias": "Temp Balkon",
                "hint": "°C",
            },
        )
        assert r.status_code == 200, r.text
        ent_id = r.json()["id"]

        # Duplikat
        r2 = await client.post(
            f"/api/v1/companion/identities/{ident}/ha_bridge/entities",
            data={"entity_id": "sensor.balkon_temp", "alias": "X"},
        )
        assert r2.status_code == 409

        # Leerer alias (nur Whitespace, schafft es durch FastAPI-Validation
        # und wird von unserer manuellen Prüfung in 400 übersetzt).
        r3 = await client.post(
            f"/api/v1/companion/identities/{ident}/ha_bridge/entities",
            data={"entity_id": "sensor.x", "alias": "   "},
        )
        assert r3.status_code == 400

        # Patch alias
        r4 = await client.patch(
            f"/api/v1/companion/ha_bridge/entities/{ent_id}",
            data={"alias": "Balkon-Temp"},
        )
        assert r4.status_code == 200
        assert r4.json()["alias"] == "Balkon-Temp"

        # Delete
        r5 = await client.delete(f"/api/v1/companion/ha_bridge/entities/{ent_id}")
        assert r5.status_code == 200


@pytest.mark.asyncio
async def test_ha_bridge_cross_user_404(app_and_outbox) -> None:
    """User A darf nicht an HA-Bridge von User B."""
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    # User A
    async with AsyncClient(transport=transport, base_url="http://t") as a:
        await _signup_and_login(a, sender, email="alice@t")
        ident_a = await _create_identity(a, name="Antonia")

    # User B
    async with AsyncClient(transport=transport, base_url="http://t") as b:
        await _signup_and_login(b, sender, email="bob@t")
        # GET HA-Bridge von A → 404 (Owner-Check schlägt)
        r = await b.get(
            f"/api/v1/companion/identities/{ident_a}/ha_bridge"
        )
        assert r.status_code == 404
        r2 = await b.post(
            f"/api/v1/companion/identities/{ident_a}/ha_bridge/allowed",
            data={"pubkey_hex": PUBKEY_B},
        )
        assert r2.status_code == 404
