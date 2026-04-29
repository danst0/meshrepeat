"""Aggregations-Endpoint /api/v1/admin/inspector/stats.

Befüllt RawPacket direkt über die App-DB-Session (nach dem Lifespan-Start),
promoted den ersten User zu admin und prüft die Aggregationen via HTTP.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import update

from meshcore_bridge.auth import passwords
from meshcore_bridge.config import AppConfig
from meshcore_bridge.db import RawPacket, User, get_session
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
def fast_argon2_for_admin_stats():
    original = passwords._DEFAULT_HASHER
    passwords._DEFAULT_HASHER = passwords.make_hasher(
        time_cost=1, memory_cost_kib=1024, parallelism=1
    )
    yield
    passwords._DEFAULT_HASHER = original


@pytest_asyncio.fixture
async def admin_client(tmp_path: Path):
    """FastAPI-App mit eingeloggtem admin-User und befüllter raw_packets-Tabelle.

    Yields ``(client, site_a, site_b)`` — die UUIDs der zwei Test-Sites.
    """
    cfg = AppConfig()
    cfg.storage.sqlite_path = tmp_path / "stats.sqlite"
    cfg.web.base_url = "http://t"
    cfg.db_key = b"\x42" * 32

    sender = _RecordingEmailSender()
    app = build_app(cfg)
    async with app.router.lifespan_context(app):
        set_email_sender(sender)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://t") as client:
            await client.post(
                "/signup",
                data={"email": "admin@example.com", "password": PASSWORD},
            )
            verify_tok = sender.outbox[-1]["body"].split("token=")[1].strip()
            await client.get(f"/verify-email?token={verify_tok}")
            await client.post(
                "/login",
                data={"email": "admin@example.com", "password": PASSWORD},
                follow_redirects=False,
            )
            async with get_session() as db:
                await db.execute(
                    update(User).where(User.email == "admin@example.com").values(role="admin")
                )
                await db.commit()

            site_a = uuid4()
            site_b = uuid4()
            now = datetime.now(UTC)
            rows = [
                # Site A — 3 ADVERT, 1 TXT_MSG, 1 dropped TRACE
                RawPacket(
                    ts=now - timedelta(minutes=2),
                    site_id=site_a,
                    site_name="A",
                    scope="public",
                    route_type="FLOOD",
                    payload_type="ADVERT",
                    raw=b"\x10" * 100,
                    path_hashes="",
                ),
                RawPacket(
                    ts=now - timedelta(minutes=3),
                    site_id=site_a,
                    site_name="A",
                    scope="public",
                    route_type="FLOOD",
                    payload_type="ADVERT",
                    raw=b"\x10" * 100,
                    path_hashes="",
                ),
                RawPacket(
                    ts=now - timedelta(minutes=4),
                    site_id=site_a,
                    site_name="A",
                    scope="public",
                    route_type="FLOOD",
                    payload_type="ADVERT",
                    raw=b"\x10" * 100,
                    path_hashes="",
                ),
                RawPacket(
                    ts=now - timedelta(minutes=1),
                    site_id=site_a,
                    site_name="A",
                    scope="public",
                    route_type="DIRECT",
                    payload_type="TXT_MSG",
                    raw=b"\x20" * 50,
                    path_hashes="aa",
                ),
                RawPacket(
                    ts=now - timedelta(minutes=2),
                    site_id=site_a,
                    site_name="A",
                    scope="public",
                    route_type="FLOOD",
                    payload_type="TRACE",
                    raw=b"\x30" * 30,
                    path_hashes="",
                    dropped_reason="rate-limit",
                ),
                # Site B — 2 TXT_MSG (eins davon älter als 5 min)
                RawPacket(
                    ts=now - timedelta(minutes=2),
                    site_id=site_b,
                    site_name="B",
                    scope="public",
                    route_type="DIRECT",
                    payload_type="TXT_MSG",
                    raw=b"\x40" * 80,
                    path_hashes="bb",
                ),
                RawPacket(
                    ts=now - timedelta(hours=2),
                    site_id=site_b,
                    site_name="B",
                    scope="public",
                    route_type="DIRECT",
                    payload_type="TXT_MSG",
                    raw=b"\x40" * 80,
                    path_hashes="bb",
                ),
            ]
            async with get_session() as db:
                db.add_all(rows)
                await db.commit()

            yield client, site_a, site_b


@pytest.mark.asyncio
async def test_stats_total_24h(admin_client) -> None:
    client, _, _ = admin_client
    resp = await client.get("/api/v1/admin/inspector/stats?since=24h")
    assert resp.status_code == 200, resp.text
    j = resp.json()
    assert j["since"] == "24h"
    assert j["total"]["count"] == 7
    # 3*100 (ADVERT) + 50 (TXT_MSG A) + 30 (TRACE) + 80 + 80 (TXT_MSG B) = 540
    assert j["total"]["bytes"] == 540


@pytest.mark.asyncio
async def test_stats_by_payload_type_sorted(admin_client) -> None:
    client, _, _ = admin_client
    resp = await client.get("/api/v1/admin/inspector/stats?since=24h")
    j = resp.json()
    # ADVERT=3, TXT_MSG=3, TRACE=1 — Reihenfolge nach count desc; ADVERT/TXT
    # können tauschen (gleicher count), aber TRACE muss zuletzt stehen.
    keys = [r["key"] for r in j["by_payload_type"]]
    counts = {r["key"]: r["count"] for r in j["by_payload_type"]}
    assert counts == {"ADVERT": 3, "TXT_MSG": 3, "TRACE": 1}
    assert keys[-1] == "TRACE"
    advert = next(r for r in j["by_payload_type"] if r["key"] == "ADVERT")
    assert advert["bytes"] == 300


@pytest.mark.asyncio
async def test_stats_since_5m_excludes_old(admin_client) -> None:
    client, _, _ = admin_client
    resp = await client.get("/api/v1/admin/inspector/stats?since=5m")
    j = resp.json()
    # Die TXT_MSG von Site B vor 2h fällt raus → 6 statt 7.
    assert j["total"]["count"] == 6


@pytest.mark.asyncio
async def test_stats_dropped_only_lists_dropped(admin_client) -> None:
    client, _, _ = admin_client
    resp = await client.get("/api/v1/admin/inspector/stats?since=24h")
    j = resp.json()
    dropped = j["by_dropped_reason"]
    assert dropped == [{"reason": "rate-limit", "count": 1}]
    # Per-Site: A hat genau 1 dropped, B keinen.
    by_site = {r["site_name"]: r for r in j["by_site"]}
    assert by_site["A"]["dropped"] == 1
    assert by_site["B"]["dropped"] == 0


@pytest.mark.asyncio
async def test_stats_by_site_sorted_by_count(admin_client) -> None:
    client, _, _ = admin_client
    resp = await client.get("/api/v1/admin/inspector/stats?since=24h")
    j = resp.json()
    sites = j["by_site"]
    # A hat 5, B hat 2 (innerhalb 24h) → A vor B.
    assert [s["site_name"] for s in sites] == ["A", "B"]
    assert sites[0]["count"] == 5
    assert sites[1]["count"] == 2


@pytest.mark.asyncio
async def test_stats_invalid_since_returns_400(admin_client) -> None:
    client, _, _ = admin_client
    resp = await client.get("/api/v1/admin/inspector/stats?since=10s")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_stats_requires_admin(tmp_path: Path) -> None:
    cfg = AppConfig()
    cfg.storage.sqlite_path = tmp_path / "anon.sqlite"
    cfg.web.base_url = "http://t"
    cfg.db_key = b"\x42" * 32

    app = build_app(cfg)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://t") as client:
            resp = await client.get("/api/v1/admin/inspector/stats")
            # Anonymer Aufruf → 401 (kein Login-Cookie).
            assert resp.status_code == 401
