"""Tests für die Companion-API-Bearer-Tokens.

Deckt ab: Erstellen, Authentifizieren, Scope-Check (read/write), Identity-
Lock (Token zu Identity A spricht nicht Identity B), Revoke und Expiry.
Management-Endpoints (POST /tokens, /tokens/revoke) bleiben Cookie-only —
das wird hier auch geprüft.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
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
    cfg.storage.sqlite_path = tmp_path / "tokens.sqlite"
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
        "/login", data={"email": email, "password": PASSWORD}, follow_redirects=False
    )


async def _create_identity(
    client: AsyncClient, *, name: str = "Antonia"
) -> tuple[str, str]:
    resp = await client.post(
        "/api/v1/companion/identities", data={"name": name, "scope": "public"}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    return body["id"], body["pubkey_hex"]


async def _create_token(
    client: AsyncClient,
    identity_id: str,
    *,
    name: str = "bot",
    scopes: str = "read,write",
    expires_at: str = "",
) -> tuple[str, dict]:
    data = {"name": name, "scopes": scopes}
    if expires_at:
        data["expires_at"] = expires_at
    resp = await client.post(
        f"/api/v1/companion/identities/{identity_id}/tokens", data=data
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    return payload["token"], payload


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_token_lists_and_reads_locked_identity(app_and_outbox) -> None:
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="lock@t")
        a, _a_pk = await _create_identity(client, name="Antonia")
        b, _b_pk = await _create_identity(client, name="Bertha")
        token, _ = await _create_token(client, a, scopes="read")

    # Frischer Client ohne Cookie — nur Bearer:
    async with AsyncClient(transport=transport, base_url="http://t") as bot:
        r = await bot.get("/api/v1/companion/identities", headers=_bearer(token))
        assert r.status_code == 200, r.text
        ids = [i["id"] for i in r.json()]
        assert ids == [a], f"expected only locked identity, got {ids}"

        r2 = await bot.get(
            f"/api/v1/companion/identities/{b}/threads", headers=_bearer(token)
        )
        assert r2.status_code == 403, r2.text


@pytest.mark.asyncio
async def test_token_read_scope_blocks_write(app_and_outbox) -> None:
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="ro@t")
        a, _ = await _create_identity(client)
        _, peer_hex = await _create_identity(client, name="Bertha")
        token, _ = await _create_token(client, a, scopes="read")

    async with AsyncClient(transport=transport, base_url="http://t") as bot:
        r = await bot.post(
            "/api/v1/companion/messages/dm",
            data={"identity_id": a, "peer_pubkey_hex": peer_hex, "text": "hi"},
            headers=_bearer(token),
        )
        assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_token_write_scope_sends_dm(app_and_outbox) -> None:
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="rw@t")
        a, _ = await _create_identity(client)
        _, peer_hex = await _create_identity(client, name="Bertha")
        token, _ = await _create_token(client, a, scopes="read,write")

    async with AsyncClient(transport=transport, base_url="http://t") as bot:
        r = await bot.post(
            "/api/v1/companion/messages/dm",
            data={"identity_id": a, "peer_pubkey_hex": peer_hex, "text": "hi"},
            headers=_bearer(token),
        )
        assert r.status_code == 200, r.text
        assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_token_for_other_identity_rejected(app_and_outbox) -> None:
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="xid@t")
        a, _ = await _create_identity(client, name="Antonia")
        b, peer_hex = await _create_identity(client, name="Bertha")
        token, _ = await _create_token(client, a, scopes="read,write")

    async with AsyncClient(transport=transport, base_url="http://t") as bot:
        # Token zu A versucht, eine DM aus B zu schicken
        r = await bot.post(
            "/api/v1/companion/messages/dm",
            data={"identity_id": b, "peer_pubkey_hex": peer_hex, "text": "hi"},
            headers=_bearer(token),
        )
        assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_revoked_token_rejected(app_and_outbox) -> None:
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="rev@t")
        a, _ = await _create_identity(client)
        token, payload = await _create_token(client, a, scopes="read")
        rr = await client.post(f"/api/v1/companion/tokens/{payload['id']}/revoke")
        assert rr.status_code == 200, rr.text
        assert rr.json()["revoked_at"] is not None

    async with AsyncClient(transport=transport, base_url="http://t") as bot:
        r = await bot.get("/api/v1/companion/identities", headers=_bearer(token))
        assert r.status_code == 401, r.text


@pytest.mark.asyncio
async def test_expired_token_rejected(app_and_outbox) -> None:
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    past = (datetime.now(UTC) - timedelta(seconds=60)).isoformat()
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="exp@t")
        a, _ = await _create_identity(client)
        token, _ = await _create_token(client, a, scopes="read", expires_at=past)

    async with AsyncClient(transport=transport, base_url="http://t") as bot:
        r = await bot.get("/api/v1/companion/identities", headers=_bearer(token))
        assert r.status_code == 401, r.text


@pytest.mark.asyncio
async def test_management_routes_reject_token(app_and_outbox) -> None:
    """Token darf sich nicht selbst verlängern oder neue Tokens erzeugen —
    Management-Endpoints sind Cookie-only."""
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="mgmt@t")
        a, _ = await _create_identity(client)
        token, payload = await _create_token(client, a, scopes="read,write")

    async with AsyncClient(transport=transport, base_url="http://t") as bot:
        # Token versucht neuen Token zu erzeugen
        r = await bot.post(
            f"/api/v1/companion/identities/{a}/tokens",
            data={"name": "shadow", "scopes": "read"},
            headers=_bearer(token),
        )
        assert r.status_code == 401, r.text
        # Token versucht sich selbst zu revoken
        r2 = await bot.post(
            f"/api/v1/companion/tokens/{payload['id']}/revoke",
            headers=_bearer(token),
        )
        assert r2.status_code == 401, r2.text


@pytest.mark.asyncio
async def test_invalid_scope_rejected(app_and_outbox) -> None:
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="badscope@t")
        a, _ = await _create_identity(client)
        r = await client.post(
            f"/api/v1/companion/identities/{a}/tokens",
            data={"name": "bot", "scopes": "superuser"},
        )
        assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_admin_scope_can_trigger_advert(app_and_outbox) -> None:
    """Mit ``admin``-Scope darf der Token Identity-Einstellungen
    anstoßen (hier: Advert pushen)."""
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="adv@t")
        a, _ = await _create_identity(client)
        token, _ = await _create_token(client, a, scopes="admin")

    async with AsyncClient(transport=transport, base_url="http://t") as bot:
        r = await bot.post(
            f"/api/v1/companion/identities/{a}/advert", headers=_bearer(token)
        )
        assert r.status_code == 200, r.text
        assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_write_scope_cannot_trigger_admin_routes(app_and_outbox) -> None:
    """Ein Token mit nur ``write`` (DM/Channel senden) darf keine
    Identity-Einstellungen ändern."""
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="wo@t")
        a, _ = await _create_identity(client)
        token, _ = await _create_token(client, a, scopes="write")

    async with AsyncClient(transport=transport, base_url="http://t") as bot:
        r = await bot.post(
            f"/api/v1/companion/identities/{a}/advert", headers=_bearer(token)
        )
        assert r.status_code == 403, r.text
        r2 = await bot.post(
            f"/api/v1/companion/identities/{a}/echo",
            data={"enabled": "true"},
            headers=_bearer(token),
        )
        assert r2.status_code == 403, r2.text


@pytest.mark.asyncio
async def test_admin_token_cannot_create_identity_or_tokens(app_and_outbox) -> None:
    """Auch mit ``admin``-Scope bleiben Identity-Erstellung und Token-
    Management Cookie-only — sonst würde ein gestohlener Token sich
    selbst persistieren oder neue Identities anlegen."""
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="escal@t")
        a, _ = await _create_identity(client)
        token, payload = await _create_token(client, a, scopes="read,write,admin")

    async with AsyncClient(transport=transport, base_url="http://t") as bot:
        r = await bot.post(
            "/api/v1/companion/identities",
            data={"name": "Phantom", "scope": "public"},
            headers=_bearer(token),
        )
        assert r.status_code == 401, r.text
        r2 = await bot.post(
            f"/api/v1/companion/identities/{a}/tokens",
            data={"name": "shadow", "scopes": "admin"},
            headers=_bearer(token),
        )
        assert r2.status_code == 401, r2.text
        r3 = await bot.post(
            f"/api/v1/companion/tokens/{payload['id']}/revoke",
            headers=_bearer(token),
        )
        assert r3.status_code == 401, r3.text


@pytest.mark.asyncio
async def test_bogus_bearer_rejected(app_and_outbox) -> None:
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="bogus@t")
        await _create_identity(client)  # type: ignore[func-returns-value]

    async with AsyncClient(transport=transport, base_url="http://t") as bot:
        r = await bot.get(
            "/api/v1/companion/identities",
            headers={"Authorization": "Bearer NOT-A-REAL-TOKEN"},
        )
        assert r.status_code == 401, r.text
