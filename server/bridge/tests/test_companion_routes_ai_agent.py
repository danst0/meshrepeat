"""Tests für die KI-Agent-REST-Endpoints.

Scope: GET/PATCH ``/api/v1/companion/identities/{id}/ai_agent``,
Validierung der Hard-Limits, lazy Row-Anlage, Identity-Ownership-Check.
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
    cfg.storage.sqlite_path = tmp_path / "ai_agent.sqlite"
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


async def _create_identity(client: AsyncClient, *, name: str = "Antonia") -> str:
    resp = await client.post(
        "/api/v1/companion/identities",
        data={"name": name, "scope": "public"},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["id"]


@pytest.mark.asyncio
async def test_ai_agent_lazy_default(app_and_outbox) -> None:
    """GET liefert Defaults ohne den Row anzulegen."""
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="default@t")
        ident = await _create_identity(client)

        r = await client.get(f"/api/v1/companion/identities/{ident}/ai_agent")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["agent"]["enabled"] is False
        assert body["agent"]["interval_s"] == 14_400
        assert body["agent"]["dm_rate_per_hour"] == 6
        assert body["agent"]["respond_on_mention"] is True
        assert body["agent"]["respond_to_dms"] is True
        assert body["agent"]["created_at"] is None  # Row existiert noch nicht
        # Channels enthält mindestens den voreingestellten Public-Channel.
        assert any(ch["name"] == "public" for ch in body["channels"])
        assert body["caps"]["min_interval_s"] == 3600
        assert body["caps"]["max_interval_s"] == 86_400


@pytest.mark.asyncio
async def test_ai_agent_patch_enables_and_sets_next_post(app_and_outbox) -> None:
    """Toggle enabled=false→true setzt next_post_at und legt den Row an."""
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="enable@t")
        ident = await _create_identity(client)

        r = await client.patch(
            f"/api/v1/companion/identities/{ident}/ai_agent",
            data={
                "enabled": "true",
                "system_prompt": "Sei freundlich.",
                "interval_s": "7200",
            },
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["enabled"] is True
        assert body["system_prompt"] == "Sei freundlich."
        assert body["interval_s"] == 7200
        assert body["next_post_at"] is not None


@pytest.mark.asyncio
async def test_ai_agent_interval_out_of_range(app_and_outbox) -> None:
    """interval_s unter min_interval_s oder über max_interval_s → 400."""
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="rng@t")
        ident = await _create_identity(client)

        r_low = await client.patch(
            f"/api/v1/companion/identities/{ident}/ai_agent",
            data={"interval_s": "100"},
        )
        assert r_low.status_code == 400, r_low.text

        r_high = await client.patch(
            f"/api/v1/companion/identities/{ident}/ai_agent",
            data={"interval_s": "9999999"},
        )
        assert r_high.status_code == 400


@pytest.mark.asyncio
async def test_ai_agent_prompt_length_cap(app_and_outbox) -> None:
    """Prompt über max_prompt_chars → 400."""
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="prompt@t")
        ident = await _create_identity(client)

        r = await client.patch(
            f"/api/v1/companion/identities/{ident}/ai_agent",
            data={"system_prompt": "x" * 3000},
        )
        assert r.status_code == 400


@pytest.mark.asyncio
async def test_ai_agent_dm_rate_cap(app_and_outbox) -> None:
    """dm_rate_per_hour über dm_rate_cap_per_hour → 400."""
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="rate@t")
        ident = await _create_identity(client)

        r = await client.patch(
            f"/api/v1/companion/identities/{ident}/ai_agent",
            data={"dm_rate_per_hour": "999"},
        )
        assert r.status_code == 400


@pytest.mark.asyncio
async def test_ai_agent_delay_min_gt_max(app_and_outbox) -> None:
    """dm_min_delay_s > dm_max_delay_s → 400."""
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="delay@t")
        ident = await _create_identity(client)

        r = await client.patch(
            f"/api/v1/companion/identities/{ident}/ai_agent",
            data={"dm_min_delay_s": "120", "dm_max_delay_s": "60"},
        )
        assert r.status_code == 400


@pytest.mark.asyncio
async def test_ai_agent_channel_mismatch(app_and_outbox) -> None:
    """channel_id einer fremden Identity → 400."""
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="ch@t")
        ident_a = await _create_identity(client, name="A")
        ident_b = await _create_identity(client, name="B")

        # Channel von B holen
        rb = await client.get(f"/api/v1/companion/identities/{ident_b}/ai_agent")
        channel_b_id = rb.json()["channels"][0]["id"]

        # A versucht, B's Channel zu nutzen
        r = await client.patch(
            f"/api/v1/companion/identities/{ident_a}/ai_agent",
            data={"channel_id": channel_b_id},
        )
        assert r.status_code == 400


@pytest.mark.asyncio
async def test_ai_agent_ownership_check(app_and_outbox) -> None:
    """User B kann A's Identity nicht editieren → 404."""
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="own_a@t")
        ident = await _create_identity(client)
        # Logout via Cookie-Reset durch neue Session
        client.cookies.clear()
        await _signup_and_login(client, sender, email="own_b@t")

        r = await client.get(f"/api/v1/companion/identities/{ident}/ai_agent")
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_ai_agent_lookback_bounds(app_and_outbox) -> None:
    """lookback_minutes außerhalb 1..1440 → 400."""
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="lk@t")
        ident = await _create_identity(client)

        r_zero = await client.patch(
            f"/api/v1/companion/identities/{ident}/ai_agent",
            data={"lookback_minutes": "0"},
        )
        assert r_zero.status_code == 400

        r_huge = await client.patch(
            f"/api/v1/companion/identities/{ident}/ai_agent",
            data={"lookback_minutes": "5000"},
        )
        assert r_huge.status_code == 400


@pytest.mark.asyncio
async def test_ai_agent_blocked_names_round_trip(app_and_outbox) -> None:
    """Newline-separierte Blacklist wird gespeichert + zurückgegeben."""
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await _signup_and_login(client, sender, email="blk@t")
        ident = await _create_identity(client)

        r = await client.patch(
            f"/api/v1/companion/identities/{ident}/ai_agent",
            data={"blocked_peer_names": "OtherBot\nSpammer42"},
        )
        assert r.status_code == 200
        body = r.json()
        assert "OtherBot" in body["blocked_peer_names"]
        assert "Spammer42" in body["blocked_peer_names"]
