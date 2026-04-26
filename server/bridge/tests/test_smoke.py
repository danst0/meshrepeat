"""End-to-end-Smoke: Signup → Login → Repeater anlegen → WebSocket-Hello.

Wir nutzen ``httpx`` gegen die FastAPI-App via ASGITransport und
``websockets``-light over ASGI-WebSocket-Test-Client.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from starlette.testclient import TestClient

from meshcore_bridge.auth import passwords
from meshcore_bridge.config import AppConfig
from meshcore_bridge.web import build_app
from meshcore_bridge.web.auth_routes import set_email_sender
from meshcore_bridge.wire import (
    Hello,
    HelloAck,
    Packet,
    decode_frame,
    encode_frame,
)

# aiosqlite emits ResourceWarning on __del__ if a connection survives the
# event loop that opened it (happens when TestClient spins up its own loop
# alongside the async fixture). The warning is benign for tests — disabled.
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
def fast_argon2_for_smoke():
    original = passwords._DEFAULT_HASHER
    passwords._DEFAULT_HASHER = passwords.make_hasher(
        time_cost=1, memory_cost_kib=1024, parallelism=1
    )
    yield
    passwords._DEFAULT_HASHER = original


@pytest_asyncio.fixture
async def app_and_outbox(tmp_path: Path):
    cfg = AppConfig()
    cfg.storage.sqlite_path = tmp_path / "smoke.sqlite"
    cfg.web.signup.require_email_verification = True
    # disables Secure-flag on session cookie for tests
    cfg.web.base_url = "http://t"
    # CompanionService aktivieren — braucht 32-byte db_key
    cfg.db_key = b"\x42" * 32

    sender = _RecordingEmailSender()

    app = build_app(cfg)
    async with app.router.lifespan_context(app):
        # Lifespan überschreibt den Sender; nach Start wieder unseren setzen.
        set_email_sender(sender)
        yield app, sender


def _extract(page: str, marker: str) -> str:
    line = next(ln for ln in page.splitlines() if marker in ln)
    return line.strip().split()[-1]


async def _signup_login_create(
    client: AsyncClient,
    sender: _RecordingEmailSender,
    *,
    email: str,
    name: str,
    scope: str = "public",
) -> tuple[str, str]:
    """Run signup/verify/login and create a repeater. Returns (token, site_id)."""
    await client.post("/signup", data={"email": email, "password": PASSWORD})
    verify_token = sender.outbox[-1]["body"].split("token=")[1].strip()
    await client.get(f"/verify-email?token={verify_token}")
    await client.post(
        "/login",
        data={"email": email, "password": PASSWORD},
        follow_redirects=False,
    )
    resp = await client.post("/repeaters", data={"name": name, "scope": scope})
    page = resp.text
    return _extract(page, "set bridge.token"), _extract(page, "set bridge.site")


@pytest.mark.asyncio
async def test_signup_login_create_repeater(app_and_outbox) -> None:
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        # 1) Signup
        resp = await client.post(
            "/signup",
            data={"email": "alice@example.com", "password": PASSWORD},
        )
        assert resp.status_code == 200, resp.text
        assert sender.outbox, "verification email should be sent"
        token = sender.outbox[0]["body"].split("token=")[1].strip()

        # 2) Verify email
        resp = await client.get(f"/verify-email?token={token}")
        assert resp.status_code == 200
        assert "best" in resp.text.lower()

        # 3) Login
        resp = await client.post(
            "/login",
            data={"email": "alice@example.com", "password": PASSWORD},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/dashboard"

        # 4) Dashboard reachable
        resp = await client.get("/dashboard")
        assert resp.status_code == 200
        assert "Dashboard" in resp.text

        # 5) Create repeater — token + site_id im HTML
        resp = await client.post(
            "/repeaters",
            data={"name": "Site-A", "scope": "public"},
        )
        assert resp.status_code == 200, resp.text
        page = resp.text
        assert "set bridge.token" in page
        bridge_token = _extract(page, "set bridge.token")
        site_id = _extract(page, "set bridge.site")
        assert len(bridge_token) == 32
        assert len(site_id) == 36


@pytest.mark.asyncio
async def test_websocket_hello_handshake(app_and_outbox) -> None:
    app, sender = app_and_outbox

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        bridge_token, site_id = await _signup_login_create(
            client, sender, email="bob@example.com", name="Site-B"
        )

    with TestClient(app) as tc, tc.websocket_connect("/api/v1/bridge") as ws:
        ws.send_bytes(
            encode_frame(
                Hello(
                    site=UUID(site_id),
                    tok=bridge_token,
                    fw="v0",
                    proto=1,
                    scope="public",
                )
            )
        )
        ack = decode_frame(ws.receive_bytes())
        assert isinstance(ack, HelloAck)
        assert ack.proto == 1
        ws.close()


@pytest.mark.asyncio
async def test_websocket_rejects_bad_token(app_and_outbox) -> None:
    app, _ = app_and_outbox

    with (
        TestClient(app) as tc,
        pytest.raises(Exception),
        tc.websocket_connect("/api/v1/bridge") as ws,
    ):
        ws.send_bytes(
            encode_frame(
                Hello(
                    site=uuid4(),
                    tok="A" * 32,
                    fw="v0",
                    proto=1,
                    scope="public",
                )
            )
        )
        ws.receive_bytes()


@pytest.mark.asyncio
async def test_companion_detail_page_and_settings(app_and_outbox) -> None:
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await client.post(
            "/signup",
            data={"email": "comp@example.com", "password": PASSWORD},
        )
        verify_tok = sender.outbox[-1]["body"].split("token=")[1].strip()
        await client.get(f"/verify-email?token={verify_tok}")
        await client.post(
            "/login",
            data={"email": "comp@example.com", "password": PASSWORD},
            follow_redirects=False,
        )

        # Identity anlegen via REST → liefert id zurück
        resp = await client.post(
            "/api/v1/companion/identities",
            data={"name": "Antonia", "scope": "public"},
        )
        assert resp.status_code == 200, resp.text
        ident_id = resp.json()["id"]

        # Detail-Page erreichbar mit Tabs (chats unified, settings)
        resp = await client.get(f"/companion/{ident_id}/")
        assert resp.status_code == 200
        body = resp.text
        assert "Antonia" in body
        assert 'data-tab="settings"' in body
        assert 'data-tab="chats"' in body

        # Rename
        resp = await client.post(
            f"/companion/{ident_id}/rename",
            data={"name": "Beatrice"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        resp = await client.get(f"/companion/{ident_id}/")
        assert "Beatrice" in resp.text

        # Channel anlegen via UI-Form
        resp = await client.post(
            f"/companion/{ident_id}/channels",
            data={"name": "tech", "password": "hunter2"},
            follow_redirects=False,
        )
        assert resp.status_code == 303

        # Threads-API listet den Channel
        resp = await client.get(
            f"/api/v1/companion/identities/{ident_id}/threads"
        )
        assert resp.status_code == 200
        j = resp.json()
        chan_names = [c["name"] for c in j["channels"]]
        assert "public" in chan_names
        assert "tech" in chan_names

        # Channel löschen
        chan_id = next(c["id"] for c in j["channels"] if c["name"] == "tech")
        resp = await client.post(
            f"/companion/channels/{chan_id}/delete",
            follow_redirects=False,
        )
        assert resp.status_code == 303

        resp = await client.get(
            f"/api/v1/companion/identities/{ident_id}/threads"
        )
        chan_names = [c["name"] for c in resp.json()["channels"]]
        assert "tech" not in chan_names


@pytest.mark.asyncio
async def test_companion_index_lists_identities(app_and_outbox) -> None:
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await client.post(
            "/signup",
            data={"email": "list@example.com", "password": PASSWORD},
        )
        verify_tok = sender.outbox[-1]["body"].split("token=")[1].strip()
        await client.get(f"/verify-email?token={verify_tok}")
        await client.post(
            "/login",
            data={"email": "list@example.com", "password": PASSWORD},
            follow_redirects=False,
        )
        await client.post(
            "/api/v1/companion/identities",
            data={"name": "Frieda", "scope": "public"},
        )
        resp = await client.get("/companion/")
        assert resp.status_code == 200
        assert "Frieda" in resp.text
        # Detail-Link sichtbar
        assert "/companion/" in resp.text and "öffnen" in resp.text


@pytest.mark.asyncio
async def test_two_repeaters_route_pkt_between_them(app_and_outbox) -> None:
    app, sender = app_and_outbox

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        # carol single signup → mehrere Repeater
        await client.post(
            "/signup",
            data={"email": "carol@example.com", "password": PASSWORD},
        )
        verify_tok = sender.outbox[-1]["body"].split("token=")[1].strip()
        await client.get(f"/verify-email?token={verify_tok}")
        await client.post(
            "/login",
            data={"email": "carol@example.com", "password": PASSWORD},
            follow_redirects=False,
        )

        a = await client.post("/repeaters", data={"name": "A", "scope": "public"})
        a_tok = _extract(a.text, "set bridge.token")
        a_site = _extract(a.text, "set bridge.site")

        b = await client.post("/repeaters", data={"name": "B", "scope": "public"})
        b_tok = _extract(b.text, "set bridge.token")
        b_site = _extract(b.text, "set bridge.site")

    with (
        TestClient(app) as tc,
        tc.websocket_connect("/api/v1/bridge") as ws_a,
        tc.websocket_connect("/api/v1/bridge") as ws_b,
    ):
        ws_a.send_bytes(
            encode_frame(
                Hello(site=UUID(a_site), tok=a_tok, fw="v0", proto=1, scope="public")
            )
        )
        ws_b.send_bytes(
            encode_frame(
                Hello(site=UUID(b_site), tok=b_tok, fw="v0", proto=1, scope="public")
            )
        )
        assert isinstance(decode_frame(ws_a.receive_bytes()), HelloAck)
        assert isinstance(decode_frame(ws_b.receive_bytes()), HelloAck)

        payload = b"\xde\xad\xbe\xef"
        ws_a.send_bytes(encode_frame(Packet(raw=payload)))

        received = decode_frame(ws_b.receive_bytes())
        assert isinstance(received, Packet)
        assert received.raw == payload

        ws_a.close()
        ws_b.close()
