"""End-to-end-Smoke: Signup → Login → Repeater anlegen → WebSocket-Hello.

Wir nutzen ``httpx`` gegen die FastAPI-App via ASGITransport und
``websockets``-light over ASGI-WebSocket-Test-Client.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from starlette.testclient import TestClient

from meshcore_bridge.auth import passwords
from meshcore_bridge.config import AppConfig
from meshcore_bridge.web import build_app
from meshcore_bridge.web.auth_routes import set_email_sender
from meshcore_bridge.wire import Hello, HelloAck, Packet, decode_frame, encode_frame

# aiosqlite emits ResourceWarning on __del__ if a connection survives the
# event loop that opened it (happens when TestClient spins up its own loop
# alongside the async fixture). The warning is benign for tests — disabled.
pytestmark = [
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
]


class _RecordingEmailSender:
    def __init__(self) -> None:
        self.outbox: list[dict[str, str]] = []

    async def send(self, *, to: str, subject: str, body: str) -> None:
        self.outbox.append({"to": to, "subject": subject, "body": body})


@pytest.fixture(autouse=True)
def fast_argon2_for_smoke():
    original = passwords._DEFAULT_HASHER
    passwords._DEFAULT_HASHER = passwords.make_hasher(time_cost=1, memory_cost_kib=1024, parallelism=1)
    yield
    passwords._DEFAULT_HASHER = original


@pytest_asyncio.fixture
async def app_and_outbox(tmp_path: Path):
    cfg = AppConfig()
    cfg.storage.sqlite_path = tmp_path / "smoke.sqlite"
    cfg.web.signup.require_email_verification = True
    cfg.web.base_url = "http://t"   # disables Secure-flag on session cookie for tests

    sender = _RecordingEmailSender()
    set_email_sender(sender)

    app = build_app(cfg)
    async with app.router.lifespan_context(app):
        yield app, sender


@pytest.mark.asyncio
async def test_signup_login_create_repeater(app_and_outbox) -> None:
    app, sender = app_and_outbox
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        # 1) Signup
        resp = await client.post(
            "/signup",
            data={"email": "alice@example.com", "password": "longenoughpw1!"},
        )
        assert resp.status_code == 200, resp.text
        assert sender.outbox, "verification email should be sent"
        body = sender.outbox[0]["body"]
        token = body.split("token=")[1].strip()

        # 2) Verify email
        resp = await client.get(f"/verify-email?token={token}")
        assert resp.status_code == 200
        assert "best" in resp.text.lower()

        # 3) Login
        resp = await client.post(
            "/login",
            data={"email": "alice@example.com", "password": "longenoughpw1!"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/dashboard"

        # 4) Dashboard reachable
        resp = await client.get("/dashboard")
        assert resp.status_code == 200
        assert "Dashboard" in resp.text

        # 5) Create repeater
        resp = await client.post(
            "/repeaters",
            data={"name": "Site-A", "scope": "public"},
        )
        assert resp.status_code == 200, resp.text
        # Token aus dem geretourneten HTML extrahieren
        page = resp.text
        assert "set bridge.token" in page
        # Token steckt in der <pre>-Block — wir extrahieren grob
        token_line = next(
            line for line in page.splitlines() if "set bridge.token" in line
        )
        bridge_token = token_line.strip().split()[-1]
        assert len(bridge_token) == 32

        # site_id parsen
        site_line = next(
            line for line in page.splitlines() if "set bridge.site" in line
        )
        site_id = site_line.strip().split()[-1]
        assert len(site_id) == 36  # uuid string


@pytest.mark.asyncio
async def test_websocket_hello_handshake(app_and_outbox) -> None:
    app, sender = app_and_outbox

    # Erst per HTTP einen User + Repeater anlegen, Token einsammeln.
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await client.post("/signup", data={"email": "bob@example.com", "password": "longenoughpw1!"})
        token = sender.outbox[-1]["body"].split("token=")[1].strip()
        await client.get(f"/verify-email?token={token}")
        await client.post("/login", data={"email": "bob@example.com", "password": "longenoughpw1!"}, follow_redirects=False)
        resp = await client.post("/repeaters", data={"name": "Site-B", "scope": "public"})
        page = resp.text
        bridge_token = next(line.strip().split()[-1] for line in page.splitlines() if "set bridge.token" in line)
        site_id = next(line.strip().split()[-1] for line in page.splitlines() if "set bridge.site" in line)

    # Jetzt WebSocket-Hello via Starlette TestClient (synchron)
    from uuid import UUID

    with TestClient(app) as tc:
        with tc.websocket_connect("/api/v1/bridge") as ws:
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
            ack_raw = ws.receive_bytes()
            ack = decode_frame(ack_raw)
            assert isinstance(ack, HelloAck)
            assert ack.proto == 1
            ws.close()


@pytest.mark.asyncio
async def test_websocket_rejects_bad_token(app_and_outbox) -> None:
    app, sender = app_and_outbox
    from uuid import uuid4

    with TestClient(app) as tc:
        with pytest.raises(Exception):
            with tc.websocket_connect("/api/v1/bridge") as ws:
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
async def test_two_repeaters_route_pkt_between_them(app_and_outbox) -> None:
    app, sender = app_and_outbox
    from uuid import UUID

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        await client.post("/signup", data={"email": "carol@example.com", "password": "longenoughpw1!"})
        v = sender.outbox[-1]["body"].split("token=")[1].strip()
        await client.get(f"/verify-email?token={v}")
        await client.post("/login", data={"email": "carol@example.com", "password": "longenoughpw1!"}, follow_redirects=False)

        resp = await client.post("/repeaters", data={"name": "A", "scope": "public"})
        a_page = resp.text
        a_tok = next(l.strip().split()[-1] for l in a_page.splitlines() if "set bridge.token" in l)
        a_site = next(l.strip().split()[-1] for l in a_page.splitlines() if "set bridge.site" in l)

        resp = await client.post("/repeaters", data={"name": "B", "scope": "public"})
        b_page = resp.text
        b_tok = next(l.strip().split()[-1] for l in b_page.splitlines() if "set bridge.token" in l)
        b_site = next(l.strip().split()[-1] for l in b_page.splitlines() if "set bridge.site" in l)

    with TestClient(app) as tc:
        with tc.websocket_connect("/api/v1/bridge") as ws_a, tc.websocket_connect("/api/v1/bridge") as ws_b:
            ws_a.send_bytes(encode_frame(Hello(site=UUID(a_site), tok=a_tok, fw="v0", proto=1, scope="public")))
            ws_b.send_bytes(encode_frame(Hello(site=UUID(b_site), tok=b_tok, fw="v0", proto=1, scope="public")))
            assert isinstance(decode_frame(ws_a.receive_bytes()), HelloAck)
            assert isinstance(decode_frame(ws_b.receive_bytes()), HelloAck)

            payload = b"\xde\xad\xbe\xef"
            ws_a.send_bytes(encode_frame(Packet(raw=payload)))

            received = decode_frame(ws_b.receive_bytes())
            assert isinstance(received, Packet)
            assert received.raw == payload

            ws_a.close()
            ws_b.close()
