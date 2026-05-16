"""Tests für die HA-LLM-Bridge.

Wir mocken Ollama via httpx.MockTransport (gleiches Muster wie
test_translator) und den HAClient direkt (eigener MockTransport).
Die DB-Pfade laufen gegen eine echte SQLite-Engine im tmp_path.
"""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio

from meshcore_companion.ha_bridge import (
    HaBridgeRunner,
    _extract_entities,
    handle_query,
    should_run_bridge,
    trim_to_bytes,
)
from meshcore_companion.homeassistant import (
    HomeAssistantClient,
    HomeAssistantConfig,
)

# ---------- Pure unit tests ----------


def test_trim_to_bytes_passthrough() -> None:
    assert trim_to_bytes("kurz") == "kurz"


def test_trim_to_bytes_cuts_long_ascii() -> None:
    s = "x" * 200
    out = trim_to_bytes(s, max_bytes=20)
    assert len(out.encode("utf-8")) <= 20
    assert out.endswith("…")


def test_trim_to_bytes_handles_multibyte() -> None:
    # "ä" = 2 Byte UTF-8, "…" = 3 Byte. Wir wollen, dass kein halbes
    # Multibyte-Zeichen am Ende stehen bleibt.
    s = "ä" * 100
    out = trim_to_bytes(s, max_bytes=10)
    encoded = out.encode("utf-8")
    assert len(encoded) <= 10
    assert encoded.decode("utf-8") == out  # valides UTF-8


def test_extract_entities_filters_to_allowed() -> None:
    allowed = {"sensor.a", "sensor.b"}
    routing = {"entities": ["sensor.a", "sensor.x", "sensor.b", "sensor.a"]}
    out = _extract_entities(routing, allowed=allowed)
    assert out == ["sensor.a", "sensor.b"]


def test_extract_entities_handles_garbage() -> None:
    assert _extract_entities(None, allowed={"sensor.a"}) == []
    assert _extract_entities({"entities": "not-a-list"}, allowed={"sensor.a"}) == []
    assert _extract_entities({}, allowed={"sensor.a"}) == []


def test_rate_bucket_allow_then_block() -> None:
    runner = HaBridgeRunner(ollama_base_url="http://stub")
    pk = b"\x01" * 32
    # 3 Anfragen erlaubt, vierte blockiert
    assert runner._rate_allow(pk, limit_per_min=3, now=100.0)
    assert runner._rate_allow(pk, limit_per_min=3, now=101.0)
    assert runner._rate_allow(pk, limit_per_min=3, now=102.0)
    assert not runner._rate_allow(pk, limit_per_min=3, now=103.0)
    # Nach 60 s sind die alten wieder raus
    assert runner._rate_allow(pk, limit_per_min=3, now=200.0)


# ---------- Integration with DB + mocked Ollama/HA ----------


@pytest_asyncio.fixture
async def db_setup(tmp_path: Path):
    """Initialisiere die echte Bridge-DB im tmp_path und liefere
    ``(sessionmaker, identity_id)`` zurück."""
    import os

    os.environ["MESHCORE_ALEMBIC_DIR"] = str(Path.cwd() / "server" / "bridge" / "alembic")
    from meshcore_bridge.db import (
        CompanionHaAllowedPubkey,
        CompanionHaBridge,
        CompanionHaExposedEntity,
        CompanionIdentity,
        User,
    )
    from meshcore_bridge.db.session import close_engine, get_session, init_engine

    db_path = tmp_path / "ha_bridge.sqlite"
    await init_engine(db_path)

    user_id = uuid4()
    identity_id = uuid4()

    async with get_session() as db:
        db.add(
            User(
                id=user_id,
                email="t@t",
                password_hash="x",
                email_verified_at=None,
            )
        )
        db.add(
            CompanionIdentity(
                id=identity_id,
                user_id=user_id,
                name="Antonia",
                pubkey=b"\xaa" * 32,
                privkey_enc=b"\x00" * 32,
                scope="public",
            )
        )
        db.add(
            CompanionHaBridge(
                identity_id=identity_id,
                enabled=True,
                ollama_model="llama3.1:8b",
                max_entities_per_query=2,
                rate_limit_per_min=5,
            )
        )
        db.add(
            CompanionHaAllowedPubkey(
                identity_id=identity_id,
                pubkey=b"\xbb" * 32,
                label="phone",
            )
        )
        db.add(
            CompanionHaExposedEntity(
                identity_id=identity_id,
                entity_id="sensor.balkon_temp",
                alias="Temp Balkon",
                hint="°C",
            )
        )
        db.add(
            CompanionHaExposedEntity(
                identity_id=identity_id,
                entity_id="sensor.balkon_hum",
                alias="Feuchte Balkon",
                hint="%",
            )
        )
        await db.commit()

    yield get_session, identity_id
    await close_engine()


def _ha_client(handler) -> HomeAssistantClient:  # type: ignore[no-untyped-def]
    cfg = HomeAssistantConfig(
        base_url="http://stub-ha.local",
        token="t",
        timeout_s=5.0,
    )
    return HomeAssistantClient(cfg, transport=httpx.MockTransport(handler))


def _patch_ollama_handler(monkeypatch: pytest.MonkeyPatch, handler) -> None:  # type: ignore[no-untyped-def]
    transport = httpx.MockTransport(handler)
    real_init = httpx.AsyncClient.__init__

    def init(self, *a, **kw):  # type: ignore[no-untyped-def]
        # Nur AsyncClient ohne eigenen Transport patchen — der HAClient
        # bringt seinen eigenen MockTransport mit und darf nicht
        # überschrieben werden.
        if "transport" not in kw:
            kw["transport"] = transport
        real_init(self, *a, **kw)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", init)


@pytest.mark.asyncio
async def test_should_run_bridge_positive(db_setup) -> None:
    sessionmaker, identity_id = db_setup
    assert (
        await should_run_bridge(
            sessionmaker=sessionmaker,
            identity_id=identity_id,
            sender_pubkey=b"\xbb" * 32,
        )
        is True
    )


@pytest.mark.asyncio
async def test_should_run_bridge_unknown_sender(db_setup) -> None:
    sessionmaker, identity_id = db_setup
    assert (
        await should_run_bridge(
            sessionmaker=sessionmaker,
            identity_id=identity_id,
            sender_pubkey=b"\xcc" * 32,
        )
        is False
    )


@pytest.mark.asyncio
async def test_should_run_bridge_disabled(db_setup) -> None:
    from meshcore_bridge.db import CompanionHaBridge

    sessionmaker, identity_id = db_setup
    async with sessionmaker() as db:
        b = await db.get(CompanionHaBridge, identity_id)
        assert b is not None
        b.enabled = False
        await db.commit()
    assert (
        await should_run_bridge(
            sessionmaker=sessionmaker,
            identity_id=identity_id,
            sender_pubkey=b"\xbb" * 32,
        )
        is False
    )


@pytest.mark.asyncio
async def test_handle_query_happy_path(db_setup, monkeypatch: pytest.MonkeyPatch) -> None:
    """Routing → 1 Entity, HA liefert 18.3 °C, Formulierung liefert
    eine Antwort. Wir prüfen, dass send_dm mit dem getrimmten Text
    aufgerufen wird."""
    sessionmaker, identity_id = db_setup
    sender = b"\xbb" * 32

    def ollama_handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content.decode("utf-8"))
        messages = body["messages"]
        system = messages[0]["content"]
        # Wir unterscheiden Routing-Call (Katalog im System-Prompt)
        # vom Antwort-Call (Daten:-Block).
        if "Sensor-Katalog" in system or "Smart-Home-Router" in system:
            payload = {
                "message": {
                    "content": json.dumps({"entities": ["sensor.balkon_temp"], "reason": "temp"})
                }
            }
        else:
            payload = {"message": {"content": "Balkon 18.3 °C"}}
        return httpx.Response(200, json=payload)

    _patch_ollama_handler(monkeypatch, ollama_handler)

    def ha_handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/api/states/sensor.balkon_temp"
        return httpx.Response(
            200,
            json={
                "entity_id": "sensor.balkon_temp",
                "state": "18.3",
                "attributes": {"unit_of_measurement": "°C"},
            },
        )

    ha = _ha_client(ha_handler)
    runner = HaBridgeRunner(ollama_base_url="http://stub-ollama.local")
    sent: list[tuple[UUID, bytes, str]] = []

    async def send_dm(ident: UUID, peer: bytes, text: str) -> bool:
        sent.append((ident, peer, text))
        return True

    await handle_query(
        runner=runner,
        sessionmaker=sessionmaker,
        ha_client=ha,
        identity_id=identity_id,
        sender_pubkey=sender,
        question="wie warm ist es auf dem Balkon?",
        send_dm=send_dm,
    )
    await ha.aclose()
    assert len(sent) == 1
    assert sent[0][0] == identity_id
    assert sent[0][1] == sender
    assert sent[0][2] == "Balkon 18.3 °C"


@pytest.mark.asyncio
async def test_handle_query_no_route_chat_fallback(
    db_setup, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Kein Entity-Treffer → der Chat-Fallback-LLM-Call liefert eine
    freie Antwort, die ans Mesh geht (kein HA-Read)."""
    sessionmaker, identity_id = db_setup

    def ollama_handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content.decode("utf-8"))
        # Erster Call läuft mit format=json (Routing), zweiter ohne.
        if body.get("format") == "json":
            return httpx.Response(
                200,
                json={"message": {"content": json.dumps({"entities": [], "reason": ""})}},
            )
        return httpx.Response(
            200,
            json={"message": {"content": "Da habe ich gerade keine Daten."}},
        )

    _patch_ollama_handler(monkeypatch, ollama_handler)

    def ha_handler(req: httpx.Request) -> httpx.Response:
        # Sollte gar nicht gerufen werden.
        raise AssertionError("HA should not be queried on no-route")

    ha = _ha_client(ha_handler)
    runner = HaBridgeRunner(ollama_base_url="http://stub-ollama.local")
    sent: list[str] = []

    async def send_dm(ident: UUID, peer: bytes, text: str) -> bool:
        sent.append(text)
        return True

    await handle_query(
        runner=runner,
        sessionmaker=sessionmaker,
        ha_client=ha,
        identity_id=identity_id,
        sender_pubkey=b"\xbb" * 32,
        question="frag das wetter auf dem Mars",
        send_dm=send_dm,
    )
    await ha.aclose()
    assert sent == ["Da habe ich gerade keine Daten."]


@pytest.mark.asyncio
async def test_handle_query_no_route_chat_fallback_failure(
    db_setup, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Kein Entity-Treffer und Chat-Fallback-Call schlägt fehl →
    fällt auf die statische Hinweismeldung zurück."""
    sessionmaker, identity_id = db_setup

    def ollama_handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content.decode("utf-8"))
        if body.get("format") == "json":
            return httpx.Response(
                200,
                json={"message": {"content": json.dumps({"entities": [], "reason": ""})}},
            )
        return httpx.Response(503, json={})

    _patch_ollama_handler(monkeypatch, ollama_handler)

    def ha_handler(req: httpx.Request) -> httpx.Response:
        raise AssertionError("HA should not be queried on no-route")

    ha = _ha_client(ha_handler)
    runner = HaBridgeRunner(ollama_base_url="http://stub-ollama.local")
    sent: list[str] = []

    async def send_dm(ident: UUID, peer: bytes, text: str) -> bool:
        sent.append(text)
        return True

    await handle_query(
        runner=runner,
        sessionmaker=sessionmaker,
        ha_client=ha,
        identity_id=identity_id,
        sender_pubkey=b"\xbb" * 32,
        question="hallo",
        send_dm=send_dm,
    )
    await ha.aclose()
    assert len(sent) == 1
    assert "keine passenden" in sent[0]


@pytest.mark.asyncio
async def test_handle_query_rate_limited_silent(db_setup, monkeypatch: pytest.MonkeyPatch) -> None:
    """Bei Rate-Limit wird keine Antwort geschickt — verhindert
    Spam-Verstärker."""
    sessionmaker, identity_id = db_setup
    runner = HaBridgeRunner(ollama_base_url="http://stub-ollama.local")
    sender = b"\xbb" * 32
    # Vorab das Limit voll machen.
    for i in range(5):
        runner._rate_allow(sender, limit_per_min=5, now=100.0 + i)

    def ollama_handler(req: httpx.Request) -> httpx.Response:
        raise AssertionError("Ollama should not be called when rate-limited")

    _patch_ollama_handler(monkeypatch, ollama_handler)

    def ha_handler(req: httpx.Request) -> httpx.Response:
        raise AssertionError("HA should not be called when rate-limited")

    ha = _ha_client(ha_handler)
    sent: list[str] = []

    async def send_dm(ident: UUID, peer: bytes, text: str) -> bool:
        sent.append(text)
        return True

    await handle_query(
        runner=runner,
        sessionmaker=sessionmaker,
        ha_client=ha,
        identity_id=identity_id,
        sender_pubkey=sender,
        question="x",
        send_dm=send_dm,
        now_monotonic=100.0 + 10,  # innerhalb der 60 s
    )
    await ha.aclose()
    assert sent == []


@pytest.mark.asyncio
async def test_handle_query_ha_failure_fallback(db_setup, monkeypatch: pytest.MonkeyPatch) -> None:
    """Wenn HA nicht erreichbar ist (404 = HomeAssistantNotFound) → wir
    schicken eine kurze Fehlermeldung, kein zweiter LLM-Call."""
    sessionmaker, identity_id = db_setup

    def ollama_handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "message": {
                    "content": json.dumps({"entities": ["sensor.balkon_temp"], "reason": ""})
                }
            },
        )

    _patch_ollama_handler(monkeypatch, ollama_handler)

    def ha_handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={})

    ha = _ha_client(ha_handler)
    runner = HaBridgeRunner(ollama_base_url="http://stub-ollama.local")
    sent: list[str] = []

    async def send_dm(ident: UUID, peer: bytes, text: str) -> bool:
        sent.append(text)
        return True

    await handle_query(
        runner=runner,
        sessionmaker=sessionmaker,
        ha_client=ha,
        identity_id=identity_id,
        sender_pubkey=b"\xbb" * 32,
        question="wie warm?",
        send_dm=send_dm,
    )
    await ha.aclose()
    assert len(sent) == 1
    assert "nicht erreichbar" in sent[0]


@pytest.mark.asyncio
async def test_handle_query_hallucinated_entity_filtered(
    db_setup, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Modell halluziniert eine Entity, die nicht im Katalog ist →
    wird gefiltert, kein Route → Chat-Fallback liefert freie Antwort,
    HA gar nicht gerufen."""
    sessionmaker, identity_id = db_setup

    def ollama_handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content.decode("utf-8"))
        if body.get("format") == "json":
            return httpx.Response(
                200,
                json={
                    "message": {
                        "content": json.dumps(
                            {"entities": ["sensor.zimmer_temp"], "reason": ""}
                        )
                    }
                },
            )
        return httpx.Response(
            200,
            json={"message": {"content": "Dazu habe ich keinen Sensor."}},
        )

    _patch_ollama_handler(monkeypatch, ollama_handler)

    def ha_handler(req: httpx.Request) -> httpx.Response:
        raise AssertionError("HA must not be called for filtered entities")

    ha = _ha_client(ha_handler)
    runner = HaBridgeRunner(ollama_base_url="http://stub-ollama.local")
    sent: list[str] = []

    async def send_dm(ident: UUID, peer: bytes, text: str) -> bool:
        sent.append(text)
        return True

    await handle_query(
        runner=runner,
        sessionmaker=sessionmaker,
        ha_client=ha,
        identity_id=identity_id,
        sender_pubkey=b"\xbb" * 32,
        question="x",
        send_dm=send_dm,
    )
    await ha.aclose()
    assert sent == ["Dazu habe ich keinen Sensor."]
