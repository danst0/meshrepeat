"""Unit-Tests für :mod:`meshcore_companion.ai_agent`.

Wir mocken die HTTP-Schicht via :class:`httpx.MockTransport`, damit weder
Netzwerk noch ein laufender LLM-Server (llama-swap/llama.cpp) nötig sind."""

from __future__ import annotations

import random
from uuid import uuid4

import httpx
import pytest

from meshcore_companion.ai_agent import (
    _JITTER_HIGH,
    _JITTER_LOW,
    AiAgentClient,
    AiAgentClientConfig,
    HistoryFilter,
    jittered_interval_s,
    mentions_identity,
    parse_blocked_peer_names,
    sanitize_reply,
)


def _patch_httpx(monkeypatch: pytest.MonkeyPatch, handler) -> None:  # type: ignore[no-untyped-def]
    transport = httpx.MockTransport(handler)
    real_init = httpx.AsyncClient.__init__

    def init(self, *a, **kw):  # type: ignore[no-untyped-def]
        kw.setdefault("transport", transport)
        real_init(self, *a, **kw)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", init)


def _chat_response(content: str) -> dict:
    """OpenAI-Chat-Completion-Hülle um einen ``content``-String."""
    return {"choices": [{"message": {"role": "assistant", "content": content}}]}


# ---------- Jitter ----------


def test_jitter_within_bounds() -> None:
    rng = random.Random(42)
    for _ in range(200):
        val = jittered_interval_s(3600, rng=rng)
        assert 3600 * _JITTER_LOW <= val <= 3600 * _JITTER_HIGH


def test_jitter_zero_or_negative_returns_zero() -> None:
    assert jittered_interval_s(0) == 0.0
    assert jittered_interval_s(-10) == 0.0


# ---------- Mention-Detect ----------


def test_mention_exact_word() -> None:
    assert mentions_identity("Hallo Antonia, was geht?", "Antonia")


def test_mention_case_insensitive() -> None:
    assert mentions_identity("hallo ANTONIA!", "Antonia")


def test_mention_no_substring_match() -> None:
    # "Antoni" darf nicht in "Antonia" matchen.
    assert not mentions_identity("Antoniaa hat geantwortet", "Antoni")


def test_mention_empty_name() -> None:
    assert not mentions_identity("irgendwas", "")
    assert not mentions_identity("irgendwas", "   ")


def test_mention_special_chars_in_name() -> None:
    # Name mit Sonderzeichen sollte korrekt escaped sein und nicht regex-explodieren.
    assert mentions_identity("hi K-9 wie geht's", "K-9")


# ---------- Sanitizer ----------


def test_sanitize_strip_whitespace() -> None:
    assert sanitize_reply("  hallo  welt  ") == "hallo welt"


def test_sanitize_newlines_to_space() -> None:
    assert sanitize_reply("zeile1\nzeile2") == "zeile1 zeile2"


def test_sanitize_removes_control_chars() -> None:
    assert sanitize_reply("hi\x00\x07\x08bye") == "hibye"


def test_sanitize_returns_none_on_empty() -> None:
    assert sanitize_reply("") is None
    assert sanitize_reply(None) is None
    assert sanitize_reply("   ") is None


def test_sanitize_byte_cap() -> None:
    txt = "x" * 200
    out = sanitize_reply(txt, max_bytes=140)
    assert out is not None
    assert len(out.encode("utf-8")) <= 140


def test_sanitize_byte_cap_multibyte_boundary() -> None:
    # Aufgepasst: "ä" ist 2 Byte UTF-8 — wenn wir auf 9 kappen, darf nichts
    # Halbes übrigbleiben.
    txt = "ä" * 20  # 40 Byte
    out = sanitize_reply(txt, max_bytes=9)
    assert out is not None
    # 8 Byte → 4 "ä"
    assert out == "ä" * 4


# ---------- Blacklist-Parser ----------


def test_parse_blocked_strips_blank_lines() -> None:
    raw = "Bot\n\n  Andere  \n\nDritter\n"
    parsed = parse_blocked_peer_names(raw)
    assert parsed == frozenset({"bot", "andere", "dritter"})


def test_parse_blocked_empty() -> None:
    assert parse_blocked_peer_names("") == frozenset()
    assert parse_blocked_peer_names(None) == frozenset()


# ---------- HistoryFilter ----------


def test_history_filter_blocks_own_pubkey() -> None:
    own = b"\x01" * 32
    other = b"\x02" * 32
    f = HistoryFilter(own_pubkeys=frozenset({own}), blocked_names=frozenset())
    assert not f.allows(peer_pubkey=own, peer_name="ich")
    assert f.allows(peer_pubkey=other, peer_name="andere")


def test_history_filter_blocks_blacklisted_name() -> None:
    f = HistoryFilter(
        own_pubkeys=frozenset(),
        blocked_names=frozenset({"botty"}),
    )
    assert not f.allows(peer_pubkey=b"\x03" * 32, peer_name="Botty")
    assert f.allows(peer_pubkey=b"\x03" * 32, peer_name="real-user")


def test_history_filter_allows_unknown_no_name() -> None:
    f = HistoryFilter(own_pubkeys=frozenset(), blocked_names=frozenset())
    assert f.allows(peer_pubkey=None, peer_name=None)


# ---------- AiAgentClient.generate ----------


def _cfg(**overrides: object) -> AiAgentClientConfig:
    base: dict[str, object] = dict(
        base_url="http://stub.local",
        model="llama3.1:8b",
        timeout_s=5.0,
        max_attempts=1,
        retry_backoff_s=0.0,
    )
    base.update(overrides)
    return AiAgentClientConfig(**base)  # type: ignore[arg-type]


async def test_generate_success(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = request.read()
        # Sanity-Check: System-Message ist drin.
        assert b'"system"' in body
        return httpx.Response(
            200,
            json=_chat_response("Servus zusammen!"),
        )

    _patch_httpx(monkeypatch, handler)
    client = AiAgentClient(_cfg())
    out = await client.generate(
        system_prompt="Antworte freundlich.",
        history=[{"role": "user", "content": "alice: Hallo?"}],
    )
    assert out == "Servus zusammen!"


async def test_generate_empty_system_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    # Wenn der Prompt leer ist, soll kein HTTP-Call erfolgen.
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("HTTP-Call sollte nicht passieren")

    _patch_httpx(monkeypatch, handler)
    client = AiAgentClient(_cfg())
    assert await client.generate(system_prompt="   ", history=[]) is None


async def test_generate_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    _patch_httpx(monkeypatch, handler)
    client = AiAgentClient(_cfg())
    assert (
        await client.generate(system_prompt="x", history=[{"role": "user", "content": "hi"}])
        is None
    )


async def test_generate_byte_cap_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    long_response = "x" * 500

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_chat_response(long_response))

    _patch_httpx(monkeypatch, handler)
    client = AiAgentClient(_cfg())
    out = await client.generate(
        system_prompt="x",
        history=[{"role": "user", "content": "hi"}],
        max_bytes=140,
    )
    assert out is not None
    assert len(out.encode("utf-8")) <= 140


async def test_generate_model_override_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json as _json

        captured["body"] = request.read().decode()
        payload = _json.loads(captured["body"])
        captured["model"] = payload["model"]
        return httpx.Response(200, json=_chat_response("ok"))

    _patch_httpx(monkeypatch, handler)
    client = AiAgentClient(_cfg())
    await client.generate(
        system_prompt="x",
        history=[{"role": "user", "content": "hi"}],
        model_override="custom:7b",
    )
    assert captured["model"] == "custom:7b"


async def test_generate_retry_recovers_after_500(monkeypatch: pytest.MonkeyPatch) -> None:
    """Zwei 5xx-Antworten, dann Erfolg — Retry-Loop muss durchkommen."""
    state = {"calls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["calls"] += 1
        if state["calls"] < 3:
            return httpx.Response(503, json={"error": "busy"})
        return httpx.Response(200, json=_chat_response("recovered"))

    _patch_httpx(monkeypatch, handler)
    client = AiAgentClient(_cfg(max_attempts=3, retry_backoff_s=0.0))
    out = await client.generate(system_prompt="x", history=[{"role": "user", "content": "hi"}])
    assert out == "recovered"
    assert state["calls"] == 3


async def test_generate_retry_gives_up_after_max_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bleibt es transient, gibt der Client nach max_attempts auf."""
    state = {"calls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["calls"] += 1
        return httpx.Response(503, json={"error": "busy"})

    _patch_httpx(monkeypatch, handler)
    client = AiAgentClient(_cfg(max_attempts=2, retry_backoff_s=0.0))
    out = await client.generate(system_prompt="x", history=[{"role": "user", "content": "hi"}])
    assert out is None
    assert state["calls"] == 2


# Ensure UUID import works (placeholder for downstream tests).
def test_uuid_factory_smoke() -> None:
    assert uuid4().hex
