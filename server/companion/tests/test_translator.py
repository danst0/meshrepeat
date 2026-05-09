"""Translator-Modul: Skip-Heuristiken + Ollama-Antwort-Parsing.

Wir mocken die HTTP-Schicht via httpx.MockTransport, damit weder Netzwerk
noch ein laufender Ollama-Container nötig sind."""

from __future__ import annotations

import json

import httpx
import pytest

from meshcore_companion import translator as trmod
from meshcore_companion.translator import Translation, TranslatorConfig, translate


def _cfg(**overrides: object) -> TranslatorConfig:
    base = dict(
        base_url="http://stub.local",
        model="llama3.1:8b",
        target_lang="de",
        target_lang_label="Deutsch",
        timeout_s=5.0,
        min_chars=3,
        max_chars=800,
    )
    base.update(overrides)
    return TranslatorConfig(**base)  # type: ignore[arg-type]


def _patch_httpx(monkeypatch: pytest.MonkeyPatch, handler) -> None:  # type: ignore[no-untyped-def]
    transport = httpx.MockTransport(handler)
    real_init = httpx.AsyncClient.__init__

    def init(self, *a, **kw):  # type: ignore[no-untyped-def]
        kw.setdefault("transport", transport)
        real_init(self, *a, **kw)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", init)


async def test_skip_too_short() -> None:
    assert await translate("hi", _cfg()) is None


async def test_skip_only_symbols() -> None:
    assert await translate("👍👍👍", _cfg()) is None
    assert await translate(".......", _cfg()) is None


async def test_skip_too_long() -> None:
    assert await translate("a" * 1000, _cfg(max_chars=800)) is None


async def test_translate_returns_translation(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/api/chat"
        body = json.loads(req.content)
        assert body["format"] == "json"
        assert body["stream"] is False
        return httpx.Response(
            200,
            json={
                "message": {
                    "role": "assistant",
                    "content": json.dumps({"lang": "nl", "translated": "Mahlzeit"}),
                }
            },
        )

    _patch_httpx(monkeypatch, handler)

    res = await translate("Eet smakelijk", _cfg())
    assert isinstance(res, Translation)
    assert res.language == "nl"
    assert res.translated_text == "Mahlzeit"


async def test_translate_already_target_language(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "message": {
                    "role": "assistant",
                    "content": json.dumps({"lang": "de", "translated": ""}),
                }
            },
        )

    _patch_httpx(monkeypatch, handler)

    # Wenn das Modell „bereits Zielsprache" sagt → kein Translation-Result.
    assert await translate("Guten Morgen!", _cfg()) is None


async def test_translate_http_5xx_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="busy")

    _patch_httpx(monkeypatch, handler)
    assert await translate("Wie is de baas?", _cfg()) is None


async def test_translate_invalid_inner_json(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"message": {"role": "assistant", "content": "not valid json"}},
        )

    _patch_httpx(monkeypatch, handler)
    assert await translate("Wie is de baas?", _cfg()) is None


async def test_translate_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=req)

    _patch_httpx(monkeypatch, handler)
    assert await translate("Wie is de baas?", _cfg()) is None


async def test_translate_dropped_when_lang_equals_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sicherheitsnetz: Modell behauptet, Quelle sei deutsch und liefert
    aber doch einen "uebersetzten" Text - wir blenden ihn aus, damit keine
    sinnlose Subline erscheint."""

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "message": {
                    "role": "assistant",
                    "content": json.dumps({"lang": "DE", "translated": "Guten Morgen!"}),
                }
            },
        )

    _patch_httpx(monkeypatch, handler)
    assert await translate("Guten Morgen!", _cfg()) is None


def test_module_logger_present() -> None:
    # _log soll ein structlog-Logger sein, kein None — wird in
    # _parse_ollama_response() bei Fehlern verwendet.
    assert trmod._log is not None
