"""Auto-Übersetzung eingehender Companion-Nachrichten via lokalem Ollama.

Aufruf-Pfad: ``CompanionService`` startet nach jedem persistierten Inbound
einen Hintergrund-Task, der :func:`translate` ruft. Bei Erfolg wird das
Ergebnis (ISO-Sprache + Zieltext) ins ``companion_messages``-Row
geschrieben und ein SSE-Event ``message_translated`` emittiert.

Design:
- Synchron-blockierende LLM-Aufrufe haben hier nichts verloren — der
  Ollama-Call ist async via ``httpx.AsyncClient``.
- Skip-Heuristiken vor dem HTTP-Call halten Kosten/Latenz niedrig:
  zu kurz, zu lang, oder nur ASCII-Symbole/Whitespace → kein Call.
- Antwortformat ist erzwungen JSON (``format="json"``) mit zwei Feldern
  ``lang`` (ISO-639-1) und ``translated``. Wenn das Modell die Sprache
  als Ziel erkennt, gibt es ``translated=""`` zurück → wir behandeln das
  als „keine Übersetzung nötig".
- Jeder unerwartete Fehler (Timeout, 5xx, ungültiges JSON, fehlende
  Felder) führt zu ``None`` und einer Warning. Der Empfangspfad darf
  nie wegen Übersetzung scheitern.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import httpx
import structlog

_log = structlog.get_logger("companion.translator")


@dataclass(frozen=True, slots=True)
class Translation:
    """Erfolgreiche Übersetzung."""

    language: str
    """ISO-639-1 der erkannten Quellsprache (z.B. ``nl``, ``en``)."""

    translated_text: str
    """Übersetzter Text in der Zielsprache."""


@dataclass(frozen=True, slots=True)
class TranslatorConfig:
    """Subset der :class:`meshcore_bridge.config.TranslationConfig`-Felder,
    die der Translator wirklich braucht. Erlaubt, das Modul ohne
    Abhängigkeit auf das Bridge-Paket zu testen."""

    base_url: str
    model: str
    target_lang: str
    target_lang_label: str
    timeout_s: float
    min_chars: int
    max_chars: int


def _should_skip(text: str, *, min_chars: int, max_chars: int) -> bool:
    """Heuristische Skip-Liste — bevor wir Ollama anrufen."""
    stripped = text.strip()
    if len(stripped) < min_chars:
        return True
    if len(stripped) > max_chars:
        return True
    # Nur ASCII-Symbole/Whitespace (keine Buchstaben) → kein Sinn zu
    # übersetzen. Wir akzeptieren bewusst keine reine Emoji-Erkennung,
    # weil viele Nicht-ASCII-Schriften (Cyrillic, Greek) durchgehen
    # sollen.
    return not any(ch.isalpha() for ch in stripped)


def _build_prompt(text: str, target_label: str) -> list[dict[str, str]]:
    system = (
        "You translate short LoRa mesh chat messages. "
        f"Target language: {target_label}. "
        'Reply ONLY as JSON with two fields: {"lang":"<ISO 639-1 of the source>",'
        '"translated":"<the message in the target language>"}. '
        "If the source is already in the target language, return "
        '"translated":"". Do NOT add explanations or quotes.'
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": text},
    ]


async def translate(text: str, cfg: TranslatorConfig) -> Translation | None:  # noqa: PLR0911
    """Übersetze ``text`` per Ollama. Liefert ``None`` bei Skip oder Fehler.

    Eine Rückgabe ``Translation(language=cfg.target_lang, ...)`` mit
    *leerem* ``translated_text`` heißt: Quelltext war bereits in der
    Zielsprache. Das Modul gibt in diesem Fall ``None`` zurück, damit
    der Aufrufer keinen Subline-Hinweis "Übersetzt aus Deutsch" anzeigt.
    """
    if _should_skip(text, min_chars=cfg.min_chars, max_chars=cfg.max_chars):
        return None

    payload = {
        "model": cfg.model,
        "messages": _build_prompt(text, cfg.target_lang_label),
        "format": "json",
        "stream": False,
        "options": {"temperature": 0.0},
    }
    url = cfg.base_url.rstrip("/") + "/api/chat"
    try:
        async with httpx.AsyncClient(timeout=cfg.timeout_s) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
    except httpx.TimeoutException:
        _log.warning("translate_timeout", url=url, timeout_s=cfg.timeout_s)
        return None
    except httpx.HTTPError as exc:
        _log.warning("translate_http_error", url=url, error=str(exc))
        return None
    except ValueError as exc:  # ungültiges JSON-Top-Level
        _log.warning("translate_bad_response", url=url, error=str(exc))
        return None

    parsed = _parse_ollama_response(data)
    if parsed is None:
        return None
    lang, translated = parsed
    if not translated.strip():
        # Modell sagt: schon in Zielsprache.
        return None
    if lang.lower() == cfg.target_lang.lower():
        # Sicherheitsnetz: wenn das Modell die Quellsprache als Ziel
        # markiert, aber trotzdem etwas zurückgibt, ist das vermutlich
        # nur eine Wiederholung — wir blenden die "Übersetzung" aus.
        return None
    return Translation(language=lang.lower(), translated_text=translated.strip())


def _parse_ollama_response(data: object) -> tuple[str, str] | None:  # noqa: PLR0911
    """Aus dem Ollama-Chat-Response das Inhalts-JSON ziehen.

    Erwartete Struktur (``content`` ist eine JSON-String-Wrapper, weil
    Ollama bei ``format=json`` den Text als JSON-Stringified zurückliefert,
    nicht als verschachteltes Objekt).
    """
    if not isinstance(data, dict):
        _log.warning("translate_bad_shape", got=type(data).__name__)
        return None
    message = data.get("message")
    if not isinstance(message, dict):
        _log.warning("translate_no_message", keys=list(data.keys()))
        return None
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        _log.warning("translate_empty_content")
        return None
    try:
        inner = json.loads(content)
    except json.JSONDecodeError as exc:
        _log.warning("translate_inner_json", error=str(exc), preview=content[:120])
        return None
    if not isinstance(inner, dict):
        _log.warning("translate_inner_not_object")
        return None
    lang = inner.get("lang")
    translated = inner.get("translated")
    if not isinstance(lang, str) or not isinstance(translated, str):
        _log.warning("translate_inner_fields", inner=inner)
        return None
    return lang, translated
