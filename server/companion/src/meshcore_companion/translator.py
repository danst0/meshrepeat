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
- Selbstheilung: kleine LLMs (gemma4:e4b o.ä.) kopieren bei
  Multi-Turn-Few-Shot manchmal die Quelle als „Übersetzung" zurück.
  Bei Erkennung (translated == source) machen wir genau **einen**
  zweiten Versuch mit einem schlankeren Single-Turn-Prompt, der die
  Quellsprache aus V1 nutzt.
- Jeder unerwartete Fehler (Timeout, 5xx, ungültiges JSON, fehlende
  Felder) führt zu ``None`` und einer Warning. Der Empfangspfad darf
  nie wegen Übersetzung scheitern.
"""

from __future__ import annotations

import json
import re
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
    # Tickrate des Batch-Loops in Sekunden, der noch nicht übersetzte Rows
    # nachholt. ``0`` = Batch aus (nur live übersetzen).
    batch_interval_s: int = 3600


# Kleine ISO-639-1 → Klartext-Map für den Re-Versuch-Prompt. gemma4 und
# llama3.1 verstehen den Klartext (Dutch/English/…) deutlich zuverlässiger
# als nur den Code, gleichzeitig schadet die Code-Erwähnung nicht.
_LANG_NAMES: dict[str, str] = {
    "nl": "Dutch",
    "en": "English",
    "fr": "French",
    "es": "Spanish",
    "it": "Italian",
    "pt": "Portuguese",
    "pl": "Polish",
    "uk": "Ukrainian",
    "ru": "Russian",
    "tr": "Turkish",
}


def _normalize(s: str) -> str:
    """Lowercase + Whitespace-Collapse für robusten Gleichheits-Vergleich."""
    return " ".join(s.lower().split())


_MENTION_RE = re.compile(r"@\[[^\]]+\]")


def _strip_mentions(text: str) -> str:
    """Entferne alle `@[...]`-Mentions und collapse Whitespace.

    Wird vor jedem LLM-Call angewandt: Das Modell sieht die Mentions nie
    und kann sie folglich nicht verschlucken, umbenennen, oder die Emojis
    in den Brackets verändern. :func:`_restore_mentions` setzt sie am Ende
    deterministisch wieder ein.
    """
    cleaned = _MENTION_RE.sub("", text)
    return " ".join(cleaned.split())


def _restore_mentions(source: str, translated: str) -> str:
    """Setze die in :func:`_strip_mentions` entfernten `@[...]`-Mentions
    in Quell-Reihenfolge wieder vor die Übersetzung.

    In Mesh-Chat stehen Mentions fast immer am Satzanfang ("@[Foo] hi"),
    daher ist Voranstellen die natürliche Rekonstruktion. Sollte das LLM
    eine Mention halluzinieren (es sieht sie nie, aber Sicherheitsnetz),
    werden bereits enthaltene Mentions nicht doppelt prepended.
    """
    src_mentions = _MENTION_RE.findall(source)
    if not src_mentions:
        return translated
    missing = [m for m in src_mentions if m not in translated]
    if not missing:
        return translated
    return " ".join(missing) + " " + translated.lstrip()


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
    """System-Prompt + Few-Shot-Beispiele (V1-Versuch).

    `@[Name]`-Mentions werden vor dem Aufruf via :func:`_strip_mentions`
    entfernt — das LLM sieht sie nie. Der Prompt muss also keine
    Mention-Regel enthalten und die Few-Shots zeigen die zentralen
    bisherigen Stolperfallen: niederländische Compound-Ortsnamen,
    Provinz-Abkürzungen, Sprachidentifikation kurzer Texte.
    """
    system = (
        f"You translate short LoRa mesh chat messages into {target_label}.\n"
        'Reply ONLY as compact JSON: {"lang":"<ISO 639-1 of source>",'
        '"translated":"<full translation>"}.\n'
        "Rules:\n"
        f"- Translate the WHOLE message into {target_label}, even if part of it "
        f"already looks like {target_label}.\n"
        "- Preserve verbatim: URLs, hex IDs, callsigns, numbers, brackets, "
        "units (km, Hops, MHz, dB), emoji, punctuation around them.\n"
        "- Keep Dutch compound place names together (e.g. 'Noordwijk Binnen', "
        "'Noordwijk aan Zee', 'Bergen aan Zee', 'Alphen aan den Rijn', "
        "'Den Haag'). Words like 'binnen', 'buiten', 'aan Zee', 'aan den Rijn' "
        "next to a town name are PART of the name, NOT prepositions. "
        "Capitalize them properly even if the source is lowercase.\n"
        "- Dutch province abbreviations after a place name (NH, ZH, NB, GLD, "
        "UT, OV, FR, GR, DR, FL, LB, ZL) stay uppercase and get a comma "
        "before them: 'noordwijk binnen zh' → 'Noordwijk-Binnen, ZH'.\n"
        f"- If the source is already entirely in {target_label}, set "
        '"translated":"" (empty string).\n'
        "- Do NOT add explanations, greetings, prefixes, or quotes around "
        "the translation."
    )
    examples = [
        (
            "Ja Rijssen hier ontvangen met 4 hops",
            {"lang": "nl", "translated": "Ja, Rijssen hier empfangen mit 4 Hops"},
        ),
        (
            "Hoi Jos uit Essen met 3 bzw. 12 Hops",
            {"lang": "nl", "translated": "Hallo Jos aus Essen mit 3 bzw. 12 Hops"},
        ),
        (
            "Goedenavond allemaal vanuit noordwijk binnen zh",
            {
                "lang": "nl",
                "translated": "Guten Abend zusammen aus Noordwijk-Binnen, ZH",
            },
        ),
        ("Guten Morgen!", {"lang": "de", "translated": ""}),
    ]
    msgs: list[dict[str, str]] = [{"role": "system", "content": system}]
    for src, out in examples:
        msgs.append({"role": "user", "content": src})
        msgs.append({"role": "assistant", "content": json.dumps(out, ensure_ascii=False)})
    msgs.append({"role": "user", "content": text})
    return msgs


def _build_retry_prompt(text: str, *, source_lang: str, target_label: str) -> list[dict[str, str]]:
    """Schlanker Single-Turn-Prompt für den V2-Versuch.

    Kein Few-Shot — manche Modelle (gemma4:e4b) interpretieren das
    Few-Shot-Schema bei ``format=json`` so, dass sie den letzten
    User-Turn einfach als „Assistant-Echo" behandeln und die Quelle
    zurückkopieren. Mit nur System+User klappt's dann oft.
    """
    name = _LANG_NAMES.get(source_lang.lower(), source_lang.upper())
    system = (
        f"Translate the following {name} ({source_lang}) message into "
        f"{target_label}. Preserve verbatim: @-mentions like '@[Name]', "
        "URLs, hex IDs, callsigns, numbers, brackets, units, emoji. "
        "Do NOT echo the source. "
        'Reply ONLY as JSON: {"lang":"<ISO 639-1>","translated":'
        f'"<full translation in {target_label}>"}}.'
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": text},
    ]


async def _translate_once(
    text: str, cfg: TranslatorConfig, messages: list[dict[str, str]]
) -> tuple[str, str] | None:
    """Genau ein Ollama-/api/chat-Roundtrip. Liefert ``(lang, translated)``
    oder ``None`` bei Fehler. Der Aufrufer entscheidet, ob ein
    Folge-Versuch sinnvoll ist."""
    payload = {
        "model": cfg.model,
        "messages": messages,
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

    return _parse_ollama_response(data)


async def translate(text: str, cfg: TranslatorConfig) -> Translation | None:  # noqa: PLR0911
    """Übersetze ``text`` per Ollama. Liefert ``None`` bei Skip oder Fehler.

    Ablauf:

    1. ``@[...]``-Mentions deterministisch via :func:`_strip_mentions`
       entfernen — das LLM sieht sie nie und kann sie folglich nicht
       verschlucken oder beschädigen (kleine Modelle wie llama3.1:8b oder
       gemma4:e4b haben das trotz expliziter Prompt-Regel zuverlässig
       unzuverlässig getan, gerade bei Mentions mit Emoji/Flags wie
       ``@[Sausage🇬🇧]``).
    2. Few-Shot-Prompt auf dem bereinigten Text.
    3. Falls V1 den Source als „Übersetzung" zurückkopiert: Single-Turn-
       Retry mit der erkannten Quellsprache. Wenn auch das nicht hilft,
       gibt's keine Übersetzung — die UI zeigt dann den Originaltext und
       keine Subline.
    4. :func:`_restore_mentions` setzt die in Schritt 1 entfernten
       Mentions in Quell-Reihenfolge wieder vor die Übersetzung.
    """
    if _should_skip(text, min_chars=cfg.min_chars, max_chars=cfg.max_chars):
        return None

    payload = _strip_mentions(text)
    # Wenn nach dem Strippen nichts Übersetzbares mehr da ist (z. B. eine
    # Nachricht, die nur aus einer Mention bestand), kein LLM-Call.
    if _should_skip(payload, min_chars=cfg.min_chars, max_chars=cfg.max_chars):
        return None

    first = await _translate_once(
        payload, cfg, _build_prompt(payload, cfg.target_lang_label)
    )
    if first is None:
        return None
    lang, translated = first
    if not translated.strip():
        # Modell sagt: schon in Zielsprache.
        return None
    if lang.lower() == cfg.target_lang.lower():
        # Sicherheitsnetz: wenn das Modell die Quellsprache als Ziel
        # markiert, aber trotzdem etwas zurückgibt, ist das vermutlich
        # nur eine Wiederholung — wir blenden die "Übersetzung" aus.
        return None
    if _normalize(translated) != _normalize(payload):
        return Translation(
            language=lang.lower(),
            translated_text=_restore_mentions(text, translated.strip()),
        )

    # V1 hat die Quelle als Übersetzung gespiegelt — V2 mit schlankem
    # Single-Turn-Prompt nachschießen.
    _log.warning(
        "translate_returned_source",
        lang=lang,
        model=cfg.model,
        preview=payload[:80],
    )
    second = await _translate_once(
        payload,
        cfg,
        _build_retry_prompt(payload, source_lang=lang, target_label=cfg.target_lang_label),
    )
    if second is None:
        return None
    lang2, translated2 = second
    if not translated2.strip():
        return None
    if _normalize(translated2) == _normalize(payload):
        _log.warning(
            "translate_retry_returned_source",
            lang=lang,
            model=cfg.model,
            preview=payload[:80],
        )
        return None
    final_lang = (lang2 or lang).lower()
    if final_lang == cfg.target_lang.lower():
        # V2 sagt „schon Zielsprache", widerspricht V1 — vertraue V1.
        final_lang = lang.lower()
    return Translation(
        language=final_lang,
        translated_text=_restore_mentions(text, translated2.strip()),
    )


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
