"""KI-Agent pro Companion-Identity.

Schlanker Ollama-Wrapper plus reine Hilfsfunktionen (Sanitizer, Jitter,
Mention-Detect, Anti-Loop-Filter). Die orchestrierende Schleife lebt in
:class:`meshcore_companion.service.CompanionService` (``_ai_agent_loop``)
— hier nur das, was sich isoliert testen lässt.

Designprinzipien:
- Synchron-blockierende LLM-Aufrufe haben hier nichts verloren — Ollama
  wird async über ``httpx.AsyncClient`` aufgerufen, gleiches Pattern wie
  :mod:`meshcore_companion.translator`.
- Fehler (Timeout, 5xx, leere Antwort) führen zu ``None``. Der Agent-
  Loop überlebt einzelne Ausfälle und probiert es im nächsten Tick neu.
- Mention-Detect ist deterministisch per Regex (siehe Memory
  ``feedback_llm_token_protection``): das LLM ist dafür zu fragil.
"""

from __future__ import annotations

import asyncio
import random
import re
import unicodedata
from dataclasses import dataclass

import httpx
import structlog

_log = structlog.get_logger("companion.ai_agent")

# Jitter-Faktor: nächste Wartezeit liegt zwischen 70% und 130% des Ziel-
# Mittelwerts. Klein genug, dass die durchschnittliche Posting-Rate
# vorhersagbar bleibt; groß genug, dass mehrere Agenten nicht
# uhrzeitgleich posten.
_JITTER_LOW = 0.7
_JITTER_HIGH = 1.3

# Wenn der LLM-Output über dieser Byte-Länge liegt, kappen wir hart auf
# einer UTF-8-Grenze. 140 Byte ist das pragmatische LoRa-TXT-Limit
# (MeshCore-Firmware verarbeitet auch etwas mehr, aber unter 140 ist
# sicher in einem Frame).
DEFAULT_MAX_BYTES = 140


@dataclass(frozen=True, slots=True)
class AiAgentClientConfig:
    """Subset der :class:`meshcore_bridge.config.AiAgentConfig`-Felder, die
    der Client wirklich braucht. Erlaubt, das Modul ohne Bridge-Paket-
    Abhängigkeit zu testen."""

    base_url: str
    model: str
    timeout_s: float
    max_attempts: int = 3
    retry_backoff_s: float = 2.0


# HTTP-Statuscode ab dem wir transient interpretieren (5xx).
_HTTP_SERVER_ERROR = 500


def jittered_interval_s(interval_s: int, *, rng: random.Random | None = None) -> float:
    """Liefert ``interval_s`` skaliert mit einem zufälligen Faktor aus
    ``[_JITTER_LOW, _JITTER_HIGH]``. Negative oder null Eingaben werden
    auf ``interval_s`` zurückgeworfen (kein Crash, der Loop darf sich
    nicht an einer Fehlkonfiguration totlaufen)."""
    if interval_s <= 0:
        return 0.0
    r = rng if rng is not None else random
    return interval_s * r.uniform(_JITTER_LOW, _JITTER_HIGH)


def mentions_identity(text: str, identity_name: str) -> bool:
    """Erkennt, ob ``identity_name`` als Wort in ``text`` vorkommt.

    Case-insensitive, mit Wort-Boundary — verhindert False-Positives auf
    Substrings (``"bot"`` in ``"robot"``). Leere Namen liefern ``False``.
    """
    name = identity_name.strip()
    if not name:
        return False
    pattern = r"(?<!\w)" + re.escape(name) + r"(?!\w)"
    return bool(re.search(pattern, text, re.IGNORECASE))


def sanitize_reply(text: str | None, *, max_bytes: int = DEFAULT_MAX_BYTES) -> str | None:
    """Bereinigt die LLM-Antwort für den LoRa-Versand.

    - Strip + Whitespace-Collapse.
    - Steuerzeichen (außer Newline) entfernen.
    - Newlines → Leerzeichen (Mesh-Chat ist single-line).
    - Auf ``max_bytes`` UTF-8 hart kappen, an Codepoint-Grenze (kein
      kaputtes Multi-Byte-Zeichen).

    Liefert ``None`` wenn nach dem Bereinigen nichts Sinnvolles übrig ist.
    """
    if not text:
        return None
    # Whitespace und C0/C1-Steuerzeichen ausfiltern
    cleaned_chars = []
    for ch in text:
        if ch in ("\n", "\r", "\t"):
            cleaned_chars.append(" ")
            continue
        if unicodedata.category(ch).startswith("C"):
            continue
        cleaned_chars.append(ch)
    cleaned = "".join(cleaned_chars)
    cleaned = " ".join(cleaned.split())
    if not cleaned:
        return None
    encoded = cleaned.encode("utf-8")
    if len(encoded) <= max_bytes:
        return cleaned
    # An Codepoint-Grenze kappen
    truncated = encoded[:max_bytes]
    while truncated:
        try:
            return truncated.decode("utf-8")
        except UnicodeDecodeError:
            truncated = truncated[:-1]
    return None


def parse_blocked_peer_names(raw: str | None) -> frozenset[str]:
    """Newline-separierte Liste in eine normalisierte Set überführen.

    Leere Zeilen werden ignoriert; jeder Name wird ``strip().casefold()``
    — der Vergleich gegen Sender-Anzeigenamen ist case-insensitive."""
    if not raw:
        return frozenset()
    return frozenset(line.strip().casefold() for line in raw.splitlines() if line.strip())


@dataclass(frozen=True, slots=True)
class HistoryFilter:
    """Anti-Loop-Filter für Channel-/DM-History, die dem LLM zugespielt wird.

    ``own_pubkeys`` enthält alle lokal bekannten Companion-Identitäts-
    Pubkeys (eigene + die anderer geladener Identitäten). ``blocked_names``
    ist die UI-Blacklist (newline-parsed via :func:`parse_blocked_peer_names`).
    """

    own_pubkeys: frozenset[bytes]
    blocked_names: frozenset[str]

    def allows(self, *, peer_pubkey: bytes | None, peer_name: str | None) -> bool:
        """``True`` wenn der Eintrag dem LLM gezeigt werden darf."""
        if peer_pubkey is not None and peer_pubkey in self.own_pubkeys:
            return False
        return not (peer_name and peer_name.strip().casefold() in self.blocked_names)


class AiAgentClient:
    """Wrapper um Ollama ``/api/chat`` für KI-Agent-Replies.

    Reine asyncio-Schnittstelle. Hält keinen langlebigen ``httpx.AsyncClient``
    — jeder Call öffnet seine eigene Connection. Bei den 1x/h-Frequenzen
    des KI-Agenten ist Connection-Reuse irrelevant, und so bleibt das Modul
    stateless/test-freundlich.
    """

    def __init__(self, cfg: AiAgentClientConfig) -> None:
        self._cfg = cfg

    @property
    def model(self) -> str:
        return self._cfg.model

    async def generate(
        self,
        *,
        system_prompt: str,
        history: list[dict[str, str]],
        max_bytes: int = DEFAULT_MAX_BYTES,
        model_override: str | None = None,
    ) -> str | None:
        """Liefert die sanitisierte Antwort des LLM oder ``None`` bei
        Skip/Fehler. ``history`` ist eine Liste von Ollama-Chat-Messages
        (jeweils ``{"role": "...", "content": "..."}``), ohne System-
        Message — die hängt der Wrapper voran.

        Retries: Timeouts und 5xx-Antworten werden bis zu
        ``max_attempts``-mal wiederholt, mit exponentiellem Back-off
        (``retry_backoff_s * 2**attempt``). 4xx-Antworten und JSON-Fehler
        sind nicht-transient und brechen sofort ab.
        """
        if not system_prompt.strip():
            return None
        messages: list[dict[str, str]] = [{"role": "system", "content": system_prompt}]
        messages.extend(history)
        payload = {
            "model": model_override or self._cfg.model,
            "messages": messages,
            "stream": False,
            # Thinking-Modus aus: gemma4/qwen3 packen sonst die ganze Antwort
            # ins ``thinking``-Feld und lassen ``content`` leer (Mesh-Chat hat
            # keinen Platz für Reasoning-Dumps). Ältere Ollama-Versionen
            # ignorieren den Key.
            "think": False,
            "options": {"temperature": 0.7},
        }
        url = self._cfg.base_url.rstrip("/") + "/api/chat"
        attempts = max(1, self._cfg.max_attempts)
        data: object | None = None
        for attempt in range(attempts):
            transient = False
            try:
                async with httpx.AsyncClient(timeout=self._cfg.timeout_s) as client:
                    resp = await client.post(url, json=payload)
                    if resp.status_code >= _HTTP_SERVER_ERROR:
                        _log.warning(
                            "ai_agent_http_error",
                            url=url,
                            status=resp.status_code,
                            attempt=attempt + 1,
                            of=attempts,
                        )
                        transient = True
                    else:
                        resp.raise_for_status()
                        data = resp.json()
                        break
            except httpx.TimeoutException:
                _log.warning(
                    "ai_agent_timeout",
                    url=url,
                    timeout_s=self._cfg.timeout_s,
                    attempt=attempt + 1,
                    of=attempts,
                )
                transient = True
            except httpx.HTTPError as exc:
                _log.warning("ai_agent_http_error", url=url, error=str(exc))
                return None
            except ValueError as exc:
                _log.warning("ai_agent_bad_json", url=url, error=str(exc))
                return None

            if not transient or attempt + 1 >= attempts:
                return None
            backoff = self._cfg.retry_backoff_s * (2**attempt)
            _log.info("ai_agent_retry_backoff", url=url, backoff_s=backoff)
            await asyncio.sleep(backoff)

        if data is None:
            return None
        raw_text = _extract_ollama_content(data)
        sanitized = sanitize_reply(raw_text, max_bytes=max_bytes)
        if sanitized is None:
            _log_sanitize_empty(raw_text, data)
        return sanitized


def _extract_ollama_content(data: object) -> str | None:
    if not isinstance(data, dict):
        return None
    message = data.get("message")
    if not isinstance(message, dict):
        return None
    content = message.get("content")
    if not isinstance(content, str):
        return None
    return content


def _log_sanitize_empty(raw_text: str | None, data: object) -> None:
    """Diagnose-Log, wenn Ollama-Response nach Sanitize leer ist."""
    thinking_len = 0
    if isinstance(data, dict):
        msg = data.get("message")
        if isinstance(msg, dict):
            thinking = msg.get("thinking")
            if isinstance(thinking, str):
                thinking_len = len(thinking)
    _log.info(
        "ai_agent_sanitize_empty",
        raw_len=len(raw_text or ""),
        preview=(raw_text or "")[:120],
        thinking_len=thinking_len,
    )
