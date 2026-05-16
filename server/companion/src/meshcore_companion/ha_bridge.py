"""LLM-Bridge zu Home Assistant: beantwortet DMs aus natürlicher Sprache
mit Werten aus dem kuratierten HA-Sensor-Katalog.

Datenfluss (eine DM → eine Antwort-DM):

1. ``_handle_inbound_dm`` im CompanionService erkennt eine DM und prüft
   anhand von :func:`should_run_bridge`, ob diese Identity die HA-Bridge
   aktiv hat *und* der Sender-Pubkey auf der Whitelist steht.
2. Wenn ja, wird :func:`handle_query` als Hintergrund-Task gestartet
   (der DM-Pfad selbst darf nie wegen der Bridge hängen).
3. :func:`handle_query` läuft:

   * Rate-Limit pro Sender-Pubkey prüfen (Token-Bucket im Speicher).
   * Routing-Call gegen Ollama → JSON ``{"entities":[…], "reason":…}``.
   * Trifft das Routing keine Entity → Chat-Fallback-Prompt für eine
     natürliche freie Antwort (kein HA-Read, kein Halluzinieren).
   * Sonst: HA-Reads parallel → Formulierungs-Call → Antworttext.
   * Hard-Trim auf 200 Bytes (UTF-8-safe), Send-DM zurück.

Fehler-Pfade sind bewusst lax: jeder unerwartete Fehler endet in einem
``log.warning`` und liefert entweder eine kurze Skip-Antwort oder gar
keine. Der DM-Empfangspfad darf nie destabilisiert werden.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID
from zoneinfo import ZoneInfo

import httpx
import structlog

from meshcore_companion.homeassistant import (
    HAState,
    HomeAssistantClient,
    HomeAssistantError,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

_log = structlog.get_logger("companion.ha_bridge")

# Maximal-Länge der Antwort-DM in UTF-8-Bytes. Bewusst etwas unter dem
# TXT_MSG-Plaintext-Limit (~229 Byte), damit Header/Ack-Felder noch
# Luft haben. Reicht für 1-2 ganze deutsche Sätze.
MAX_REPLY_BYTES = 200

# Letzter Notnagel, wenn auch der Chat-Fallback-LLM-Call scheitert.
# Im Normalfall versucht der Bot bei „keine Entity gefunden" eine
# freie Antwort über :func:`_build_chat_prompt` zu formulieren.
_NO_ROUTE_MESSAGE = "(keine passenden Sensoren gefunden)"

# Sicherheits-Cap: auch wenn der LLM-Router mehr Entities zurückgibt als
# in den Identity-Settings erlaubt, kappen wir hart. Schützt den
# HA-Adapter und das Mesh-Antwort-Limit.
_HARD_ENTITIES_PER_QUERY_CAP = 5


@dataclass
class _RateBucket:
    """Sliding-Window-Bucket pro Sender-Pubkey.

    Wir nutzen kein klassisches Token-Bucket (refill-rate), sondern eine
    Zeitstempel-Liste: einfacher zu reasoning'en und reicht, weil
    typische Mesh-Anfragen einzeln und sekundengetrennt eintrudeln.
    """

    timestamps: list[float] = field(default_factory=list)


@dataclass
class HaBridgeRunner:
    """Hält den Rate-Limit-State und kapselt die Ollama-Base-URL.

    Eine Instanz pro :class:`CompanionService`. ``ollama_base_url`` ist
    typischerweise dieselbe URL wie für den Translator (lokales Ollama),
    pro Identity kann das Modell aber unterschiedlich sein.
    """

    ollama_base_url: str
    timeout_s: float = 20.0
    # Per Sender-Pubkey ein Bucket. Erste 5-Minuten-Inaktivität-GC
    # passiert in :meth:`_rate_allow`, damit der Dict nicht wächst.
    _buckets: dict[bytes, _RateBucket] = field(default_factory=dict)

    def _rate_allow(self, sender_pubkey: bytes, *, limit_per_min: int, now: float) -> bool:
        """Reserviere einen Slot oder lehne ab. Liefert ``True`` = darf.

        Limit gilt strikt: ``> limit_per_min`` Anfragen in den letzten
        60 s → Block. Das Add passiert nur bei ``True`` — Block-Versuche
        zählen nicht weiter mit.
        """
        bucket = self._buckets.get(sender_pubkey)
        if bucket is None:
            bucket = _RateBucket()
            self._buckets[sender_pubkey] = bucket
        cutoff = now - 60.0
        bucket.timestamps = [t for t in bucket.timestamps if t >= cutoff]
        if len(bucket.timestamps) >= limit_per_min:
            return False
        bucket.timestamps.append(now)
        # Periodisches GC für nicht-aktive Sender (>5 min still).
        if len(self._buckets) > 256:
            gc_cutoff = now - 300.0
            self._buckets = {
                k: v
                for k, v in self._buckets.items()
                if v.timestamps and v.timestamps[-1] >= gc_cutoff
            }
        return True


# ---------- DB-Lookups ----------


async def should_run_bridge(
    *,
    sessionmaker: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    identity_id: UUID,
    sender_pubkey: bytes,
) -> bool:
    """Schnell-Pfad-Check im DM-Inbound: läuft die HA-Bridge für diese
    Identity überhaupt und ist der Sender freigeschaltet?

    Pollt zwei kleine Rows pro DM — bei einem ausgeschalteten oder gar
    nicht konfigurierten Setup zwei No-Op-Selects, das ist billig genug,
    um nicht zu cachen. Ein In-Memory-Cache würde nur dann lohnen, wenn
    das hier zur Bottleneck-Quelle würde.
    """
    from sqlalchemy import select

    from meshcore_bridge.db import CompanionHaAllowedPubkey, CompanionHaBridge

    async with sessionmaker() as db:
        bridge = await db.get(CompanionHaBridge, identity_id)
        if bridge is None or not bridge.enabled:
            return False
        hit = (
            await db.execute(
                select(CompanionHaAllowedPubkey.id).where(
                    CompanionHaAllowedPubkey.identity_id == identity_id,
                    CompanionHaAllowedPubkey.pubkey == sender_pubkey,
                )
            )
        ).first()
        return hit is not None


@dataclass(frozen=True, slots=True)
class _BridgeContext:
    """Geladene Settings für genau einen Query-Run."""

    ollama_model: str
    max_entities_per_query: int
    rate_limit_per_min: int
    entities: tuple[tuple[str, str, str | None], ...]
    """(entity_id, alias, hint)-Tripel, sortiert nach ``sort_order``."""


async def _load_bridge_context(
    *,
    sessionmaker: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    identity_id: UUID,
) -> _BridgeContext | None:
    """Lade Bridge-Settings + Entity-Katalog in *einer* Session.

    Liefert ``None``, wenn die Bridge inzwischen deaktiviert wurde
    (Race: Whitelist-Check war noch positiv, User klickte zwischendrin
    auf "aus") oder gar keine Entities konfiguriert sind — dann kann das
    LLM-Routing eh keine Antwort liefern.
    """
    from sqlalchemy import select

    from meshcore_bridge.db import CompanionHaBridge, CompanionHaExposedEntity

    async with sessionmaker() as db:
        bridge = await db.get(CompanionHaBridge, identity_id)
        if bridge is None or not bridge.enabled:
            return None
        rows = list(
            (
                await db.execute(
                    select(CompanionHaExposedEntity)
                    .where(CompanionHaExposedEntity.identity_id == identity_id)
                    .order_by(
                        CompanionHaExposedEntity.sort_order,
                        CompanionHaExposedEntity.alias,
                    )
                )
            ).scalars()
        )
        if not rows:
            return None
        return _BridgeContext(
            ollama_model=bridge.ollama_model,
            max_entities_per_query=bridge.max_entities_per_query,
            rate_limit_per_min=bridge.rate_limit_per_min,
            entities=tuple((r.entity_id, r.alias, r.hint) for r in rows),
        )


# ---------- Ollama-Calls ----------


def _build_routing_prompt(
    *, question: str, entities: Sequence[tuple[str, str, str | None]], max_pick: int
) -> list[dict[str, str]]:
    """System+User-Prompt für den Routing-Call.

    Bewusst klein und JSON-only. Wir geben dem Modell den Katalog als
    nummerierte Liste; das hilft kleinen Modellen, sich auf die Items
    zu fokussieren, statt ihren Vorrat an Trainings-Entities zu raten.
    """
    lines = [f"- {ent}: {alias}" + (f" ({hint})" if hint else "") for ent, alias, hint in entities]
    catalog = "\n".join(lines) if lines else "(leer)"
    system = (
        "Du bist ein Smart-Home-Router. Du wählst aus dem unten stehenden "
        "Sensor-Katalog die passenden Home-Assistant-Entities aus, um die "
        "Frage des Benutzers zu beantworten. "
        f"Wähle MAX {max_pick} Entities. Wenn keine passt, gib eine leere Liste zurück. "
        'Antworte AUSSCHLIESSLICH als JSON: {"entities":["sensor.x",...],"reason":"..."}.\n\n'
        f"Katalog:\n{catalog}"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": question},
    ]


_DE_WEEKDAYS = (
    "Montag",
    "Dienstag",
    "Mittwoch",
    "Donnerstag",
    "Freitag",
    "Samstag",
    "Sonntag",
)
_BERLIN_TZ = ZoneInfo("Europe/Berlin")


def _format_now_berlin(now: datetime | None = None) -> str:
    """Aktuelles Datum/Uhrzeit/Wochentag in Berlin als deutscher String.

    Eigene Formatierung statt ``locale``, weil die Container-Locale nicht
    garantiert ``de_DE`` ist.
    """
    dt = (now or datetime.now(_BERLIN_TZ)).astimezone(_BERLIN_TZ)
    return f"{_DE_WEEKDAYS[dt.weekday()]}, {dt:%d.%m.%Y}, {dt:%H:%M} Uhr (Europe/Berlin)"


def _build_answer_prompt(
    *,
    question: str,
    states: Sequence[HAState],
    aliases: dict[str, str],
) -> list[dict[str, str]]:
    """Formulierungs-Prompt: ≤180 Zeichen, deutsch, ganze Sätze."""
    if not states:
        data_block = "(keine Daten)"
    else:
        rows: list[str] = []
        for s in states:
            alias = aliases.get(s.entity_id, s.entity_id)
            unit = s.attributes.get("unit_of_measurement")
            unit_str = f" {unit}" if isinstance(unit, str) and unit else ""
            rows.append(f"- {alias} = {s.state}{unit_str}")
        data_block = "\n".join(rows)
    system = (
        "Du beantwortest eine LoRa-Mesh-DM auf Deutsch in höchstens 180 "
        "Zeichen. Antworte in ein bis zwei ganzen Sätzen, natürlich "
        "formuliert, ohne Anrede und ohne überflüssige Floskeln. Nenne "
        "Werte und Einheiten konkret. Wenn ein Zustand wie 'on'/'off', "
        "'home'/'not_home' geliefert wird, übersetze ihn sinnvoll ins "
        "Deutsche (z.B. 'läuft'/'aus', 'zu Hause'/'unterwegs'). Wenn "
        "keine Daten geliefert wurden, sag 'keine Daten verfügbar'.\n\n"
        f"Jetzt: {_format_now_berlin()}\n\n"
        f"Daten:\n{data_block}"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": question},
    ]


def _build_chat_prompt(
    *,
    question: str,
    entities: Sequence[tuple[str, str, str | None]],
) -> list[dict[str, str]]:
    """Fallback-Prompt für Fragen, zu denen das Routing keine Entity
    findet: freie Antwort auf Deutsch, ggf. mit Hinweis auf vorhandene
    Sensoren — damit der User weiß, wonach er fragen kann.
    """
    lines = [f"- {alias}" + (f" ({hint})" if hint else "") for _ent, alias, hint in entities]
    catalog = "\n".join(lines) if lines else "(keine)"
    system = (
        "Du bist ein freundlicher Smart-Home-Assistent in einem LoRa-Mesh. "
        "Antworte auf Deutsch in höchstens 180 Zeichen, ein bis zwei ganze "
        "Sätze, natürlich und ohne Floskeln. Zu dieser Frage hast du KEINE "
        "Live-Daten aus dem Smart Home — erfinde keine Werte. Wenn die "
        "Frage nicht zum Smart Home passt (Begrüßung, Smalltalk), antworte "
        "passend kurz. Wenn der User offenbar einen Sensor-Wert wollte, "
        "den du nicht hast, sag das knapp und nenne ggf. einen passenden "
        "Sensor aus der Liste, sofern einer thematisch nahe liegt. Datum, "
        "Uhrzeit und Wochentag darfst du direkt aus dem Kontext beantworten.\n\n"
        f"Jetzt: {_format_now_berlin()}\n\n"
        f"Verfügbare Sensoren (nur als Hinweis, keine Werte!):\n{catalog}"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": question},
    ]


async def _ollama_chat_json(
    *,
    base_url: str,
    model: str,
    messages: list[dict[str, str]],
    timeout_s: float,
) -> Any | None:
    """Ein ``/api/chat``-Roundtrip mit ``format=json``. Inneres JSON wird
    bereits geparsed zurückgegeben.

    Liefert ``None`` bei Timeout/HTTP/JSON-Fehler — der Aufrufer
    entscheidet, wie damit umzugehen ist.
    """
    payload = {
        "model": model,
        "messages": messages,
        "format": "json",
        "stream": False,
        "options": {"temperature": 0.0},
    }
    url = base_url.rstrip("/") + "/api/chat"
    try:
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
    except httpx.TimeoutException:
        _log.warning("ha_bridge_ollama_timeout", url=url, timeout_s=timeout_s)
        return None
    except httpx.HTTPError as exc:
        _log.warning("ha_bridge_ollama_http_error", url=url, error=str(exc))
        return None
    except ValueError as exc:
        _log.warning("ha_bridge_ollama_bad_response", url=url, error=str(exc))
        return None

    if not isinstance(data, dict):
        return None
    message = data.get("message")
    if not isinstance(message, dict):
        return None
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        return None
    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        _log.warning("ha_bridge_inner_json", error=str(exc), preview=content[:120])
        return None


async def _ollama_chat_text(
    *,
    base_url: str,
    model: str,
    messages: list[dict[str, str]],
    timeout_s: float,
) -> str | None:
    """Ein ``/api/chat``-Roundtrip ohne ``format=json``. Inhalt als
    Rohtext zurück."""
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {"temperature": 0.2},
    }
    url = base_url.rstrip("/") + "/api/chat"
    try:
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
    except httpx.TimeoutException:
        _log.warning("ha_bridge_ollama_timeout", url=url, timeout_s=timeout_s)
        return None
    except httpx.HTTPError as exc:
        _log.warning("ha_bridge_ollama_http_error", url=url, error=str(exc))
        return None
    except ValueError as exc:
        _log.warning("ha_bridge_ollama_bad_response", url=url, error=str(exc))
        return None
    if not isinstance(data, dict):
        return None
    message = data.get("message")
    if not isinstance(message, dict):
        return None
    content = message.get("content")
    if not isinstance(content, str):
        return None
    return content.strip()


# ---------- Output-Trimming ----------


def trim_to_bytes(text: str, max_bytes: int = MAX_REPLY_BYTES) -> str:
    """UTF-8-sicheres Zuschneiden auf ``max_bytes``. Hängt ``…`` an,
    wenn gekürzt wurde, und sorgt dafür, dass das Ergebnis inklusive
    Ellipse das Byte-Budget einhält.

    Bewusst keine Word-Boundary-Erkennung: für 200-Byte-Mesh-Antworten
    ist Mid-Word-Schnitt akzeptabel und in der Praxis selten relevant
    (Modell zielt schon auf ≤180 Zeichen).
    """
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    ellipsis = "…".encode()
    budget = max_bytes - len(ellipsis)
    if budget <= 0:
        return ""
    cut = encoded[:budget]
    # Letzte unvollständige UTF-8-Sequenz wegwerfen.
    decoded = cut.decode("utf-8", errors="ignore")
    return decoded + "…"


# ---------- Hauptablauf ----------


SendDmCallback = Callable[[UUID, bytes, str], Awaitable[bool]]


async def handle_query(
    *,
    runner: HaBridgeRunner,
    sessionmaker: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ha_client: HomeAssistantClient,
    identity_id: UUID,
    sender_pubkey: bytes,
    question: str,
    send_dm: SendDmCallback,
    now_monotonic: float | None = None,
) -> None:
    """Verarbeite eine eingehende DM-Anfrage und beantworte per DM zurück.

    Komplette Exception-Sicherheit: jede Exception wird gelogged, aber
    nicht propagiert — der DM-Pfad des Service darf nie wegen dieser
    Funktion fallen.
    """
    try:
        await _handle_query_inner(
            runner=runner,
            sessionmaker=sessionmaker,
            ha_client=ha_client,
            identity_id=identity_id,
            sender_pubkey=sender_pubkey,
            question=question,
            send_dm=send_dm,
            now_monotonic=now_monotonic,
        )
    except Exception:
        _log.exception(
            "ha_bridge_query_failed",
            identity_id=str(identity_id),
            sender_prefix=sender_pubkey[:4].hex(),
        )


async def _handle_query_inner(
    *,
    runner: HaBridgeRunner,
    sessionmaker: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ha_client: HomeAssistantClient,
    identity_id: UUID,
    sender_pubkey: bytes,
    question: str,
    send_dm: SendDmCallback,
    now_monotonic: float | None,
) -> None:
    ctx = await _load_bridge_context(sessionmaker=sessionmaker, identity_id=identity_id)
    if ctx is None:
        _log.info("ha_bridge_skipped_no_context", identity_id=str(identity_id))
        return

    now = now_monotonic if now_monotonic is not None else time.monotonic()
    if not runner._rate_allow(sender_pubkey, limit_per_min=ctx.rate_limit_per_min, now=now):
        _log.info(
            "ha_bridge_rate_limited",
            identity_id=str(identity_id),
            sender_prefix=sender_pubkey[:4].hex(),
            limit=ctx.rate_limit_per_min,
        )
        # Bewusst keine Antwort — sonst kann der Limiter selbst zum
        # Spam-Verstärker werden, wenn ein Peer aus Versehen einen
        # Bot-Loop bekommt.
        return

    max_pick = min(ctx.max_entities_per_query, _HARD_ENTITIES_PER_QUERY_CAP)
    routing_msgs = _build_routing_prompt(
        question=question, entities=ctx.entities, max_pick=max_pick
    )
    routing = await _ollama_chat_json(
        base_url=runner.ollama_base_url,
        model=ctx.ollama_model,
        messages=routing_msgs,
        timeout_s=runner.timeout_s,
    )
    picked = _extract_entities(routing, allowed={ent for ent, *_ in ctx.entities})
    if not picked:
        _log.info(
            "ha_bridge_no_route",
            identity_id=str(identity_id),
            sender_prefix=sender_pubkey[:4].hex(),
            question_preview=question[:60],
        )
        chat_msgs = _build_chat_prompt(question=question, entities=ctx.entities)
        chat_reply = await _ollama_chat_text(
            base_url=runner.ollama_base_url,
            model=ctx.ollama_model,
            messages=chat_msgs,
            timeout_s=runner.timeout_s,
        )
        await _safe_send(
            send_dm,
            identity_id,
            sender_pubkey,
            trim_to_bytes(chat_reply) if chat_reply else _NO_ROUTE_MESSAGE,
        )
        return

    # Cap auf max_pick — falls das Modell trotz Prompt-Regel mehr liefert.
    picked = picked[:max_pick]
    aliases = {ent: alias for ent, alias, _ in ctx.entities}

    # HA-Reads parallel.
    state_results = await asyncio.gather(
        *(ha_client.get_state(ent) for ent in picked),
        return_exceptions=True,
    )
    states: list[HAState] = []
    for ent, result in zip(picked, state_results, strict=True):
        if isinstance(result, HAState):
            states.append(result)
        elif isinstance(result, HomeAssistantError):
            _log.warning(
                "ha_bridge_ha_read_failed",
                identity_id=str(identity_id),
                entity=ent,
                error=str(result),
            )
        elif isinstance(result, BaseException):
            _log.warning(
                "ha_bridge_ha_read_exception",
                identity_id=str(identity_id),
                entity=ent,
                error=str(result),
            )

    if not states:
        # Alle HA-Reads ausgefallen → kurze Klartext-Antwort, kein zweiter
        # LLM-Call (würde nur halluzinieren).
        await _safe_send(
            send_dm,
            identity_id,
            sender_pubkey,
            "(HA-Werte gerade nicht erreichbar)",
        )
        return

    answer_msgs = _build_answer_prompt(question=question, states=states, aliases=aliases)
    answer = await _ollama_chat_text(
        base_url=runner.ollama_base_url,
        model=ctx.ollama_model,
        messages=answer_msgs,
        timeout_s=runner.timeout_s,
    )
    if not answer:
        # Fallback: deterministische Zeile aus den Werten, damit der
        # Sender wenigstens etwas bekommt.
        answer = _format_states_fallback(states, aliases)
    final = trim_to_bytes(answer)
    await _safe_send(send_dm, identity_id, sender_pubkey, final)
    _log.info(
        "ha_bridge_answered",
        identity_id=str(identity_id),
        sender_prefix=sender_pubkey[:4].hex(),
        entities=picked,
        reply_bytes=len(final.encode("utf-8")),
    )


def _extract_entities(routing: Any, *, allowed: set[str]) -> list[str]:
    """Robust gegen verschiedene JSON-Shapes, die kleine Modelle liefern.

    Erwarteter Shape: ``{"entities": ["sensor.x", ...]}``. Wir filtern
    auf den ``allowed``-Set, damit das Modell nichts halluzinieren kann,
    was nicht im Katalog steht.
    """
    if not isinstance(routing, dict):
        return []
    raw = routing.get("entities")
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            continue
        ent = item.strip()
        if ent in allowed and ent not in seen:
            seen.add(ent)
            out.append(ent)
    return out


def _format_states_fallback(states: Sequence[HAState], aliases: dict[str, str]) -> str:
    """Wenn der Antwort-LLM-Call fehlschlägt: trockene Auflistung
    ``alias=wert unit · alias=wert unit``."""
    parts: list[str] = []
    for s in states:
        alias = aliases.get(s.entity_id, s.entity_id)
        unit = s.attributes.get("unit_of_measurement")
        unit_str = f" {unit}" if isinstance(unit, str) and unit else ""
        parts.append(f"{alias}={s.state}{unit_str}")
    return " · ".join(parts)


async def _safe_send(
    send_dm: SendDmCallback,
    identity_id: UUID,
    sender_pubkey: bytes,
    text: str,
) -> None:
    """``send_dm`` mit Exception-Schutz. Wir wollen verhindern, dass eine
    Sende-Fehler den Error-Pfad des Aufrufers triggert (er hat schon
    geantwortet bzw. ist im Fallback)."""
    try:
        ok = await send_dm(identity_id, sender_pubkey, text)
    except Exception:
        _log.exception(
            "ha_bridge_send_dm_failed",
            identity_id=str(identity_id),
            sender_prefix=sender_pubkey[:4].hex(),
        )
        return
    if not ok:
        _log.warning(
            "ha_bridge_send_dm_rejected",
            identity_id=str(identity_id),
            sender_prefix=sender_pubkey[:4].hex(),
        )
