"""CompanionService — orchestriert virtuelle Companion-Nodes auf dem Server.

Verbindungen:
- DB (CompanionIdentity, CompanionContact, CompanionMessage)
- Bridge-Router: Pakete-Receiver-Hook + Inject-Methode

Verantwortlichkeiten:
- Identitäten beim Start aus DB laden (privkey via storage.decrypt_seed)
- Pro Identity periodisch ein Advert in den Scope ausliefern
- Eingehende Pakete sniffen:
    * ADVERT      → CompanionContact upsert
    * TXT_MSG     → für jede unserer Identitäten try_decrypt; bei Hit
                    Message persistieren
- API: send_dm(identity, peer_pubkey, text)
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import time
from collections.abc import Awaitable, Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, ClassVar
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from meshcore_companion.coords import is_valid_coord
from meshcore_companion.crypto import (
    PATH_HASH_SIZE,
    Identity,
    LocalIdentity,
    derive_channel_secret,
)
from meshcore_companion.node import (
    ADV_TYPE_CHAT,
    ADV_TYPE_ROOM,
    CompanionNode,
    IncomingChannelMessage,
    IncomingResponse,
    IncomingRoomPost,
    IncomingTextMessage,
    compute_dm_ack_hash,
    compute_room_ack_hash,
    encode_advert_app_data,
    parse_advert_app_data,
    parse_login_response,
    parse_lpp_gps,
    parse_repeater_stats,
    try_decrypt_grp_txt,
)
from meshcore_companion.packet import Packet, PayloadType, RouteType
from meshcore_companion.storage import decrypt_seed, encrypt_seed

if TYPE_CHECKING:
    from meshcore_bridge.db import CompanionChannel, CompanionContact

_log = structlog.get_logger("companion")

# Tag-Prefix einer Reply (4 Byte LE timestamp/tag, vor reply_data)
_TAG_BYTES = 4
# DM-ACK-Hash-Länge (firmware: sha256(...)[:4]).
_ACK_HASH_LEN = 4

PacketInjector = Callable[[Packet, str], Awaitable[None]]
"""Callable(packet, scope) — fügt ein Paket in den Mesh-Scope ein."""

EventNotifier = Callable[[UUID, dict[str, object]], Awaitable[None]]
"""Callable(identity_id, event) — Push-Event in den UI-Bus (SSE).

``event`` ist ein JSON-serialisierbares dict mit ``type`` ∈
{"dm","channel","sent_dm","sent_channel","contact_update"} plus
typ-spezifischen Feldern."""

PUBLIC_CHANNEL_NAME = "public"
# Offizieller MeshCore-Public-Channel-PSK (base64, 16 Byte real). Quelle:
# firmware/lib/meshcore/examples/companion_radio/MyMesh.cpp PUBLIC_GROUP_PSK.
# Wir padden auf 32 Byte (letzte 16 Byte = 0). HMAC-SHA256 ist durch
# Block-Padding-Eigenschaft funktional identisch zu HMAC mit 16-Byte-Key,
# AES-128 nutzt nur die ersten 16 Byte.
PUBLIC_CHANNEL_PSK_B64 = "izOH6cXN6mrJ5e26oRXNcg=="
"""Default-Channel, der für jede Identity automatisch angelegt wird."""


def _public_channel_secret_and_hash() -> tuple[bytes, bytes]:
    """Liefert (secret_32, channel_hash_1) für den MeshCore-Public-Channel.
    channel_hash wird über die *echten* PSK-Bytes berechnet (Firmware-
    Konvention), nicht über das mit Nullen gepaddete 32-Byte-Secret.
    """
    real = base64.b64decode(PUBLIC_CHANNEL_PSK_B64)
    secret = real.ljust(32, b"\x00")
    chash = hashlib.sha256(real).digest()[:PATH_HASH_SIZE]
    return secret, chash


@dataclass
class LoadedIdentity:
    id: UUID
    user_id: UUID
    name: str
    scope: str
    node: CompanionNode
    is_echo: bool = False

    @property
    def pubkey(self) -> bytes:
        return self.node.pub_key


@dataclass
class LoginSession:
    """In-Memory-Session nach erfolgreichem ANON_REQ-Login an einem
    Repeater oder Room. Der Server selbst hält keinen sichtbaren Session-
    Timeout, daher ist die TTL hier eine Heuristik (Frontend-Hinweis).
    Geht beim Container-Restart verloren — User muss sich neu einloggen.
    """

    expires_at: float  # monotonic seconds
    is_admin: bool
    permissions: int


# Default-TTL für eingeloggte Sessions (1 Stunde).
_LOGIN_SESSION_TTL_S = 3600


@dataclass
class _EchoRateState:
    """Pro-Sender-Zustand für die progressiv steigende Echo-Rate-Begrenzung.

    ``streak`` wächst um 1 mit jeder Reply, die innerhalb des
    Reset-Fensters (``_ECHO_RL_STREAK_RESET_S``) der vorherigen Reply
    landet; sonst startet er wieder bei 1. Cooldown verdoppelt sich pro
    Streak-Stufe (``_ECHO_RL_BASE_S * 2**(streak-1)``), gedeckelt bei
    ``_ECHO_RL_MAX_S``."""

    next_allowed_at: float  # monotonic
    last_reply_at: float  # monotonic
    streak: int


@dataclass
class _RetryMeta:
    """Metadaten für automatische Retries bei ausbleibender RESPONSE.

    Wir speichern alles, was wir brauchen, um den Request bei Timeout
    mit neuem Tag neu zu bauen — ohne den Original-Caller (FastAPI-Route)
    erneut zu involvieren.
    """

    kind: str  # "login" | "status" | "telemetry"
    identity_id: UUID
    peer_pubkey: bytes
    retries_left: int
    flood: bool  # True → FLOOD-Routing, False → DIRECT
    # Builder-spezifische Parameter:
    password: str | None = None  # nur für login relevant
    msg_id: UUID | None = None  # ID der „warte auf Antwort"-Bubble


@dataclass
class CompanionService:
    master_key: bytes
    sessionmaker: Callable[[], AbstractAsyncContextManager[AsyncSession]]
    inject: PacketInjector | None = None
    notify: EventNotifier | None = None
    advert_interval_s: int = 600

    _by_id: dict[UUID, LoadedIdentity] = field(default_factory=dict)
    _by_pubkey: dict[bytes, LoadedIdentity] = field(default_factory=dict)
    _advert_task: asyncio.Task[None] | None = None
    _stop: asyncio.Event = field(default_factory=asyncio.Event)
    # Inbound-Dedup: gleiches raw-Paket kommt pro verbundenem Repeater einmal
    # rein. Ohne dedup persistieren wir GRP_TXT/TXT_MSG mehrfach.
    _seen_raw: dict[bytes, float] = field(default_factory=dict)
    # Pending REQ-Tracker: tag → (sent_monotonic, req_type, identity_id, peer_pubkey).
    # Wird beim Empfang einer RESPONSE konsultiert, um die Antwort dem
    # passenden Request-Typ zuzuordnen (Status vs Telemetrie vs ...).
    _pending_reqs: dict[int, tuple[float, int, UUID, bytes]] = field(default_factory=dict)
    # Retry-Metadaten parallel zu _pending_reqs (gleicher Tag-Schlüssel).
    # Trägt alles, was wir brauchen, um den Request bei Timeout neu
    # aufzubauen — Builder-Parameter, restliche Versuche, Route-Type.
    _retry_meta: dict[int, _RetryMeta] = field(default_factory=dict)
    # Aktive Login-Sessions (in-memory). Key = (identity_id, peer_pubkey).
    _login_sessions: dict[tuple[UUID, bytes], LoginSession] = field(default_factory=dict)
    # Hintergrund-Tasks für Request-Timeouts. Wir halten Referenzen, damit
    # der GC sie nicht canceln kann, solange sie noch laufen.
    _request_timeout_tasks: set[asyncio.Task[None]] = field(default_factory=set)
    # Echo-Bot-Rate-Limit pro Sender-Pubkey. Schlüssel = sender_pubkey
    # (32 Byte); Wert = Backoff-Zustand. Siehe ``_echo_rate_allow``.
    _echo_rl: dict[bytes, _EchoRateState] = field(default_factory=dict)
    # Pending DIRECT-DMs: ack_hash(4) → (sent_monotonic, identity_id, peer_pubkey).
    # Wenn der ACK in ``_DM_DIRECT_TIMEOUT_S`` ausbleibt, gilt der gelernte
    # out_path als stale → wir invalidieren ihn (NULL setzen) und der nächste
    # send_dm geht per FLOOD. Nur DIRECT-Sends werden getrackt; FLOOD braucht
    # keine Invalidation (kein Pfad zum Verwerfen).
    _pending_dms: dict[bytes, tuple[float, UUID, bytes]] = field(default_factory=dict)
    _dm_timeout_tasks: set[asyncio.Task[None]] = field(default_factory=set)
    # Pending Link-Probes: tag → (sent_monotonic, probe_id, identity_id, peer_pubkey).
    # Probe = STATUS-REQ ohne UI-Bubble; getrennter Tracker, damit der
    # normale REQ-Antwort-Flow (Persistierung als CompanionMessage) nicht
    # getriggert wird. Kein Retry — Loss soll messbar sein, nicht
    # maskiert. Siehe ``send_link_probe``.
    _pending_probes: dict[int, tuple[float, UUID, UUID, bytes]] = field(default_factory=dict)
    _probe_timeout_tasks: set[asyncio.Task[None]] = field(default_factory=set)

    # Echo-Rate-Limit-Parameter. Reply 1 → Cooldown 5 s,
    # 2 → 10, 3 → 20 … gedeckelt bei 300 s. Nach 600 s ohne Reply
    # an denselben Sender startet die Streak wieder bei 1.
    _ECHO_RL_BASE_S: ClassVar[float] = 5.0
    _ECHO_RL_MAX_S: ClassVar[float] = 300.0
    _ECHO_RL_STREAK_RESET_S: ClassVar[float] = 600.0
    _ECHO_RL_DICT_MAX: ClassVar[int] = 256

    # ACK-Wartefrist für DIRECT-DMs. Wenn keine ACK in dieser Zeit ankommt,
    # gilt der gelernte out_path als stale (Topologie-Änderung, Repeater
    # offline, …) → wir invalidieren ihn.
    _DM_DIRECT_TIMEOUT_S: ClassVar[float] = 30.0

    # Wartefrist für Link-Probes. Etwas großzügiger als _REQ_TIMEOUT_S, damit
    # Multi-Hop-FLOOD-Probes nicht fälschlich als "loss" gewertet werden.
    _PROBE_TIMEOUT_S: ClassVar[float] = 30.0

    async def _emit(self, identity_id: UUID, event: dict[str, object]) -> None:
        if self.notify is None:
            return
        try:
            await self.notify(identity_id, event)
        except Exception:
            _log.exception("notify_failed", type=event.get("type"))

    async def start(self) -> None:
        """DB → Identitäten laden, Advert-Loop starten."""
        from meshcore_bridge.db import CompanionIdentity

        async with self.sessionmaker() as db:
            rows = list(
                (
                    await db.execute(
                        select(CompanionIdentity).where(CompanionIdentity.archived_at.is_(None))
                    )
                ).scalars()
            )
            for row in rows:
                seed = decrypt_seed(self.master_key, row.id, row.privkey_enc)
                local = LocalIdentity(seed)
                loaded = LoadedIdentity(
                    id=row.id,
                    user_id=row.user_id,
                    name=row.name,
                    scope=row.scope,
                    node=CompanionNode(local),
                    is_echo=row.is_echo,
                )
                self._by_id[row.id] = loaded
                self._by_pubkey[loaded.pubkey] = loaded

        # Default-Public-Channel pro Identity sicherstellen
        for identity_id in list(self._by_id.keys()):
            await self._ensure_public_channel(identity_id)

        self._stop.clear()
        self._advert_task = asyncio.create_task(self._advert_loop())

    async def stop(self) -> None:
        self._stop.set()
        if self._advert_task is not None:
            self._advert_task.cancel()
            try:
                await self._advert_task
            except asyncio.CancelledError:
                pass

    def __len__(self) -> int:
        return len(self._by_id)

    def list_identities(self) -> list[LoadedIdentity]:
        return list(self._by_id.values())

    def get(self, identity_id: UUID) -> LoadedIdentity | None:
        return self._by_id.get(identity_id)

    async def add_identity(
        self,
        *,
        user_id: UUID,
        name: str,
        scope: str,
        is_echo: bool = False,
    ) -> LoadedIdentity:
        """Erzeugt eine neue Identity, persistiert sie verschlüsselt."""
        from meshcore_bridge.db import CompanionIdentity

        local = LocalIdentity.generate()
        async with self.sessionmaker() as db:
            row = CompanionIdentity(
                user_id=user_id,
                name=name,
                pubkey=local.pub_key,
                privkey_enc=b"",  # placeholder, replaced below
                scope=scope,
                is_echo=is_echo,
            )
            db.add(row)
            await db.flush()
            row.privkey_enc = encrypt_seed(self.master_key, row.id, local.seed)
            await db.commit()
            row_id = row.id

        loaded = LoadedIdentity(
            id=row_id,
            user_id=user_id,
            name=name,
            scope=scope,
            node=CompanionNode(local),
            is_echo=is_echo,
        )
        self._by_id[row_id] = loaded
        self._by_pubkey[loaded.pubkey] = loaded
        # Default-Public-Channel mit anlegen
        await self._ensure_public_channel(row_id)
        # Erst-Advert sofort
        await self._send_advert(loaded)
        return loaded

    async def archive_identity(self, identity_id: UUID) -> bool:
        from meshcore_bridge.db import CompanionIdentity

        async with self.sessionmaker() as db:
            row = await db.get(CompanionIdentity, identity_id)
            if row is None:
                return False
            row.archived_at = datetime.now(UTC)
            await db.commit()
        loaded = self._by_id.pop(identity_id, None)
        if loaded is not None:
            self._by_pubkey.pop(loaded.pubkey, None)
        return True

    async def rename_identity(self, identity_id: UUID, new_name: str) -> bool:
        from meshcore_bridge.db import CompanionIdentity

        clean = new_name.strip()
        if not clean:
            return False
        async with self.sessionmaker() as db:
            row = await db.get(CompanionIdentity, identity_id)
            if row is None or row.archived_at is not None:
                return False
            row.name = clean
            await db.commit()
        loaded = self._by_id.get(identity_id)
        if loaded is not None:
            loaded.name = clean
        return True

    async def set_echo(self, identity_id: UUID, enabled: bool) -> bool:
        """Schaltet das Echo-Bot-Flag um (DB + In-Memory)."""
        from meshcore_bridge.db import CompanionIdentity

        async with self.sessionmaker() as db:
            row = await db.get(CompanionIdentity, identity_id)
            if row is None or row.archived_at is not None:
                return False
            row.is_echo = enabled
            await db.commit()
        loaded = self._by_id.get(identity_id)
        if loaded is not None:
            loaded.is_echo = enabled
        _log.info("is_echo_toggled", identity_id=str(identity_id), enabled=enabled)
        return True

    async def delete_channel(self, channel_id: UUID) -> bool:
        from meshcore_bridge.db import CompanionChannel

        async with self.sessionmaker() as db:
            row = await db.get(CompanionChannel, channel_id)
            if row is None:
                return False
            await db.delete(row)
            await db.commit()
        return True

    _PENDING_REQ_TTL_S = 300.0
    # Echte MeshCore-REQ-Typen
    REQ_TYPE_STATUS = 0x01
    REQ_TYPE_TELEMETRY = 0x03
    # Pseudo-Marker für eigenen Tag-Tracker (kein Wire-Code) — ANON_REQ
    # ist ein eigener PayloadType, kein REQ-Subtyp.
    REQ_TYPE_LOGIN = 0xF1

    def _track_pending_req(
        self,
        *,
        tag: int,
        req_type: int,
        identity_id: UUID,
        peer_pubkey: bytes,
    ) -> None:
        """Tag in der pending-Map ablegen und alte Einträge ausräumen.
        Wird beim Empfang einer RESPONSE benutzt, um die Antwort einem
        Request-Typ zuzuordnen (Status, Telemetrie, …)."""
        now = time.monotonic()
        cutoff = now - self._PENDING_REQ_TTL_S
        self._pending_reqs = {t: v for t, v in self._pending_reqs.items() if v[0] >= cutoff}
        self._pending_reqs[tag] = (now, req_type, identity_id, peer_pubkey)

    # User-facing Timeout pro Versuch (REQ → RESPONSE). Wird beim Retry
    # mehrfach hintereinander durchlaufen — je nach Route-Type bis zu
    # ``_RETRIES_FLOOD`` bzw. ``_RETRIES_DIRECT`` mal.
    _REQ_TIMEOUT_S = 20
    # Anzahl Wiederholungen NACH dem ersten Versuch. Total = 1 + retries.
    _RETRIES_FLOOD = 3  # ~ 4 Versuche * 20s = 80s max
    _RETRIES_DIRECT = 5  # ~ 6 Versuche * 20s = 120s max
    _REQ_KIND_META: ClassVar[dict[str, tuple[str, str]]] = {
        # kind → (icon, label)
        "login": ("🔑", "Login"),
        "status": ("ℹ", "Status"),
        "telemetry": ("📡", "Telemetrie"),
    }

    async def _persist_pending_request(
        self,
        *,
        loaded: LoadedIdentity,
        peer_pubkey: bytes,
        kind: str,
        tag: int,
    ) -> UUID | None:
        """Schreibt eine "warte auf Antwort"-Bubble als CompanionMessage in
        die DB und feuert ein SSE-Event mit ``expires_at`` für den Frontend-
        Countdown. Persistierung sorgt dafür, dass der Anfrage-Verlauf nach
        Reload sichtbar bleibt. Liefert die DB-msg_id zurück, damit Retries
        die bestehende Bubble per SSE-Update referenzieren können."""
        from meshcore_bridge.db import CompanionContact, CompanionMessage

        icon, label = self._REQ_KIND_META.get(kind, ("?", kind))
        now_ts = datetime.now(UTC)
        expires_at = now_ts + timedelta(seconds=self._REQ_TIMEOUT_S)
        text = f"{icon} {label} angefragt — warte auf Antwort… ({self._REQ_TIMEOUT_S}s)"
        async with self.sessionmaker() as db:
            peer_name = (
                await db.execute(
                    select(CompanionContact.peer_name).where(
                        CompanionContact.identity_id == loaded.id,
                        CompanionContact.peer_pubkey == peer_pubkey,
                    )
                )
            ).scalar_one_or_none()
            msg = CompanionMessage(
                identity_id=loaded.id,
                direction="system",
                payload_type=int(PayloadType.REQ),
                peer_pubkey=peer_pubkey,
                peer_name=peer_name,
                text=text,
                raw=b"",
                ts=now_ts,
            )
            db.add(msg)
            await db.commit()
            msg_id = msg.id
        await self._emit(
            loaded.id,
            {
                "type": "pending_request",
                "id": str(msg_id),
                "tag": tag,
                "kind": kind,
                "ts": now_ts.isoformat(),
                "expires_at": expires_at.isoformat(),
                "timeout_s": self._REQ_TIMEOUT_S,
                "peer_pubkey_hex": peer_pubkey.hex(),
                "peer_name": peer_name,
                "text": text,
                "direction": "system",
            },
        )
        return msg_id

    async def _timeout_pending_req(
        self,
        *,
        tag: int,
        identity_id: UUID,
        peer_pubkey: bytes,
        kind: str,
    ) -> None:
        """Wird als Hintergrund-Task pro REQ gestartet. Schläft
        ``_REQ_TIMEOUT_S`` und prüft, ob der Tag noch im pending-Pool ist —
        wenn ja, wurde keine RESPONSE empfangen. Falls Retries übrig:
        Request mit neuem Tag erneut senden (transparent für UI). Sonst
        finales „abgelaufen"-Event."""
        from meshcore_bridge.db import CompanionContact, CompanionMessage

        await asyncio.sleep(self._REQ_TIMEOUT_S)
        if self._pending_reqs.pop(tag, None) is None:
            return  # RESPONSE kam rechtzeitig — Tag wurde schon entfernt
        loaded = self._by_id.get(identity_id)
        if loaded is None:
            self._retry_meta.pop(tag, None)
            return

        # Retry-Versuch: nur wenn Retry-Meta existiert und retries_left > 0.
        meta = self._retry_meta.pop(tag, None)
        if meta is not None and meta.retries_left > 0:
            retried = await self._retry_request(meta=meta)
            if retried:
                return  # neuer Timeout-Task wurde gespawned

        _icon, label = self._REQ_KIND_META.get(kind, ("?", kind))
        text = f"⏱ {label}-Anfrage abgelaufen ({self._REQ_TIMEOUT_S}s ohne Antwort)"
        now_ts = datetime.now(UTC)
        async with self.sessionmaker() as db:
            peer_name = (
                await db.execute(
                    select(CompanionContact.peer_name).where(
                        CompanionContact.identity_id == loaded.id,
                        CompanionContact.peer_pubkey == peer_pubkey,
                    )
                )
            ).scalar_one_or_none()
            msg = CompanionMessage(
                identity_id=loaded.id,
                direction="system",
                payload_type=int(PayloadType.REQ),
                peer_pubkey=peer_pubkey,
                peer_name=peer_name,
                text=text,
                raw=b"",
                ts=now_ts,
            )
            db.add(msg)
            await db.commit()
            msg_id = msg.id
        await self._emit(
            loaded.id,
            {
                "type": "request_timeout",
                "id": str(msg_id),
                "tag": tag,
                "kind": kind,
                "ts": now_ts.isoformat(),
                "peer_pubkey_hex": peer_pubkey.hex(),
                "peer_name": peer_name,
                "text": text,
                "direction": "system",
            },
        )
        _log.info(
            "request_timeout",
            identity=loaded.name,
            peer=peer_pubkey[:4].hex(),
            tag=tag,
            kind=kind,
        )

    def _spawn_request_timeout(
        self, *, tag: int, identity_id: UUID, peer_pubkey: bytes, kind: str
    ) -> None:
        """Startet die Timeout-Coroutine als Hintergrund-Task."""
        task = asyncio.create_task(
            self._timeout_pending_req(
                tag=tag,
                identity_id=identity_id,
                peer_pubkey=peer_pubkey,
                kind=kind,
            )
        )
        self._request_timeout_tasks.add(task)
        task.add_done_callback(self._request_timeout_tasks.discard)

    def _track_pending_dm(
        self, *, ack_hash: bytes, identity_id: UUID, peer_pubkey: bytes
    ) -> None:
        """Trackt eine ausgehende DIRECT-DM gegen ihren erwarteten ACK-Hash
        und spawnt den Invalidations-Timeout-Task."""
        self._pending_dms[ack_hash] = (time.monotonic(), identity_id, peer_pubkey)
        task = asyncio.create_task(
            self._timeout_pending_dm(
                ack_hash=ack_hash,
                identity_id=identity_id,
                peer_pubkey=peer_pubkey,
            )
        )
        self._dm_timeout_tasks.add(task)
        task.add_done_callback(self._dm_timeout_tasks.discard)

    async def _timeout_pending_dm(
        self, *, ack_hash: bytes, identity_id: UUID, peer_pubkey: bytes
    ) -> None:
        """Wartet ``_DM_DIRECT_TIMEOUT_S`` und invalidiert den out_path
        des Peers, falls bis dahin kein ACK eingetroffen ist (ACK-Empfang
        löscht den Pending-Eintrag)."""
        from meshcore_bridge.db import CompanionContact

        await asyncio.sleep(self._DM_DIRECT_TIMEOUT_S)
        if self._pending_dms.pop(ack_hash, None) is None:
            return  # ACK kam rechtzeitig
        async with self.sessionmaker() as db:
            contact = (
                await db.execute(
                    select(CompanionContact).where(
                        CompanionContact.identity_id == identity_id,
                        CompanionContact.peer_pubkey == peer_pubkey,
                    )
                )
            ).scalar_one_or_none()
            if contact is None or contact.out_path is None:
                return
            contact.out_path = None
            contact.out_path_updated_at = datetime.now(UTC)
            await db.commit()
        _log.info(
            "dm_out_path_invalidated",
            peer=peer_pubkey[:4].hex(),
            reason="ack_timeout",
            timeout_s=self._DM_DIRECT_TIMEOUT_S,
        )

    def _retries_quota(self, *, flood: bool) -> int:
        """Anzahl Retries je nach Route-Type. FLOOD ist „teuer" (jeder Retry
        re-floodet die Topologie), DIRECT ist „billig" (1 Paket pro Versuch),
        deshalb mehr DIRECT-Retries."""
        return self._RETRIES_FLOOD if flood else self._RETRIES_DIRECT

    async def _retry_request(self, *, meta: _RetryMeta) -> bool:
        """Baut den Request basierend auf ``meta`` neu (mit frischem Random-
        Tag), trackt ihn, sendet ihn raus und spawnt einen neuen Timeout-
        Task. Liefert True bei Erfolg, False wenn etwas am Re-Build schief
        ging (in dem Fall wird der Aufrufer den finalen Timeout-Pfad gehen).
        """
        loaded = self._by_id.get(meta.identity_id)
        if loaded is None:
            return False

        if meta.kind == "login":
            pkt, new_tag = loaded.node.make_anon_login_req(
                peer_pubkey=meta.peer_pubkey,
                password=meta.password or "",
                flood=meta.flood,
            )
            req_type = self.REQ_TYPE_LOGIN
        elif meta.kind == "status":
            pkt, new_tag = loaded.node.make_status_req(
                peer_pubkey=meta.peer_pubkey, flood=meta.flood
            )
            req_type = self.REQ_TYPE_STATUS
        elif meta.kind == "telemetry":
            pkt, new_tag = loaded.node.make_telemetry_req(
                peer_pubkey=meta.peer_pubkey, flood=meta.flood
            )
            req_type = self.REQ_TYPE_TELEMETRY
        else:
            return False

        new_meta = _RetryMeta(
            kind=meta.kind,
            identity_id=meta.identity_id,
            peer_pubkey=meta.peer_pubkey,
            retries_left=meta.retries_left - 1,
            flood=meta.flood,
            password=meta.password,
            msg_id=meta.msg_id,
        )
        self._retry_meta[new_tag] = new_meta
        self._track_pending_req(
            tag=new_tag,
            req_type=req_type,
            identity_id=meta.identity_id,
            peer_pubkey=meta.peer_pubkey,
        )
        self._spawn_request_timeout(
            tag=new_tag,
            identity_id=meta.identity_id,
            peer_pubkey=meta.peer_pubkey,
            kind=meta.kind,
        )

        total_retries = self._retries_quota(flood=meta.flood)
        attempt = total_retries - new_meta.retries_left + 1  # 1-basiert
        total = total_retries + 1
        _log.info(
            "request_retry",
            identity=loaded.name,
            peer=meta.peer_pubkey[:4].hex(),
            kind=meta.kind,
            new_tag=new_tag,
            attempt=attempt,
            total=total,
            flood=meta.flood,
        )
        await self._emit(
            meta.identity_id,
            {
                "type": "request_retry",
                "id": str(meta.msg_id) if meta.msg_id is not None else None,
                "tag": new_tag,
                "kind": meta.kind,
                "attempt": attempt,
                "total": total,
                "peer_pubkey_hex": meta.peer_pubkey.hex(),
                "timeout_s": self._REQ_TIMEOUT_S,
            },
        )
        if self.inject is not None:
            await self.inject(pkt, loaded.scope)
        return True

    async def request_telemetry(
        self,
        *,
        identity_id: UUID,
        peer_pubkey: bytes,
    ) -> bool:
        """Schickt einen REQ_TYPE_GET_TELEMETRY_DATA an ``peer_pubkey``.

        Fire-and-forget: die RESPONSE wird asynchron via
        ``_handle_inbound_response`` verarbeitet (LPP-Buffer parsen, falls
        ``LPP_GPS`` enthalten ist → ``CompanionContact.last_lat/last_lon``
        aktualisieren). Bei Timeout retry'd der Service automatisch
        gemäß ``_RETRIES_FLOOD``/``_RETRIES_DIRECT``.
        """
        loaded = self._by_id.get(identity_id)
        if loaded is None:
            return False
        flood = True
        pkt, tag = loaded.node.make_telemetry_req(peer_pubkey=peer_pubkey, flood=flood)
        self._track_pending_req(
            tag=tag,
            req_type=self.REQ_TYPE_TELEMETRY,
            identity_id=identity_id,
            peer_pubkey=peer_pubkey,
        )
        msg_id = await self._persist_pending_request(
            loaded=loaded, peer_pubkey=peer_pubkey, kind="telemetry", tag=tag
        )
        self._retry_meta[tag] = _RetryMeta(
            kind="telemetry",
            identity_id=identity_id,
            peer_pubkey=peer_pubkey,
            retries_left=self._retries_quota(flood=flood),
            flood=flood,
            msg_id=msg_id,
        )
        self._spawn_request_timeout(
            tag=tag, identity_id=identity_id, peer_pubkey=peer_pubkey, kind="telemetry"
        )
        _log.info(
            "telemetry_req",
            identity=loaded.name,
            peer=peer_pubkey[:4].hex(),
            tag=tag,
        )
        if self.inject is not None:
            await self.inject(pkt, loaded.scope)
        return True

    def get_login_session(self, identity_id: UUID, peer_pubkey: bytes) -> LoginSession | None:
        """Liefert eine aktive LoginSession oder ``None`` wenn ausgeloggt
        bzw. abgelaufen. Räumt nebenbei abgelaufene Einträge auf."""
        key = (identity_id, peer_pubkey)
        session = self._login_sessions.get(key)
        if session is None:
            return None
        if session.expires_at <= time.monotonic():
            self._login_sessions.pop(key, None)
            return None
        return session

    async def request_login(
        self,
        *,
        identity_id: UUID,
        peer_pubkey: bytes,
        password: str = "",
    ) -> bool:
        """ANON_REQ-Login bei einem Repeater oder Room. Bei leerem Passwort
        versucht der Server einen Guest-Match (oft erlaubt). Antwort kommt
        als RESPONSE mit ``RESP_SERVER_LOGIN_OK``. Bei Timeout retry'd der
        Service automatisch (FLOOD-Quota)."""
        loaded = self._by_id.get(identity_id)
        if loaded is None:
            return False
        flood = True
        pkt, tag = loaded.node.make_anon_login_req(
            peer_pubkey=peer_pubkey, password=password, flood=flood
        )
        self._track_pending_req(
            tag=tag,
            req_type=self.REQ_TYPE_LOGIN,
            identity_id=identity_id,
            peer_pubkey=peer_pubkey,
        )
        msg_id = await self._persist_pending_request(
            loaded=loaded, peer_pubkey=peer_pubkey, kind="login", tag=tag
        )
        self._retry_meta[tag] = _RetryMeta(
            kind="login",
            identity_id=identity_id,
            peer_pubkey=peer_pubkey,
            retries_left=self._retries_quota(flood=flood),
            flood=flood,
            password=password,
            msg_id=msg_id,
        )
        self._spawn_request_timeout(
            tag=tag, identity_id=identity_id, peer_pubkey=peer_pubkey, kind="login"
        )
        _log.info(
            "login_req",
            identity=loaded.name,
            peer=peer_pubkey[:4].hex(),
            tag=tag,
            with_password=bool(password),
        )
        if self.inject is not None:
            await self.inject(pkt, loaded.scope)
        return True

    async def request_status(
        self,
        *,
        identity_id: UUID,
        peer_pubkey: bytes,
    ) -> bool:
        """Schickt einen REQ_TYPE_GET_STATUS — quasi „Ping mit Status-Daten".

        Antwort kommt als RESPONSE mit einer ``RepeaterStats``-Struktur,
        Round-Trip-Zeit messen wir via ``_pending_reqs``. Bei Timeout
        retry'd der Service automatisch (FLOOD-Quota).
        """
        loaded = self._by_id.get(identity_id)
        if loaded is None:
            return False
        flood = True
        pkt, tag = loaded.node.make_status_req(peer_pubkey=peer_pubkey, flood=flood)
        self._track_pending_req(
            tag=tag,
            req_type=self.REQ_TYPE_STATUS,
            identity_id=identity_id,
            peer_pubkey=peer_pubkey,
        )
        msg_id = await self._persist_pending_request(
            loaded=loaded, peer_pubkey=peer_pubkey, kind="status", tag=tag
        )
        self._retry_meta[tag] = _RetryMeta(
            kind="status",
            identity_id=identity_id,
            peer_pubkey=peer_pubkey,
            retries_left=self._retries_quota(flood=flood),
            flood=flood,
            msg_id=msg_id,
        )
        self._spawn_request_timeout(
            tag=tag, identity_id=identity_id, peer_pubkey=peer_pubkey, kind="status"
        )
        _log.info(
            "status_req",
            identity=loaded.name,
            peer=peer_pubkey[:4].hex(),
            tag=tag,
        )
        if self.inject is not None:
            await self.inject(pkt, loaded.scope)
        return True

    async def send_link_probe(
        self,
        *,
        identity_id: UUID,
        peer_pubkey: bytes,
    ) -> UUID | None:
        """Schickt eine STATUS-REQ als reine Erreichbarkeits-Probe.

        Anders als ``request_status`` landet das **nicht** als Bubble im
        DM-Verlauf, sondern als Zeile in ``companion_link_probes``. Kein
        Retry — Loss soll messbar sein. Wenn out_path bekannt → DIRECT,
        sonst FLOOD. Liefert die Probe-ID zurück (oder ``None`` wenn die
        Identity nicht existiert).
        """
        from meshcore_bridge.db import CompanionContact, CompanionLinkProbe

        loaded = self._by_id.get(identity_id)
        if loaded is None:
            return None

        # out_path bestimmen (gleiche Logik wie send_dm).
        out_path = b""
        async with self.sessionmaker() as db:
            contact = (
                await db.execute(
                    select(CompanionContact).where(
                        CompanionContact.identity_id == identity_id,
                        CompanionContact.peer_pubkey == peer_pubkey,
                    )
                )
            ).scalar_one_or_none()
            if contact is not None and contact.out_path:
                out_path = contact.out_path

        flood = not out_path
        pkt, tag = loaded.node.make_status_req(peer_pubkey=peer_pubkey, flood=flood)
        # Wenn out_path bekannt: ergibt sich aus Wire kein Pfad-Header in REQ
        # (REQ läuft FLOOD oder DIRECT analog DM); wir tracken hop_count nur
        # zur Info, beeinflusst die Probe selbst nicht.
        hop_count = len(out_path) if out_path else None

        async with self.sessionmaker() as db:
            row = CompanionLinkProbe(
                identity_id=identity_id,
                peer_pubkey=peer_pubkey,
                req_tag=tag,
                route_kind="DIRECT" if not flood else "FLOOD",
                hop_count=hop_count,
                status="pending",
            )
            db.add(row)
            await db.commit()
            await db.refresh(row)
            probe_id = row.id

        self._pending_probes[tag] = (
            time.monotonic(),
            probe_id,
            identity_id,
            peer_pubkey,
        )
        task = asyncio.create_task(
            self._timeout_pending_probe(tag=tag, probe_id=probe_id)
        )
        self._probe_timeout_tasks.add(task)
        task.add_done_callback(self._probe_timeout_tasks.discard)

        _log.info(
            "link_probe_sent",
            identity=loaded.name,
            peer=peer_pubkey[:4].hex(),
            tag=tag,
            route="DIRECT" if not flood else "FLOOD",
            hops=hop_count,
        )
        if self.inject is not None:
            await self.inject(pkt, loaded.scope)
        return probe_id

    async def _timeout_pending_probe(self, *, tag: int, probe_id: UUID) -> None:
        """Wartet ``_PROBE_TIMEOUT_S`` und schreibt 'timeout', wenn bis dahin
        keine RESPONSE eingetroffen ist (ACK-Empfang räumt den Tag aus
        ``_pending_probes`` und macht diesen Task no-op)."""
        from meshcore_bridge.db import CompanionLinkProbe

        await asyncio.sleep(self._PROBE_TIMEOUT_S)
        if self._pending_probes.pop(tag, None) is None:
            return  # RESPONSE kam rechtzeitig
        async with self.sessionmaker() as db:
            row = await db.get(CompanionLinkProbe, probe_id)
            if row is None or row.status != "pending":
                return
            row.status = "timeout"
            await db.commit()
        _log.info("link_probe_timeout", tag=tag, probe_id=str(probe_id))

    async def _record_probe_response(
        self,
        *,
        tag: int,
        pending: tuple[float, UUID, UUID, bytes],
        sender_pubkey: bytes,
    ) -> None:
        """Schreibt das ACK-Ergebnis einer Link-Probe in die DB. Wird vom
        Response-Pfad aufgerufen, wenn der eingehende Tag zu einer
        ausstehenden Probe gehört."""
        from meshcore_bridge.db import CompanionLinkProbe

        sent_mono, probe_id, _identity_id, peer_pubkey = pending
        if sender_pubkey != peer_pubkey:
            # Unerwartet: Tag matcht, Sender nicht. Ignorieren — Tag ist
            # 32 bit random; Kollisionen extrem unwahrscheinlich, aber
            # falls doch, lieber Probe weiter pending lassen als falsch
            # als ACK markieren.
            _log.warning(
                "probe_response_sender_mismatch",
                tag=tag,
                expected=peer_pubkey[:4].hex(),
                got=sender_pubkey[:4].hex(),
            )
            self._pending_probes[tag] = pending  # zurücklegen
            return
        rtt_ms = int((time.monotonic() - sent_mono) * 1000)
        async with self.sessionmaker() as db:
            row = await db.get(CompanionLinkProbe, probe_id)
            if row is None:
                return
            row.status = "ack"
            row.rtt_ms = rtt_ms
            row.answered_at = datetime.now(UTC)
            await db.commit()
        _log.info(
            "link_probe_ack",
            tag=tag,
            probe_id=str(probe_id),
            peer=peer_pubkey[:4].hex(),
            rtt_ms=rtt_ms,
        )

    async def send_dm(
        self,
        *,
        identity_id: UUID,
        peer_pubkey: bytes,
        text: str,
    ) -> bool:
        """Sendet eine DM. Wenn für den Peer ein out_path bekannt ist
        (gelernt aus früherem PATH-Return), wird DIRECT mit diesem Pfad
        geschickt — und bei ausbleibendem ACK in ``_DM_DIRECT_TIMEOUT_S``
        invalidiert. Sonst: FLOOD."""
        from meshcore_bridge.db import CompanionContact

        loaded = self._by_id.get(identity_id)
        if loaded is None:
            return False

        out_path = b""
        async with self.sessionmaker() as db:
            contact = (
                await db.execute(
                    select(CompanionContact).where(
                        CompanionContact.identity_id == identity_id,
                        CompanionContact.peer_pubkey == peer_pubkey,
                    )
                )
            ).scalar_one_or_none()
            if contact is not None and contact.out_path:
                out_path = contact.out_path

        ts = int(time.time())
        text_bytes = text.encode("utf-8")
        pkt = loaded.node.make_dm(
            peer_pubkey=peer_pubkey, text=text, timestamp=ts, path=out_path
        )
        await self._persist_outgoing(loaded, peer_pubkey=peer_pubkey, text=text, raw=pkt.encode())

        if out_path:
            ack_hash = compute_dm_ack_hash(
                timestamp=ts,
                flags=0,
                text_bytes=text_bytes,
                sender_pubkey=loaded.pubkey,
            )
            self._track_pending_dm(
                ack_hash=ack_hash,
                identity_id=identity_id,
                peer_pubkey=peer_pubkey,
            )
            _log.info(
                "dm_send_direct",
                identity=loaded.name,
                peer=peer_pubkey[:4].hex(),
                hops=len(out_path),
                ack=ack_hash.hex(),
            )

        if self.inject is not None:
            await self.inject(pkt, loaded.scope)
        return True

    async def add_channel(
        self,
        *,
        identity_id: UUID,
        name: str,
        password: str,
    ) -> CompanionChannel | None:
        """Legt einen Channel für die Identity an oder gibt den
        existierenden zurück. Secret wird aus
        ``derive_channel_secret(name, password)`` abgeleitet — gleiches
        Schema wie einige MeshCore-Apps; ohne offizielle KDF-Spec.
        """
        from meshcore_bridge.db import CompanionChannel, CompanionIdentity

        secret = derive_channel_secret(name, password)
        chash = hashlib.sha256(secret).digest()[:PATH_HASH_SIZE]
        async with self.sessionmaker() as db:
            ident = await db.get(CompanionIdentity, identity_id)
            if ident is None:
                return None
            existing = (
                await db.execute(
                    select(CompanionChannel).where(
                        CompanionChannel.identity_id == identity_id,
                        CompanionChannel.name == name,
                    )
                )
            ).scalar_one_or_none()
            if existing is not None:
                return existing
            row = CompanionChannel(
                identity_id=identity_id,
                name=name,
                secret=secret,
                channel_hash=chash,
            )
            db.add(row)
            await db.commit()
            await db.refresh(row)
            return row

    async def _ensure_public_channel(self, identity_id: UUID) -> None:
        """Idempotent: legt den MeshCore-Public-Channel an oder migriert
        ein bestehendes ``public`` mit falschem (legacy) Secret auf den
        offiziellen PSK."""
        from meshcore_bridge.db import CompanionChannel

        secret, chash = _public_channel_secret_and_hash()
        try:
            async with self.sessionmaker() as db:
                existing = (
                    await db.execute(
                        select(CompanionChannel).where(
                            CompanionChannel.identity_id == identity_id,
                            CompanionChannel.name == PUBLIC_CHANNEL_NAME,
                        )
                    )
                ).scalar_one_or_none()
                if existing is None:
                    db.add(
                        CompanionChannel(
                            identity_id=identity_id,
                            name=PUBLIC_CHANNEL_NAME,
                            secret=secret,
                            channel_hash=chash,
                        )
                    )
                    await db.commit()
                    return
                if existing.secret != secret or existing.channel_hash != chash:
                    _log.info(
                        "public_channel_secret_migrated",
                        identity_id=str(identity_id),
                    )
                    existing.secret = secret
                    existing.channel_hash = chash
                    await db.commit()
        except Exception:
            _log.exception("ensure_public_channel_failed", identity_id=str(identity_id))

    async def send_channel(
        self,
        *,
        identity_id: UUID,
        channel_id: UUID,
        text: str,
    ) -> bool:
        from meshcore_bridge.db import CompanionChannel, CompanionMessage

        loaded = self._by_id.get(identity_id)
        if loaded is None:
            return False

        async with self.sessionmaker() as db:
            channel = await db.get(CompanionChannel, channel_id)
            if channel is None or channel.identity_id != identity_id:
                return False
            chan_name = channel.name
            chan_secret = channel.secret
            chan_hash = channel.channel_hash

        pkt = loaded.node.make_channel_message(
            channel_secret=chan_secret,
            channel_hash=chan_hash,
            text=text,
            sender_name=loaded.name,
        )
        raw = pkt.encode()

        async with self.sessionmaker() as db:
            new_msg = CompanionMessage(
                identity_id=loaded.id,
                direction="out",
                payload_type=int(PayloadType.GRP_TXT),
                peer_pubkey=None,
                peer_name=None,
                channel_name=chan_name,
                text=text,
                raw=raw,
            )
            db.add(new_msg)
            await db.commit()
            await self._emit(
                loaded.id,
                {
                    "type": "sent_channel",
                    "id": str(new_msg.id),
                    "ts": (new_msg.ts or datetime.now(UTC)).isoformat(),
                    "channel_id": str(channel_id),
                    "channel_name": chan_name,
                    "text": text,
                    "direction": "out",
                },
            )

        if self.inject is not None:
            await self.inject(pkt, loaded.scope)
        return True

    async def on_repeater_connected(self, *, scope: str) -> None:
        """Bridge ruft uns wenn ein Repeater connectet — wir nutzen das um
        sofort einen Advert für jede Identity im selben Scope zu senden.
        """
        matching = [li for li in self._by_id.values() if li.scope == scope]
        _log.info("companion_on_repeater_connected", scope=scope, identities=len(matching))
        for loaded in matching:
            await self._send_advert(loaded)

    _SEEN_RAW_TTL_S = 600.0
    _SEEN_RAW_MAX = 4096

    def _seen_already(self, key: bytes) -> bool:
        """Inbound-Dedup. ``key`` MUSS hop-invariant sein — derselbe
        LoRa-Frame über zwei Repeater hat unterschiedliches ``raw`` (jeder
        Hop schreibt seinen path_hash in den Header), aber identischen
        ``(payload_type, payload)``-Body. Daher nutzen wir den Body als
        Key, nicht das ganze raw."""
        now = time.monotonic()
        if len(self._seen_raw) > self._SEEN_RAW_MAX:
            cutoff = now - self._SEEN_RAW_TTL_S
            self._seen_raw = {k: v for k, v in self._seen_raw.items() if v >= cutoff}
        prev = self._seen_raw.get(key)
        if prev is not None and now - prev < self._SEEN_RAW_TTL_S:
            return True
        self._seen_raw[key] = now
        return False

    def _echo_rate_allow(self, sender_pubkey: bytes, now: float) -> bool:
        """Progressives Per-Sender-Rate-Limit für Echo-Replies.

        Liefert ``True``, wenn der Sender aktuell antworten darf, und
        aktualisiert dabei den Backoff-Zustand. Cooldown verdoppelt sich
        pro aufeinanderfolgender Reply (innerhalb von
        ``_ECHO_RL_STREAK_RESET_S`` seit der letzten), gedeckelt bei
        ``_ECHO_RL_MAX_S``. Nach längerer Pause beginnt die Streak neu.
        """
        state = self._echo_rl.get(sender_pubkey)
        if state is not None and now < state.next_allowed_at:
            return False
        if state is None or (now - state.last_reply_at) >= self._ECHO_RL_STREAK_RESET_S:
            streak = 1
        else:
            streak = state.streak + 1
        cooldown = min(self._ECHO_RL_MAX_S, self._ECHO_RL_BASE_S * (2 ** (streak - 1)))
        self._echo_rl[sender_pubkey] = _EchoRateState(
            next_allowed_at=now + cooldown,
            last_reply_at=now,
            streak=streak,
        )
        if len(self._echo_rl) > self._ECHO_RL_DICT_MAX:
            cutoff = now - self._ECHO_RL_STREAK_RESET_S
            self._echo_rl = {k: v for k, v in self._echo_rl.items() if v.last_reply_at >= cutoff}
        return True

    async def on_inbound_packet(self, *, raw: bytes, scope: str) -> None:
        """Hook, vom Router pro empfangenem Paket gerufen."""
        try:
            pkt = Packet.decode(raw)
        except ValueError:
            return
        # Dedup-Key: payload_type + payload — ohne path_len/path_hashes,
        # die jeder Repeater beim Forward inkrementiert.
        dedup_key = hashlib.sha256(bytes([int(pkt.payload_type)]) + pkt.payload).digest()
        if self._seen_already(dedup_key):
            return
        if pkt.payload_type == PayloadType.ADVERT:
            await self._handle_inbound_advert(pkt=pkt, scope=scope)
        elif pkt.payload_type == PayloadType.TXT_MSG:
            await self._handle_inbound_dm(pkt=pkt, scope=scope, raw=raw)
        elif pkt.payload_type == PayloadType.GRP_TXT:
            await self._handle_inbound_grp_txt(pkt=pkt, scope=scope, raw=raw)
        elif pkt.payload_type == PayloadType.RESPONSE:
            await self._handle_inbound_response(pkt=pkt, scope=scope)
        elif pkt.payload_type == PayloadType.PATH:
            await self._handle_inbound_path(pkt=pkt, scope=scope)
        elif pkt.payload_type == PayloadType.ACK:
            self._handle_inbound_ack(pkt=pkt)

    # ---------- internal ----------

    async def _handle_inbound_advert(self, *, pkt: Packet, scope: str) -> None:
        from meshcore_bridge.db import CompanionContact

        await asyncio.sleep(0)  # cooperative
        for loaded in self._by_id.values():
            if loaded.scope != scope:
                continue
            advert = loaded.node.parse_inbound_advert(pkt)
            if advert is None:
                continue
            if advert.pubkey == loaded.pubkey:
                continue
            parsed = parse_advert_app_data(advert.app_data)
            name = parsed.name
            coord_ok = is_valid_coord(parsed.lat, parsed.lon)
            if (parsed.lat is not None or parsed.lon is not None) and not coord_ok:
                _log.debug(
                    "advert_coord_rejected",
                    peer_pubkey=advert.pubkey.hex(),
                    lat=parsed.lat,
                    lon=parsed.lon,
                )
            async with self.sessionmaker() as db:
                contact = (
                    await db.execute(
                        select(CompanionContact).where(
                            CompanionContact.identity_id == loaded.id,
                            CompanionContact.peer_pubkey == advert.pubkey,
                        )
                    )
                ).scalar_one_or_none()
                if contact is None:
                    contact = CompanionContact(
                        identity_id=loaded.id,
                        peer_pubkey=advert.pubkey,
                        peer_name=name or None,
                        last_seen_at=datetime.now(UTC),
                        last_lat=parsed.lat if coord_ok else None,
                        last_lon=parsed.lon if coord_ok else None,
                        node_type=parsed.adv_type or None,
                    )
                    db.add(contact)
                else:
                    contact.last_seen_at = datetime.now(UTC)
                    if name and contact.peer_name != name:
                        contact.peer_name = name
                    # Koordinaten nur überschreiben, wenn der Advert
                    # plausible Werte mitbringt — sonst letzten
                    # bekannten Wert behalten (Knoten ohne Lat/Lon oder
                    # mit Schrott-Koordinaten).
                    if coord_ok:
                        contact.last_lat = parsed.lat
                        contact.last_lon = parsed.lon
                    if parsed.adv_type:
                        contact.node_type = parsed.adv_type
                await db.commit()
            await self._emit(
                loaded.id,
                {
                    "type": "contact_update",
                    "peer_pubkey_hex": advert.pubkey.hex(),
                    "peer_name": name,
                    "lat": parsed.lat if coord_ok else None,
                    "lon": parsed.lon if coord_ok else None,
                    "node_type": parsed.adv_type or None,
                    "ts": datetime.now(UTC).isoformat(),
                },
            )

    async def _handle_inbound_dm(self, *, pkt: Packet, scope: str, raw: bytes) -> None:
        from meshcore_bridge.db import CompanionContact, CompanionMessage

        for loaded in self._by_id.values():
            if loaded.scope != scope:
                continue
            async with self.sessionmaker() as db:
                contacts = list(
                    (
                        await db.execute(
                            select(CompanionContact).where(
                                CompanionContact.identity_id == loaded.id
                            )
                        )
                    ).scalars()
                )
            # Room-Pushes haben das gleiche äußere Wire-Layout wie eine DM,
            # nutzen aber TXT_TYPE_SIGNED_PLAIN und tragen einen 4-Byte-
            # author-prefix im Plaintext. try_decrypt_dm würde sie wegen
            # txt_type-Mismatch verwerfen, daher zuerst den Room-Decode mit
            # genau den Room-Contacts probieren (sonst kein No-Op).
            rooms = [c for c in contacts if c.node_type == ADV_TYPE_ROOM]
            room_post: IncomingRoomPost | None = None
            if rooms:
                room_post = loaded.node.try_decrypt_room_push(
                    packet=pkt,
                    room_candidates=[Identity(c.peer_pubkey) for c in rooms],
                )
            if room_post is not None:
                await self._handle_room_push(
                    loaded=loaded,
                    pkt=pkt,
                    raw=raw,
                    room_post=room_post,
                    contacts=contacts,
                    scope=scope,
                )
                return
            cands = [Identity(c.peer_pubkey) for c in contacts]
            decoded: IncomingTextMessage | None = loaded.node.try_decrypt_dm(
                packet=pkt, peer_candidates=cands
            )
            if decoded is None:
                continue
            peer_name = next(
                (c.peer_name for c in contacts if c.peer_pubkey == decoded.sender_pubkey),
                None,
            )
            # ts vom Sender persistieren (firmware setzt seine RTC). Zwei Retries
            # mit gleichem ts + peer + identity → de-duped via DB-Lookup.
            msg_ts = datetime.fromtimestamp(decoded.timestamp, UTC)
            text_bytes = decoded.text.encode("utf-8")
            async with self.sessionmaker() as db:
                existing = (
                    await db.execute(
                        select(CompanionMessage.id).where(
                            CompanionMessage.identity_id == loaded.id,
                            CompanionMessage.peer_pubkey == decoded.sender_pubkey,
                            CompanionMessage.payload_type == int(PayloadType.TXT_MSG),
                            CompanionMessage.ts == msg_ts,
                        )
                    )
                ).scalar_one_or_none()
                if existing is None:
                    new_msg = CompanionMessage(
                        identity_id=loaded.id,
                        direction="in",
                        payload_type=int(PayloadType.TXT_MSG),
                        peer_pubkey=decoded.sender_pubkey,
                        peer_name=peer_name,
                        text=decoded.text,
                        raw=raw,
                        ts=msg_ts,
                    )
                    db.add(new_msg)
                    await db.commit()
                    await self._emit(
                        loaded.id,
                        {
                            "type": "dm",
                            "id": str(new_msg.id),
                            "ts": msg_ts.isoformat(),
                            "peer_pubkey_hex": decoded.sender_pubkey.hex(),
                            "peer_name": peer_name,
                            "text": decoded.text,
                            "direction": "in",
                            "hops": pkt.hop_count,
                        },
                    )
                else:
                    _log.info(
                        "dm_retry_dedup",
                        peer=decoded.sender_pubkey[:4].hex(),
                        ts=decoded.timestamp,
                    )

            # ACK senden — bei FLOOD-RX zusätzlich PATH-Return (lernt
            # Out-Path) gemäß firmware BaseChatMesh.cpp:217-231:
            #   FLOOD  → createPathReturn(... ACK + ack_hash) per FLOOD
            #   DIRECT → sendAckTo() — separater ACK-Frame (FLOOD-Fallback,
            #            wenn out_path unbekannt; bei uns immer der Fall,
            #            weil wir Senders out_path nicht tracken).
            # Wir senden in beiden Fällen den separaten ACK-Frame —
            # firmware tut das bei DIRECT-RX explizit und manche Mobile-
            # Apps werten den im PATH eingebetteten ACK nicht zuverlässig
            # aus, der unverschlüsselte ACK-Frame greift dafür sicher.
            if self.inject is not None:
                ack_hash = compute_dm_ack_hash(
                    timestamp=decoded.timestamp,
                    flags=decoded.flags,
                    text_bytes=text_bytes,
                    sender_pubkey=decoded.sender_pubkey,
                )
                try:
                    if pkt.route_type == RouteType.FLOOD:
                        path_pkt = loaded.node.make_path_return(
                            peer_pubkey=decoded.sender_pubkey,
                            rx_path_len_byte=pkt.path_len_byte,
                            rx_path_bytes=pkt.path,
                            extra_type=int(PayloadType.ACK),
                            extra_data=ack_hash,
                        )
                        await self.inject(path_pkt, scope)
                    ack_pkt = loaded.node.make_ack(ack_hash)
                    await self.inject(ack_pkt, scope)
                    _log.info(
                        "dm_ack_sent",
                        peer=decoded.sender_pubkey[:4].hex(),
                        ts=decoded.timestamp,
                        flags=decoded.flags,
                        text_len=len(text_bytes),
                        ack=ack_hash.hex(),
                        route=pkt.route_type.name,
                        rx_hops=pkt.hop_count,
                    )
                except Exception:
                    _log.exception("dm_ack_send_failed")
            sender_loaded = self._by_pubkey.get(decoded.sender_pubkey)
            sender_is_echo = sender_loaded is not None and sender_loaded.is_echo
            if (
                loaded.is_echo
                and existing is None
                and not sender_is_echo
                and self._echo_rate_allow(decoded.sender_pubkey, time.monotonic())
            ):
                try:
                    age = int(time.time()) - decoded.timestamp
                    age_str = f"{age}s" if age >= 0 else "?"
                    route = pkt.route_type.name
                    hops = pkt.hop_count
                    text_len = len(text_bytes)
                    suffix = f" — hops={hops} route={route} age={age_str} len={text_len}b"
                    prefix = 'echo: "'
                    # 140-Byte-Reserve unter dem TXT_MSG-Plaintext-Limit (~229 Byte).
                    budget = 140 - len(prefix.encode()) - len(b'"') - len(suffix.encode())
                    encoded = decoded.text.encode("utf-8")
                    if len(encoded) <= max(0, budget):
                        body = decoded.text
                    else:
                        # 3 Byte für '…' reservieren, damit Total ≤ 140 bleibt.
                        body = encoded[: max(0, budget - 3)].decode("utf-8", errors="ignore") + "…"
                    reply = f'{prefix}{body}"{suffix}'
                    await self.send_dm(
                        identity_id=loaded.id,
                        peer_pubkey=decoded.sender_pubkey,
                        text=reply,
                    )
                    _log.info(
                        "echo_bot_reply_sent",
                        identity=loaded.name,
                        peer=decoded.sender_pubkey[:4].hex(),
                        hops=hops,
                        route=route,
                        age_s=age,
                        orig_len=text_len,
                        reply_len=len(reply.encode("utf-8")),
                    )
                except Exception:
                    _log.exception("echo_bot_reply_failed", identity=loaded.name)
            return  # erste Identity, die's lesen kann, gewinnt

    async def _handle_room_push(
        self,
        *,
        loaded: LoadedIdentity,
        pkt: Packet,
        raw: bytes,
        room_post: IncomingRoomPost,
        contacts: list[CompanionContact],
        scope: str,
    ) -> None:
        """Persistiere einen Room-Server-Push und ACKe ihn.

        Der äußere Sender im Wire ist der Room-Server (``room_pubkey``);
        der eigentliche Autor des Posts kommt nur als 4-Byte-Prefix im
        Plaintext. Wir versuchen, den Autor anhand der existierenden
        Contact-Liste der Identity aufzulösen — bei mehreren Match-
        Kandidaten (Prefix-Kollision) den mit dem jüngsten ``last_seen_at``.
        Kein Treffer → ``author_name=None`` (Frontend zeigt dann den
        Hex-Prefix).
        """
        from meshcore_bridge.db import CompanionMessage

        room_contact = next((c for c in contacts if c.peer_pubkey == room_post.room_pubkey), None)
        room_name = room_contact.peer_name if room_contact else None

        author_candidates = [c for c in contacts if c.peer_pubkey[:4] == room_post.author_prefix]
        author_contact = None
        if author_candidates:
            author_contact = max(
                author_candidates,
                key=lambda c: c.last_seen_at or datetime.min.replace(tzinfo=UTC),
            )
        author_name = author_contact.peer_name if author_contact else None

        msg_ts = datetime.fromtimestamp(room_post.timestamp, UTC)
        async with self.sessionmaker() as db:
            existing = (
                await db.execute(
                    select(CompanionMessage.id).where(
                        CompanionMessage.identity_id == loaded.id,
                        CompanionMessage.peer_pubkey == room_post.room_pubkey,
                        CompanionMessage.payload_type == int(PayloadType.TXT_MSG),
                        CompanionMessage.ts == msg_ts,
                        CompanionMessage.room_sender_pubkey == room_post.author_prefix,
                    )
                )
            ).scalar_one_or_none()
            if existing is None:
                new_msg = CompanionMessage(
                    identity_id=loaded.id,
                    direction="in",
                    payload_type=int(PayloadType.TXT_MSG),
                    peer_pubkey=room_post.room_pubkey,
                    peer_name=room_name,
                    text=room_post.text,
                    raw=raw,
                    ts=msg_ts,
                    room_sender_pubkey=room_post.author_prefix,
                )
                db.add(new_msg)
                await db.commit()
                await self._emit(
                    loaded.id,
                    {
                        "type": "room_post",
                        "id": str(new_msg.id),
                        "ts": msg_ts.isoformat(),
                        "peer_pubkey_hex": room_post.room_pubkey.hex(),
                        "peer_name": room_name,
                        "room_sender_prefix_hex": room_post.author_prefix.hex(),
                        "room_sender_name": author_name,
                        "text": room_post.text,
                        "direction": "in",
                        "hops": pkt.hop_count,
                    },
                )
            else:
                _log.info(
                    "room_post_retry_dedup",
                    room=room_post.room_pubkey[:4].hex(),
                    author=room_post.author_prefix.hex(),
                    ts=room_post.timestamp,
                )

        # ACK über den vollen Plaintext + eigener (Empfänger-)Pubkey;
        # PATH-Return bei FLOOD-RX analog zum DM-Branch.
        if self.inject is not None:
            ack_hash = compute_room_ack_hash(
                full_plain=room_post.full_plain,
                receiver_pubkey=loaded.pubkey,
            )
            try:
                if pkt.route_type == RouteType.FLOOD:
                    path_pkt = loaded.node.make_path_return(
                        peer_pubkey=room_post.room_pubkey,
                        rx_path_len_byte=pkt.path_len_byte,
                        rx_path_bytes=pkt.path,
                        extra_type=int(PayloadType.ACK),
                        extra_data=ack_hash,
                    )
                    await self.inject(path_pkt, scope)
                ack_pkt = loaded.node.make_ack(ack_hash)
                await self.inject(ack_pkt, scope)
                _log.info(
                    "room_ack_sent",
                    room=room_post.room_pubkey[:4].hex(),
                    author=room_post.author_prefix.hex(),
                    ts=room_post.timestamp,
                    flags=room_post.flags,
                    text_len=len(room_post.text.encode("utf-8")),
                    ack=ack_hash.hex(),
                    route=pkt.route_type.name,
                    rx_hops=pkt.hop_count,
                )
            except Exception:
                _log.exception("room_ack_send_failed")

    async def _handle_inbound_grp_txt(self, *, pkt: Packet, scope: str, raw: bytes) -> None:
        from meshcore_bridge.db import CompanionChannel, CompanionMessage

        in_scope = [li for li in self._by_id.values() if li.scope == scope]
        if not in_scope:
            return
        own_ids = [li.id for li in in_scope]
        async with self.sessionmaker() as db:
            channels = list(
                (
                    await db.execute(
                        select(CompanionChannel).where(CompanionChannel.identity_id.in_(own_ids))
                    )
                ).scalars()
            )
        if not channels:
            return
        pairs = [(ch.channel_hash, ch.secret) for ch in channels]
        decoded: IncomingChannelMessage | None = try_decrypt_grp_txt(packet=pkt, channels=pairs)
        if decoded is None:
            return
        target = next((ch for ch in channels if ch.secret == decoded.channel_secret), None)
        if target is None:
            return
        loaded = self._by_id.get(target.identity_id)
        if loaded is None:
            return
        # Eigene Outbox-Echos best-effort filtern: gleiche Identity, gleicher
        # sender_name. Channels haben keine kryptographische Sender-Auth.
        if decoded.sender_name and decoded.sender_name == loaded.name:
            return
        ts = datetime.fromtimestamp(decoded.timestamp, UTC)
        async with self.sessionmaker() as db:
            new_msg = CompanionMessage(
                identity_id=target.identity_id,
                direction="in",
                payload_type=int(PayloadType.GRP_TXT),
                peer_pubkey=None,
                peer_name=decoded.sender_name or None,
                channel_name=target.name,
                text=decoded.text,
                raw=raw,
                ts=ts,
            )
            db.add(new_msg)
            await db.commit()
            await self._emit(
                target.identity_id,
                {
                    "type": "channel",
                    "id": str(new_msg.id),
                    "ts": ts.isoformat(),
                    "channel_id": str(target.id),
                    "channel_name": target.name,
                    "peer_name": decoded.sender_name or None,
                    "text": decoded.text,
                    "direction": "in",
                    "hops": pkt.hop_count,
                },
            )

    async def _handle_inbound_response(self, *, pkt: Packet, scope: str) -> None:
        """RESPONSE auf einen unserer REQs (DIRECT-Variante)."""
        from meshcore_bridge.db import CompanionContact

        for loaded in self._by_id.values():
            if loaded.scope != scope:
                continue
            async with self.sessionmaker() as db:
                contacts = list(
                    (
                        await db.execute(
                            select(CompanionContact).where(
                                CompanionContact.identity_id == loaded.id
                            )
                        )
                    ).scalars()
                )
            cands = [Identity(c.peer_pubkey) for c in contacts]
            decoded: IncomingResponse | None = loaded.node.try_decrypt_response(
                packet=pkt, peer_candidates=cands
            )
            if decoded is None:
                continue
            await self._process_response_payload(
                loaded=loaded,
                sender_pubkey=decoded.sender_pubkey,
                tag=decoded.tag,
                reply_data=decoded.reply_data,
                contacts=contacts,
            )
            return

    def _handle_inbound_ack(self, *, pkt: Packet) -> None:
        """ACK-Frame (4 Byte unverschlüsselter ack_hash). Wenn er zu einer
        unserer pending DIRECT-DMs passt → Pending-Eintrag entfernen, was
        den Timeout-Task no-op werden lässt (out_path bleibt erhalten)."""
        if len(pkt.payload) != _ACK_HASH_LEN:
            return
        ack_hash = bytes(pkt.payload)
        entry = self._pending_dms.pop(ack_hash, None)
        if entry is None:
            return
        sent_mono, _, peer_pubkey = entry
        rtt_ms = int((time.monotonic() - sent_mono) * 1000)
        _log.info(
            "dm_ack_recv",
            peer=peer_pubkey[:4].hex(),
            ack=ack_hash.hex(),
            rtt_ms=rtt_ms,
        )

    async def _handle_inbound_path(self, *, pkt: Packet, scope: str) -> None:
        """PATH-Wrapper auf einen FLOOD-REQ (insb. ANON_REQ-Login).
        Repeater verpackt die RESPONSE in PATH, damit der Sender
        gleichzeitig den out_path lernt. Wir extrahieren das eingebettete
        ``extra``-Payload und routen es analog zur RESPONSE.
        """
        from meshcore_bridge.db import CompanionContact

        for loaded in self._by_id.values():
            if loaded.scope != scope:
                continue
            async with self.sessionmaker() as db:
                contacts = list(
                    (
                        await db.execute(
                            select(CompanionContact).where(
                                CompanionContact.identity_id == loaded.id
                            )
                        )
                    ).scalars()
                )
            cands = [Identity(c.peer_pubkey) for c in contacts]
            decoded = loaded.node.try_decrypt_path(packet=pkt, peer_candidates=cands)
            if decoded is None:
                continue
            peer, path_bytes, extra_type, extra = decoded
            _log.info(
                "path_recv",
                identity=loaded.name,
                peer=peer.pub_key[:4].hex(),
                path_hops=len(path_bytes),
                extra_type=extra_type,
                extra_len=len(extra),
            )
            # Out-Path lernen — der vom Peer in den PATH-Return gepackte
            # path_bytes ist firmware-konvention 1:1 unser Out-Path zum
            # Peer (Mesh.cpp:434, BaseChatMesh.cpp:217-231). Persistieren
            # wir, damit zukünftige DMs an den Peer als DIRECT laufen.
            if path_bytes:
                await self._persist_out_path(
                    identity_id=loaded.id,
                    peer_pubkey=peer.pub_key,
                    path_bytes=path_bytes,
                )
            # Embedded ACK (DM-Delivery-Confirmation) → wie ACK-Frame
            # behandeln, damit der Pending-DM-Timeout aufhört zu laufen
            # (verhindert unnötige out_path-Invalidation, falls der
            # separate ACK-Frame nicht ankommt, der PATH-Return aber schon).
            if extra_type == int(PayloadType.ACK) and len(extra) == _ACK_HASH_LEN:
                self._handle_inbound_ack(
                    pkt=Packet(payload_type=PayloadType.ACK, payload=bytes(extra))
                )
                return
            # Nur eingebettete RESPONSE interessiert uns (REQ/Login-Reply).
            # extra = [tag:4 LE] [reply_data...]
            if extra_type != int(PayloadType.RESPONSE) or len(extra) < _TAG_BYTES:
                return
            tag = int.from_bytes(extra[:_TAG_BYTES], "little", signed=False)
            reply_data = extra[_TAG_BYTES:]
            await self._process_response_payload(
                loaded=loaded,
                sender_pubkey=peer.pub_key,
                tag=tag,
                reply_data=reply_data,
                contacts=contacts,
            )
            return

    async def _persist_out_path(
        self,
        *,
        identity_id: UUID,
        peer_pubkey: bytes,
        path_bytes: bytes,
    ) -> None:
        """Speichert den gelernten Out-Path im Contact. No-op, wenn der
        Peer (noch) nicht in den Contacts ist oder der Path identisch zum
        bereits gespeicherten ist (vermeidet leeren UPDATE)."""
        from meshcore_bridge.db import CompanionContact

        async with self.sessionmaker() as db:
            contact = (
                await db.execute(
                    select(CompanionContact).where(
                        CompanionContact.identity_id == identity_id,
                        CompanionContact.peer_pubkey == peer_pubkey,
                    )
                )
            ).scalar_one_or_none()
            if contact is None:
                return
            if contact.out_path == path_bytes:
                return
            contact.out_path = path_bytes
            contact.out_path_updated_at = datetime.now(UTC)
            await db.commit()
        _log.info(
            "out_path_learned",
            identity_id=str(identity_id),
            peer=peer_pubkey[:4].hex(),
            hops=len(path_bytes),
        )

    async def _process_response_payload(
        self,
        *,
        loaded: LoadedIdentity,
        sender_pubkey: bytes,
        tag: int,
        reply_data: bytes,
        contacts: list[CompanionContact],
    ) -> None:
        """Persistiert eine eingegangene Reply (egal ob RESPONSE oder PATH-
        embedded) als System-Message und pusht ein SSE-Event.

        Verzweigung nach pending REQ-Typ:
          * LOGIN     → RESP_SERVER_LOGIN_OK + permissions
          * STATUS    → RepeaterStats
          * TELEMETRY → LPP-Buffer (LPP_GPS optional)
          * unbekannt → Telemetrie-Fallback (Legacy).
        """
        from meshcore_bridge.db import CompanionContact, CompanionMessage

        # Probe-Pfad zuerst: STATUS-REQs aus ``send_link_probe`` haben einen
        # eigenen Tracker und sollen NICHT als CompanionMessage-Bubble
        # persistiert werden. Wenn der Tag dort liegt → Probe-Eintrag
        # updaten und früh raus.
        probe_pending = self._pending_probes.pop(tag, None)
        if probe_pending is not None:
            await self._record_probe_response(
                tag=tag, pending=probe_pending, sender_pubkey=sender_pubkey
            )
            return

        pending = self._pending_reqs.pop(tag, None)
        # Erfolgreicher Receive → Retry-Meta verwerfen, sonst feuert ein
        # nachlaufender Timeout-Task einen unnötigen Resend.
        self._retry_meta.pop(tag, None)
        now_mono = time.monotonic()
        rtt_ms = int((now_mono - pending[0]) * 1000) if pending else None
        req_type = pending[1] if pending else self.REQ_TYPE_TELEMETRY
        now_ts = datetime.now(UTC)
        peer_name = next(
            (c.peer_name for c in contacts if c.peer_pubkey == sender_pubkey),
            None,
        )

        async with self.sessionmaker() as db:
            contact = (
                await db.execute(
                    select(CompanionContact).where(
                        CompanionContact.identity_id == loaded.id,
                        CompanionContact.peer_pubkey == sender_pubkey,
                    )
                )
            ).scalar_one_or_none()
            if contact is not None:
                contact.last_seen_at = now_ts

            text: str | None = None
            event_type: str = "system"
            event_extra: dict[str, object] = {}

            if req_type == self.REQ_TYPE_LOGIN:
                login = parse_login_response(reply_data)
                if login is None:
                    _log.info(
                        "login_response_unparsable",
                        peer=sender_pubkey[:4].hex(),
                        tag=tag,
                        reply_len=len(reply_data),
                    )
                    return
                rtt_part = f"{rtt_ms} ms" if rtt_ms is not None else "?"
                role = "admin" if login.is_admin else "guest"
                text = (
                    f"🔑 Login OK · RTT {rtt_part} · "
                    f"Rolle {role} · Permissions 0x{login.permissions:02x}"
                )
                # Session merken — TTL ist eine Heuristik, Server-Server-
                # seitige Ablaufzeit kennen wir nicht zuverlässig.
                session = LoginSession(
                    expires_at=time.monotonic() + _LOGIN_SESSION_TTL_S,
                    is_admin=login.is_admin,
                    permissions=login.permissions,
                )
                self._login_sessions[(loaded.id, sender_pubkey)] = session
                expires_iso = (
                    datetime.now(UTC) + timedelta(seconds=_LOGIN_SESSION_TTL_S)
                ).isoformat()
                event_type = "login_response"
                event_extra = {
                    "rtt_ms": rtt_ms,
                    "is_admin": login.is_admin,
                    "permissions": login.permissions,
                    "logged_in_until": expires_iso,
                }

            elif req_type == self.REQ_TYPE_STATUS:
                stats = parse_repeater_stats(reply_data)
                if stats is None:
                    _log.info(
                        "status_response_unparsable",
                        peer=sender_pubkey[:4].hex(),
                        tag=tag,
                        reply_len=len(reply_data),
                    )
                    return
                rtt_part = f"{rtt_ms} ms" if rtt_ms is not None else "?"
                up_h = stats.total_up_time_secs / 3600.0
                text = (
                    f"ℹ Status · RTT {rtt_part} · "
                    f"Uptime {up_h:.1f} h · "
                    f"Batt {stats.battery_volts:.2f} V · "
                    f"SNR {stats.snr_db:.1f} dB · RSSI {stats.last_rssi} · "
                    f"RX {stats.n_packets_recv}/TX {stats.n_packets_sent}"
                )
                event_type = "status_response"
                event_extra = {
                    "rtt_ms": rtt_ms,
                    "stats": {
                        "battery_volts": stats.battery_volts,
                        "snr_db": stats.snr_db,
                        "last_rssi": stats.last_rssi,
                        "uptime_s": stats.total_up_time_secs,
                        "n_packets_recv": stats.n_packets_recv,
                        "n_packets_sent": stats.n_packets_sent,
                        "tx_queue_len": stats.curr_tx_queue_len,
                    },
                }

            elif req_type == self.REQ_TYPE_TELEMETRY:
                gps = parse_lpp_gps(reply_data)
                parts: list[str] = []
                if rtt_ms is not None:
                    parts.append(f"RTT {rtt_ms} ms")
                if gps is not None and is_valid_coord(gps.lat, gps.lon):
                    if contact is not None:
                        contact.last_lat = gps.lat
                        contact.last_lon = gps.lon
                    parts.append(f"GPS {gps.lat:.4f}, {gps.lon:.4f}")
                else:
                    parts.append("kein GPS")
                text = "📡 Telemetrie · " + " · ".join(parts)
                event_type = "telemetry_response"
                _gps_ok = gps is not None and is_valid_coord(gps.lat, gps.lon)
                event_extra = {
                    "rtt_ms": rtt_ms,
                    "lat": gps.lat if _gps_ok and gps is not None else None,
                    "lon": gps.lon if _gps_ok and gps is not None else None,
                }

            if text is None:
                await db.commit()
                return

            sys_msg = CompanionMessage(
                identity_id=loaded.id,
                direction="system",
                payload_type=int(PayloadType.RESPONSE),
                peer_pubkey=sender_pubkey,
                peer_name=peer_name,
                text=text,
                raw=b"",
                ts=now_ts,
            )
            db.add(sys_msg)
            await db.commit()

            emit_payload: dict[str, object] = {
                "type": event_type,
                "id": str(sys_msg.id),
                "ts": now_ts.isoformat(),
                "peer_pubkey_hex": sender_pubkey.hex(),
                "peer_name": peer_name,
                "text": text,
                "direction": "system",
            }
            emit_payload.update(event_extra)
            await self._emit(loaded.id, emit_payload)

        _log.info(
            "response_handled",
            identity=loaded.name,
            peer=sender_pubkey[:4].hex(),
            tag=tag,
            req_type=req_type,
            rtt_ms=rtt_ms,
        )

    async def _persist_outgoing(
        self,
        loaded: LoadedIdentity,
        *,
        peer_pubkey: bytes,
        text: str,
        raw: bytes,
    ) -> None:
        from meshcore_bridge.db import CompanionContact, CompanionMessage

        async with self.sessionmaker() as db:
            contact = (
                await db.execute(
                    select(CompanionContact).where(
                        CompanionContact.identity_id == loaded.id,
                        CompanionContact.peer_pubkey == peer_pubkey,
                    )
                )
            ).scalar_one_or_none()
            new_msg = CompanionMessage(
                identity_id=loaded.id,
                direction="out",
                payload_type=int(PayloadType.TXT_MSG),
                peer_pubkey=peer_pubkey,
                peer_name=contact.peer_name if contact else None,
                text=text,
                raw=raw,
            )
            db.add(new_msg)
            await db.commit()
            await self._emit(
                loaded.id,
                {
                    "type": "sent_dm",
                    "id": str(new_msg.id),
                    "ts": (new_msg.ts or datetime.now(UTC)).isoformat(),
                    "peer_pubkey_hex": peer_pubkey.hex(),
                    "peer_name": contact.peer_name if contact else None,
                    "text": text,
                    "direction": "out",
                },
            )

    async def _advert_loop(self) -> None:
        try:
            # Beim Start jeder Identity ein Initial-Advert
            for loaded in list(self._by_id.values()):
                await self._send_advert(loaded)
            while not self._stop.is_set():
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self.advert_interval_s)
                except TimeoutError:
                    pass
                if self._stop.is_set():
                    break
                for loaded in list(self._by_id.values()):
                    await self._send_advert(loaded)
        except asyncio.CancelledError:
            return

    async def _send_advert(self, loaded: LoadedIdentity) -> None:
        if self.inject is None:
            _log.warning("send_advert_no_inject", identity=loaded.name)
            return
        # MeshCore-Advert-Format: flags(1) [lat lon]? name…
        app_data = encode_advert_app_data(name=loaded.name[:32], adv_type=ADV_TYPE_CHAT)
        pkt = loaded.node.make_advert(
            timestamp=int(time.time()),
            app_data=app_data,
        )
        raw = pkt.encode()
        _log.info(
            "send_advert",
            identity=loaded.name,
            scope=loaded.scope,
            pubkey_prefix=loaded.pubkey[:4].hex(),
            raw_bytes=len(raw),
        )
        try:
            await self.inject(pkt, loaded.scope)
        except Exception:
            _log.exception("send_advert_inject_failed", identity=loaded.name)
