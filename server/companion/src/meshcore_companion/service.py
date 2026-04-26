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
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from meshcore_companion.crypto import (
    PATH_HASH_SIZE,
    Identity,
    LocalIdentity,
    derive_channel_secret,
)
from meshcore_companion.node import (
    ADV_TYPE_CHAT,
    CompanionNode,
    IncomingChannelMessage,
    IncomingResponse,
    IncomingTextMessage,
    compute_dm_ack_hash,
    encode_advert_app_data,
    parse_advert_app_data,
    parse_lpp_gps,
    try_decrypt_grp_txt,
)
from meshcore_companion.packet import Packet, PayloadType, RouteType
from meshcore_companion.storage import decrypt_seed, encrypt_seed

if TYPE_CHECKING:
    from meshcore_bridge.db import CompanionChannel

_log = structlog.get_logger("companion")

PacketInjector = Callable[[Packet, str], Awaitable[None]]
"""Callable(packet, scope) — fügt ein Paket in den Mesh-Scope ein."""

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

    @property
    def pubkey(self) -> bytes:
        return self.node.pub_key


@dataclass
class CompanionService:
    master_key: bytes
    sessionmaker: Callable[[], AsyncSession]
    inject: PacketInjector | None = None
    advert_interval_s: int = 3600

    _by_id: dict[UUID, LoadedIdentity] = field(default_factory=dict)
    _by_pubkey: dict[bytes, LoadedIdentity] = field(default_factory=dict)
    _advert_task: asyncio.Task[None] | None = None
    _stop: asyncio.Event = field(default_factory=asyncio.Event)
    # Inbound-Dedup: gleiches raw-Paket kommt pro verbundenem Repeater einmal
    # rein. Ohne dedup persistieren wir GRP_TXT/TXT_MSG mehrfach.
    _seen_raw: dict[bytes, float] = field(default_factory=dict)

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
            )
            db.add(row)
            await db.flush()
            row.privkey_enc = encrypt_seed(self.master_key, row.id, local.seed)
            await db.commit()
            row_id = row.id

        loaded = LoadedIdentity(
            id=row_id, user_id=user_id, name=name, scope=scope, node=CompanionNode(local)
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

    async def delete_channel(self, channel_id: UUID) -> bool:
        from meshcore_bridge.db import CompanionChannel

        async with self.sessionmaker() as db:
            row = await db.get(CompanionChannel, channel_id)
            if row is None:
                return False
            await db.delete(row)
            await db.commit()
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
        aktualisieren).
        """
        loaded = self._by_id.get(identity_id)
        if loaded is None:
            return False
        pkt, tag = loaded.node.make_telemetry_req(peer_pubkey=peer_pubkey)
        _log.info(
            "telemetry_req",
            identity=loaded.name,
            peer=peer_pubkey[:4].hex(),
            tag=tag,
        )
        if self.inject is not None:
            await self.inject(pkt, loaded.scope)
        return True

    async def send_dm(
        self,
        *,
        identity_id: UUID,
        peer_pubkey: bytes,
        text: str,
    ) -> bool:
        loaded = self._by_id.get(identity_id)
        if loaded is None:
            return False
        pkt = loaded.node.make_dm(peer_pubkey=peer_pubkey, text=text)
        await self._persist_outgoing(loaded, peer_pubkey=peer_pubkey, text=text, raw=pkt.encode())
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
            db.add(
                CompanionMessage(
                    identity_id=loaded.id,
                    direction="out",
                    payload_type=int(PayloadType.GRP_TXT),
                    peer_pubkey=None,
                    peer_name=None,
                    channel_name=chan_name,
                    text=text,
                    raw=raw,
                )
            )
            await db.commit()

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
            self._seen_raw = {
                k: v for k, v in self._seen_raw.items() if v >= cutoff
            }
        prev = self._seen_raw.get(key)
        if prev is not None and now - prev < self._SEEN_RAW_TTL_S:
            return True
        self._seen_raw[key] = now
        return False

    async def on_inbound_packet(self, *, raw: bytes, scope: str) -> None:
        """Hook, vom Router pro empfangenem Paket gerufen."""
        try:
            pkt = Packet.decode(raw)
        except ValueError:
            return
        # Dedup-Key: payload_type + payload — ohne path_len/path_hashes,
        # die jeder Repeater beim Forward inkrementiert.
        dedup_key = hashlib.sha256(
            bytes([int(pkt.payload_type)]) + pkt.payload
        ).digest()
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
                        last_lat=parsed.lat,
                        last_lon=parsed.lon,
                    )
                    db.add(contact)
                else:
                    contact.last_seen_at = datetime.now(UTC)
                    if name and contact.peer_name != name:
                        contact.peer_name = name
                    # Koordinaten nur überschreiben, wenn der Advert welche
                    # mitbringt (Knoten könnten ohne Lat/Lon adverten —
                    # dann letzten bekannten Wert behalten).
                    if parsed.lat is not None and parsed.lon is not None:
                        contact.last_lat = parsed.lat
                        contact.last_lon = parsed.lon
                await db.commit()

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
                    db.add(
                        CompanionMessage(
                            identity_id=loaded.id,
                            direction="in",
                            payload_type=int(PayloadType.TXT_MSG),
                            peer_pubkey=decoded.sender_pubkey,
                            peer_name=peer_name,
                            text=decoded.text,
                            raw=raw,
                            ts=msg_ts,
                        )
                    )
                    await db.commit()
                else:
                    _log.info(
                        "dm_retry_dedup",
                        peer=decoded.sender_pubkey[:4].hex(),
                        ts=decoded.timestamp,
                    )

            # ACK + PATH-Return: der Sender lernt damit die Out-Path zu uns
            # und markiert die DM in seiner UI als 'delivered'. Pflicht bei
            # FLOOD-RX laut firmware BaseChatMesh.cpp:224.
            if pkt.route_type == RouteType.FLOOD and self.inject is not None:
                # firmware-Konvention: ACK-Hash = sha256(plaintext || sender_pubkey).
                # ``sender`` ist HIER der Absender der DM (Octavia), nicht wir.
                ack_hash = compute_dm_ack_hash(
                    timestamp=decoded.timestamp,
                    flags=decoded.flags,
                    text_bytes=text_bytes,
                    sender_pubkey=decoded.sender_pubkey,
                )
                try:
                    path_pkt = loaded.node.make_path_return(
                        peer_pubkey=decoded.sender_pubkey,
                        rx_path_len_byte=pkt.path_len_byte,
                        rx_path_bytes=pkt.path,
                        extra_type=int(PayloadType.ACK),
                        extra_data=ack_hash,
                    )
                    await self.inject(path_pkt, scope)
                    _log.info(
                        "dm_ack_sent",
                        peer=decoded.sender_pubkey[:4].hex(),
                        ts=decoded.timestamp,
                        ack=ack_hash.hex(),
                        rx_hops=pkt.hop_count,
                    )
                except Exception:
                    _log.exception("dm_ack_send_failed")
            return  # erste Identity, die's lesen kann, gewinnt

    async def _handle_inbound_grp_txt(
        self, *, pkt: Packet, scope: str, raw: bytes
    ) -> None:
        from meshcore_bridge.db import CompanionChannel, CompanionMessage

        in_scope = [li for li in self._by_id.values() if li.scope == scope]
        if not in_scope:
            return
        own_ids = [li.id for li in in_scope]
        async with self.sessionmaker() as db:
            channels = list(
                (
                    await db.execute(
                        select(CompanionChannel).where(
                            CompanionChannel.identity_id.in_(own_ids)
                        )
                    )
                ).scalars()
            )
        if not channels:
            return
        pairs = [(ch.channel_hash, ch.secret) for ch in channels]
        decoded: IncomingChannelMessage | None = try_decrypt_grp_txt(
            packet=pkt, channels=pairs
        )
        if decoded is None:
            return
        target = next(
            (ch for ch in channels if ch.secret == decoded.channel_secret), None
        )
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
            db.add(
                CompanionMessage(
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
            )
            await db.commit()

    async def _handle_inbound_response(self, *, pkt: Packet, scope: str) -> None:
        """RESPONSE auf einen unserer REQs. Wir kennen den Sender nicht
        per src_hash eindeutig, daher iterieren wir über alle Identities
        im scope und ihre bekannten Contacts. Erste erfolgreiche
        Dekryption gewinnt; bei Telemetrie mit LPP_GPS → lat/lon
        persistieren.
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
            decoded: IncomingResponse | None = loaded.node.try_decrypt_response(
                packet=pkt, peer_candidates=cands
            )
            if decoded is None:
                continue
            # firmware MyMesh.cpp:212 + 264: reply_data wird komplett als
            # plaintext verschlüsselt; reply_data[0..3] = sender_timestamp
            # (= unser tag-Echo, schon als ``decoded.tag`` extrahiert),
            # reply_data[4..] = LPP-Telemetrie-Buffer. Der ``decoded.reply_data``
            # ist hier bereits ab Byte 4 = direkt der LPP-Buffer.
            gps = parse_lpp_gps(decoded.reply_data)
            if gps is None:
                _log.info(
                    "telemetry_response_no_gps",
                    identity=loaded.name,
                    peer=decoded.sender_pubkey[:4].hex(),
                    tag=decoded.tag,
                    reply_len=len(decoded.reply_data),
                )
                return
            # Lat/Lon = (0,0) ist Default-Sentinel, nicht ozeanmittig schreiben
            if gps.lat == 0.0 and gps.lon == 0.0:
                _log.info(
                    "telemetry_gps_zero",
                    peer=decoded.sender_pubkey[:4].hex(),
                )
                return
            async with self.sessionmaker() as db:
                contact = (
                    await db.execute(
                        select(CompanionContact).where(
                            CompanionContact.identity_id == loaded.id,
                            CompanionContact.peer_pubkey == decoded.sender_pubkey,
                        )
                    )
                ).scalar_one_or_none()
                if contact is None:
                    return
                contact.last_lat = gps.lat
                contact.last_lon = gps.lon
                contact.last_seen_at = datetime.now(UTC)
                await db.commit()
            _log.info(
                "telemetry_gps_persisted",
                identity=loaded.name,
                peer=decoded.sender_pubkey[:4].hex(),
                lat=gps.lat,
                lon=gps.lon,
            )
            return

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
            db.add(
                CompanionMessage(
                    identity_id=loaded.id,
                    direction="out",
                    payload_type=int(PayloadType.TXT_MSG),
                    peer_pubkey=peer_pubkey,
                    peer_name=contact.peer_name if contact else None,
                    text=text,
                    raw=raw,
                )
            )
            await db.commit()

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
        app_data = encode_advert_app_data(
            name=loaded.name[:32], adv_type=ADV_TYPE_CHAT
        )
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
