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
    IncomingTextMessage,
    encode_advert_app_data,
    parse_advert_app_data,
)
from meshcore_companion.packet import Packet, PayloadType
from meshcore_companion.storage import decrypt_seed, encrypt_seed

if TYPE_CHECKING:
    from meshcore_bridge.db import CompanionChannel

_log = structlog.get_logger("companion")

PacketInjector = Callable[[Packet, str], Awaitable[None]]
"""Callable(packet, scope) — fügt ein Paket in den Mesh-Scope ein."""

PUBLIC_CHANNEL_NAME = "public"
PUBLIC_CHANNEL_PASSWORD = "public"  # noqa: S105 — kein Geheimnis, MeshCore-Konvention
"""Default-Channel, der für jede Identity automatisch angelegt wird."""


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
        """Idempotent: legt den Standard-Public-Channel an, falls noch
        nicht vorhanden."""
        try:
            await self.add_channel(
                identity_id=identity_id,
                name=PUBLIC_CHANNEL_NAME,
                password=PUBLIC_CHANNEL_PASSWORD,
            )
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

    async def on_inbound_packet(self, *, raw: bytes, scope: str) -> None:
        """Hook, vom Router pro empfangenem Paket gerufen."""
        try:
            pkt = Packet.decode(raw)
        except ValueError:
            return
        if pkt.payload_type == PayloadType.ADVERT:
            await self._handle_inbound_advert(pkt=pkt, scope=scope)
        elif pkt.payload_type == PayloadType.TXT_MSG:
            await self._handle_inbound_dm(pkt=pkt, scope=scope, raw=raw)

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
                    )
                    db.add(contact)
                else:
                    contact.last_seen_at = datetime.now(UTC)
                    if name and contact.peer_name != name:
                        contact.peer_name = name
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
            async with self.sessionmaker() as db:
                db.add(
                    CompanionMessage(
                        identity_id=loaded.id,
                        direction="in",
                        payload_type=int(PayloadType.TXT_MSG),
                        peer_pubkey=decoded.sender_pubkey,
                        peer_name=peer_name,
                        text=decoded.text,
                        raw=raw,
                    )
                )
                await db.commit()
            return  # erste Identity, die's lesen kann, gewinnt

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
