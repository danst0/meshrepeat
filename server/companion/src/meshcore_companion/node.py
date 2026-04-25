"""CompanionNode — virtueller MeshCore-Teilnehmer in Python.

Eine Instanz pro Companion-Identität. Erzeugt Adverts, sendet DMs
(PAYLOAD_TYPE_TXT_MSG mit AES+HMAC) und Channel-Posts
(PAYLOAD_TYPE_GRP_TXT, geteiltes Channel-Secret). Inbound-GRP_TXT-
Decode ist bewusst noch nicht implementiert (Phase 5).

DM-Wire-Format (siehe firmware Mesh.cpp:466 + Utils::encryptThenMAC):
    [dest_hash:1] [src_hash:1] [mac:2] [encrypted: timestamp(4) || text]

Der Sender setzt:
    dest_hash = peer.pubkey[:1]
    src_hash  = self.pubkey[:1]
und encrypted-Block = encrypt_then_mac(shared_secret, timestamp || text)
mit shared_secret = ECDH(self, peer).

GRP_TXT-Wire-Format (firmware Mesh.cpp:526 ``createGroupDatagram`` +
BaseChatMesh.cpp:464-481 ``sendGroupTextMessage``):
    [channel_hash:1] [mac:2] [encrypted: timestamp(4) || txt_type(1)
                              || "<sender_name>: " || text]
mit channel_hash = sha256(channel_secret)[:1] und encrypt_then_mac via
channel_secret. ``txt_type`` ist 0 (TXT_TYPE_PLAIN); die oberen 6 Bit
müssen 0 sein.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from meshcore_companion.crypto import (
    PATH_HASH_SIZE,
    Identity,
    LocalIdentity,
    encrypt_then_mac,
    mac_then_decrypt,
)
from meshcore_companion.packet import Advert, Packet, PayloadType, RouteType

_TIMESTAMP_LEN = 4  # le-uint32, prepended to encrypted DM body


@dataclass
class IncomingTextMessage:
    """Geparste Klartext-DM."""

    sender_pubkey: bytes  # nur best-effort: src_hash matched mehrere Pubkeys
    timestamp: int
    text: str


class CompanionNode:
    """Stateless-ish helper to encode/decode MeshCore packets for one identity."""

    def __init__(self, local: LocalIdentity) -> None:
        self.local = local

    @property
    def pub_key(self) -> bytes:
        return self.local.pub_key

    @property
    def pub_hash(self) -> bytes:
        return self.local.pub_key[:PATH_HASH_SIZE]

    # ---------- ADVERT ----------

    def make_advert(
        self,
        *,
        timestamp: int | None = None,
        app_data: bytes = b"",
        flood: bool = True,
    ) -> Packet:
        """Erzeugt einen ADVERT-Packet, signiert mit unserer Identity."""
        ts = timestamp if timestamp is not None else int(time.time())
        adv = Advert(pubkey=self.pub_key, timestamp=ts, app_data=app_data)
        adv.signature = self.local.sign(adv.signed_message)
        return Packet(
            route_type=RouteType.FLOOD if flood else RouteType.DIRECT,
            payload_type=PayloadType.ADVERT,
            payload=adv.encode(),
        )

    # ---------- DM (TXT_MSG) ----------

    def make_dm(
        self,
        *,
        peer_pubkey: bytes,
        text: str,
        timestamp: int | None = None,
        flood: bool = True,
    ) -> Packet:
        """Verschlüsselte Direktnachricht an ``peer_pubkey``."""
        ts = timestamp if timestamp is not None else int(time.time())
        secret = self.local.calc_shared_secret(peer_pubkey)
        plaintext = (
            int.to_bytes(ts, 4, "little", signed=False) + text.encode("utf-8")
        )
        encrypted = encrypt_then_mac(secret, plaintext)
        peer = Identity(peer_pubkey)
        body = peer.hash_prefix() + self.pub_hash + encrypted
        return Packet(
            route_type=RouteType.FLOOD if flood else RouteType.DIRECT,
            payload_type=PayloadType.TXT_MSG,
            payload=body,
        )

    def try_decrypt_dm(
        self,
        *,
        packet: Packet,
        peer_candidates: list[Identity],
    ) -> IncomingTextMessage | None:
        """Versucht, einen TXT_MSG-Paket-Body zu entschlüsseln, indem mit jedem
        Kandidaten ECDH gerechnet und ``mac_then_decrypt`` probiert wird.
        """
        if packet.payload_type != PayloadType.TXT_MSG:
            return None
        body = packet.payload
        if len(body) < 2 + 2:  # dest_hash + src_hash + mac
            return None
        dest_hash = body[:PATH_HASH_SIZE]
        if dest_hash != self.pub_hash:
            return None
        src_hash = body[PATH_HASH_SIZE : 2 * PATH_HASH_SIZE]
        encrypted = body[2 * PATH_HASH_SIZE :]
        for peer in peer_candidates:
            if peer.hash_prefix() != src_hash:
                continue
            secret = self.local.calc_shared_secret(peer.pub_key)
            plain = mac_then_decrypt(secret, encrypted)
            if plain is None:
                continue
            if len(plain) < _TIMESTAMP_LEN:
                continue
            ts = int.from_bytes(plain[:_TIMESTAMP_LEN], "little", signed=False)
            try:
                text = plain[_TIMESTAMP_LEN:].rstrip(b"\x00").decode("utf-8")
            except UnicodeDecodeError:
                continue
            return IncomingTextMessage(
                sender_pubkey=peer.pub_key, timestamp=ts, text=text
            )
        return None

    # ---------- CHANNEL (GRP_TXT) ----------

    def make_channel_message(
        self,
        *,
        channel_secret: bytes,
        channel_hash: bytes,
        text: str,
        sender_name: str | None = None,
        timestamp: int | None = None,
        flood: bool = True,
    ) -> Packet:
        """Erzeugt einen verschlüsselten GRP_TXT-Channel-Post.

        ``channel_secret`` ist das 32-Byte-Symmetric-Secret des Channels,
        ``channel_hash`` das 1-Byte-Routing-Prefix (üblicherweise
        ``sha256(secret)[:1]``).
        """
        if len(channel_hash) < PATH_HASH_SIZE:
            raise ValueError("channel_hash must be at least 1 byte")
        ts = timestamp if timestamp is not None else int(time.time())
        prefix_name = sender_name if sender_name is not None else ""
        body = (
            int.to_bytes(ts, 4, "little", signed=False)
            + bytes([0])  # TXT_TYPE_PLAIN; high 6 bits must stay 0
            + f"{prefix_name}: ".encode()
            + text.encode("utf-8")
        )
        encrypted = encrypt_then_mac(channel_secret, body)
        payload = channel_hash[:PATH_HASH_SIZE] + encrypted
        return Packet(
            route_type=RouteType.FLOOD if flood else RouteType.DIRECT,
            payload_type=PayloadType.GRP_TXT,
            payload=payload,
        )

    # ---------- ADVERT receive ----------

    def parse_inbound_advert(self, packet: Packet) -> Advert | None:
        if packet.payload_type != PayloadType.ADVERT:
            return None
        try:
            adv = Advert.decode(packet.payload)
        except ValueError:
            return None
        if not Identity(adv.pubkey).verify(adv.signature, adv.signed_message):
            return None
        return adv
