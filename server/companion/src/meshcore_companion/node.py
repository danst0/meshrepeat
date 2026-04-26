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

import struct
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

# AdvertDataHelpers (firmware/lib/meshcore/src/helpers/AdvertDataHelpers.h):
# app_data := flags(1) [lat(4) lon(4)]? [feat1(2)]? [feat2(2)]? [name…]?
ADV_TYPE_NONE = 0
ADV_TYPE_CHAT = 1
ADV_TYPE_REPEATER = 2
ADV_TYPE_ROOM = 3
ADV_TYPE_SENSOR = 4
ADV_LATLON_MASK = 0x10
ADV_FEAT1_MASK = 0x20
ADV_FEAT2_MASK = 0x40
ADV_NAME_MASK = 0x80


@dataclass
class ParsedAdvertData:
    adv_type: int
    name: str
    lat: float | None
    lon: float | None


def encode_advert_app_data(
    *,
    name: str,
    adv_type: int = ADV_TYPE_CHAT,
    lat: float | None = None,
    lon: float | None = None,
) -> bytes:
    """Baut das ``app_data``-Feld eines ADVERT-Pakets im MeshCore-Format
    (Flags-Byte, optional Lat/Lon, dann Name).
    """
    flags = adv_type & 0x0F
    body = b""
    if lat is not None and lon is not None:
        flags |= ADV_LATLON_MASK
        body += struct.pack("<ii", int(lat * 1_000_000), int(lon * 1_000_000))
    name_bytes = name.encode("utf-8")
    if name_bytes:
        flags |= ADV_NAME_MASK
        body += name_bytes
    return bytes([flags]) + body


def parse_advert_app_data(app_data: bytes) -> ParsedAdvertData:
    """Liest ein ADVERT-``app_data``-Feld zurück. Tolerant gegen
    Längen-Mismatches (gibt dann leeren Namen zurück).
    """
    if not app_data:
        return ParsedAdvertData(adv_type=0, name="", lat=None, lon=None)
    flags = app_data[0]
    adv_type = flags & 0x0F
    i = 1
    lat: float | None = None
    lon: float | None = None
    if flags & ADV_LATLON_MASK:
        if len(app_data) < i + 8:
            return ParsedAdvertData(adv_type=adv_type, name="", lat=None, lon=None)
        lat_i, lon_i = struct.unpack("<ii", app_data[i : i + 8])
        lat = lat_i / 1_000_000.0
        lon = lon_i / 1_000_000.0
        i += 8
    if flags & ADV_FEAT1_MASK:
        i += 2
    if flags & ADV_FEAT2_MASK:
        i += 2
    name = ""
    if flags & ADV_NAME_MASK and len(app_data) > i:
        name = app_data[i:].rstrip(b"\x00").decode("utf-8", errors="replace").strip()
    return ParsedAdvertData(adv_type=adv_type, name=name, lat=lat, lon=lon)


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
