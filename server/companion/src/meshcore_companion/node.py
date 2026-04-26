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

import hashlib
import os
import struct
import time
from dataclasses import dataclass
from typing import ClassVar

from meshcore_companion.crypto import (
    CIPHER_MAC_SIZE,
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
    flags: int = 0  # raw flags-Byte aus plaintext[4], wichtig für ack_hash


@dataclass
class IncomingResponse:
    """Decodierte RESPONSE auf einen REQ. ``reply_data`` ist payload-
    spezifisch (z.B. LPP-Buffer für GET_TELEMETRY_DATA, beginnend nach
    den 4 ``tag``-Bytes — diese sind hier bereits als ``tag`` extrahiert)."""

    sender_pubkey: bytes
    tag: int
    reply_data: bytes


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
        """Verschlüsselte Direktnachricht an ``peer_pubkey``.

        Plaintext-Format (firmware ``BaseChatMesh.cpp:209-219``):
        ``[ts:4 LE] [flags:1] [text...]`` — flags bits sind
        ``(attempt & 3) | (txt_type << 2)``. Wir senden flags=0 =
        TXT_TYPE_PLAIN, attempt=0.
        """
        ts = timestamp if timestamp is not None else int(time.time())
        secret = self.local.calc_shared_secret(peer_pubkey)
        plaintext = (
            int.to_bytes(ts, 4, "little", signed=False)
            + bytes([0])  # flags: TXT_TYPE_PLAIN | attempt=0
            + text.encode("utf-8")
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
        """TXT_MSG-Paket-Body entschlüsseln.

        Plaintext-Format (firmware ``BaseChatMesh.cpp:209``):
        ``[ts:4 LE] [flags:1] [text...]``. ``flags = (attempt & 3) |
        (txt_type << 2)``. Wir akzeptieren nur ``txt_type == 0``
        (TXT_TYPE_PLAIN); andere Typen (CLI_DATA, SIGNED_PLAIN) werden
        gedroppt, weil deren Body-Layout abweicht.
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
            if len(plain) < _TIMESTAMP_LEN + 1:
                continue
            ts = int.from_bytes(plain[:_TIMESTAMP_LEN], "little", signed=False)
            flags = plain[_TIMESTAMP_LEN]
            txt_type = flags >> 2
            if txt_type != 0:  # nur TXT_TYPE_PLAIN
                continue
            try:
                text = plain[_TIMESTAMP_LEN + 1 :].rstrip(b"\x00").decode("utf-8")
            except UnicodeDecodeError:
                continue
            return IncomingTextMessage(
                sender_pubkey=peer.pub_key,
                timestamp=ts,
                text=text,
                flags=flags,
            )
        return None

    # ---------- REQ / RESPONSE (Admin-Telemetrie etc.) ----------

    def make_telemetry_req(
        self,
        *,
        peer_pubkey: bytes,
        tag: int | None = None,
        req_type: int = 0x03,
        perm_mask_inverse: int = 0x00,
        timestamp: int | None = None,
        flood: bool = True,
    ) -> tuple[Packet, int]:
        """REQ-Paket für ``REQ_TYPE_GET_TELEMETRY_DATA`` an ``peer_pubkey``.

        Wire (firmware ``BaseChatMesh::sendRequest`` und
        ``Mesh::createDatagram``): payload_type=REQ, body =
        ``[dest_hash:1] [src_hash:1] [encrypt_then_mac(plaintext)]``,
        plaintext = ``tag(4 LE) || req_type(1) || perm_mask_inverse(1) ||
        reserved(3 zero) || random(4)`` = 13 Byte.

        Firmware setzt ``perm_mask = ~payload[1]``, daher 0x00 hier
        bedeutet "alle Permissions" beim Empfänger (gefiltert auf
        ``PERM_ACL_GUEST`` falls Sender Guest ist).

        Returns ``(packet, tag)`` — ``tag`` wird als Korrelations-ID in
        der RESPONSE zurück-echot.
        """
        if tag is None:
            tag = (timestamp if timestamp is not None else int(time.time())) & 0xFFFFFFFF
        plaintext = (
            int.to_bytes(tag, 4, "little", signed=False)
            + bytes([req_type, perm_mask_inverse, 0x00, 0x00, 0x00])
            + os.urandom(4)
        )
        secret = self.local.calc_shared_secret(peer_pubkey)
        encrypted = encrypt_then_mac(secret, plaintext)
        peer = Identity(peer_pubkey)
        body = peer.hash_prefix() + self.pub_hash + encrypted
        pkt = Packet(
            route_type=RouteType.FLOOD if flood else RouteType.DIRECT,
            payload_type=PayloadType.REQ,
            payload=body,
        )
        return pkt, tag

    def try_decrypt_response(
        self,
        *,
        packet: Packet,
        peer_candidates: list[Identity],
    ) -> IncomingResponse | None:
        """RESPONSE-Body decoden. Wire-Format identisch zu DM:
        ``[dest_hash:1] [src_hash:1] [encrypt_then_mac(tag(4) || reply_data)]``.

        Wir probieren alle Kandidaten mit passendem ``src_hash``-Prefix
        und versuchen ``mac_then_decrypt``. Erste erfolgreiche Dekryption
        gewinnt. Reply_data ab Byte 4 (nach tag).
        """
        if packet.payload_type != PayloadType.RESPONSE:
            return None
        body = packet.payload
        if len(body) < 2 * PATH_HASH_SIZE + CIPHER_MAC_SIZE:
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
            tag = int.from_bytes(plain[:_TIMESTAMP_LEN], "little", signed=False)
            return IncomingResponse(
                sender_pubkey=peer.pub_key,
                tag=tag,
                reply_data=bytes(plain[4:]),
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

    # ---------- ACK (PAYLOAD_TYPE_ACK = 0x03) ----------

    _ACK_HASH_LEN: ClassVar[int] = 4

    def make_ack(self, ack_hash: bytes, *, flood: bool = True) -> Packet:
        """Reiner ACK-Frame (firmware ``Mesh::createAck`` Mesh.cpp:546).

        Payload ist 4 Byte unverschlüsselter ack_hash. Wir schicken den
        zusätzlich zum PATH-Return, weil manche MeshCore-Implementierungen
        den im PATH eingebetteten ACK nicht zuverlässig auswerten — der
        separate ACK-Frame wird in firmware ``onAckRecv``-Pfad direkt
        verarbeitet."""
        if len(ack_hash) != self._ACK_HASH_LEN:
            raise ValueError(f"ack_hash must be {self._ACK_HASH_LEN} bytes")
        return Packet(
            route_type=RouteType.FLOOD if flood else RouteType.DIRECT,
            payload_type=PayloadType.ACK,
            payload=ack_hash,
        )

    # ---------- PATH-Return (Out-Path-Lernen + ACK piggyback) ----------

    def make_path_return(
        self,
        *,
        peer_pubkey: bytes,
        rx_path_len_byte: int,
        rx_path_bytes: bytes,
        extra_type: int = 0,
        extra_data: bytes = b"",
    ) -> Packet:
        """Erzeugt ein PATH-Datagramm an ``peer_pubkey``.

        firmware ``Mesh::createPathReturn`` (Mesh.cpp:434): plaintext =
        ``[path_len_byte:1] [path_bytes:N] [extra_type:1] [extra_data]``
        (bei ``extra_data`` leer wird ``extra_type=0xFF`` und 4 Random-
        Bytes als Filler gesendet, damit der packet_hash unique bleibt).

        Praxis-Aufruf: nach erfolgreichem DM-Empfang (RouteType=FLOOD)
        antwortet der Empfänger mit PATH-Return + extra_type=ACK
        (0x03) + ack_hash(4 Byte). Der Sender lernt damit den Out-Path
        ZU UNS und kennzeichnet die DM in seiner UI als delivered.
        """
        plain_data = bytearray()
        plain_data.append(rx_path_len_byte)
        plain_data += rx_path_bytes
        if extra_data:
            plain_data.append(extra_type)
            plain_data += extra_data
        else:
            plain_data.append(0xFF)
            plain_data += os.urandom(4)
        secret = self.local.calc_shared_secret(peer_pubkey)
        encrypted = encrypt_then_mac(secret, bytes(plain_data))
        peer = Identity(peer_pubkey)
        body = peer.hash_prefix() + self.pub_hash + encrypted
        return Packet(
            route_type=RouteType.FLOOD,
            payload_type=PayloadType.PATH,
            payload=body,
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


# ---------- CHANNEL receive ----------


@dataclass
class IncomingChannelMessage:
    """Geparster GRP_TXT-Channel-Post.

    ``sender_name`` ist nur kosmetisch — MeshCore-Channels signieren den
    Inhalt nicht, jeder mit Channel-Secret kann beliebige Namen senden.
    """

    channel_secret: bytes
    timestamp: int
    sender_name: str
    text: str


def compute_dm_ack_hash(
    *, timestamp: int, flags: int, text_bytes: bytes, sender_pubkey: bytes
) -> bytes:
    """4-Byte-ACK-Hash über die DM-Plaintext (firmware
    ``BaseChatMesh.cpp:222``): ``sha256(ts(4) || flags(1) || text || sender_pubkey)[:4]``.

    Empfänger sendet diesen Hash im PATH-Return-extra zurück, damit die
    Mobile-App des Senders die DM in der UI als 'delivered' markiert.
    """
    plaintext = (
        int.to_bytes(timestamp, 4, "little", signed=False)
        + bytes([flags])
        + text_bytes
    )
    return hashlib.sha256(plaintext + sender_pubkey).digest()[:4]


@dataclass
class TelemetryGPS:
    """Aus LPP_GPS-Eintrag eines Telemetrie-Reply gewonnene Geokoordinaten."""

    lat: float
    lon: float
    alt: float


# LPP-Type-IDs → Datenlänge in Bytes (ohne chan+type-Prefix). Quelle:
# firmware/lib/meshcore/src/helpers/sensors/LPPDataHelpers.h skipData().
_LPP_DATA_SIZE: dict[int, int] = {
    0: 1,    # DIGITAL_INPUT
    1: 1,    # DIGITAL_OUTPUT
    2: 2,    # ANALOG_INPUT
    3: 2,    # ANALOG_OUTPUT
    100: 4,  # GENERIC_SENSOR
    101: 2,  # LUMINOSITY
    102: 1,  # PRESENCE
    103: 2,  # TEMPERATURE
    104: 1,  # RELATIVE_HUMIDITY
    113: 6,  # ACCELEROMETER
    115: 2,  # BAROMETRIC_PRESSURE
    116: 2,  # VOLTAGE
    117: 2,  # CURRENT
    118: 4,  # FREQUENCY
    120: 1,  # PERCENTAGE
    121: 2,  # ALTITUDE
    125: 2,  # CONCENTRATION
    128: 2,  # POWER
    130: 4,  # DISTANCE
    131: 4,  # ENERGY
    132: 2,  # DIRECTION
    133: 4,  # UNIXTIME
    134: 6,  # GYROMETER
    135: 3,  # COLOUR
    136: 9,  # GPS (3 lat + 3 lon + 3 alt)
    142: 1,  # SWITCH
}
_LPP_GPS_TYPE = 136


def parse_lpp_gps(buf: bytes) -> TelemetryGPS | None:
    """Findet den ersten ``LPP_GPS``-Eintrag in einem LPP-Telemetrie-Buffer.

    Format pro Eintrag: ``[chan:1] [type:1] [data:N]``. GPS-Daten sind
    9 Byte: lat(3 BE signed, /10000), lon(3 BE signed, /10000), alt(3 BE
    signed, /100). Bei unbekanntem Type bricht der Parser ab — saubere
    Telemetrie-Buffer enthalten nur known types.
    """
    i = 0
    while i + 2 <= len(buf):
        type_ = buf[i + 1]
        if type_ == _LPP_GPS_TYPE:
            if i + 2 + 9 > len(buf):
                return None
            lat = int.from_bytes(buf[i + 2 : i + 5], "big", signed=True) / 10000.0
            lon = int.from_bytes(buf[i + 5 : i + 8], "big", signed=True) / 10000.0
            alt = int.from_bytes(buf[i + 8 : i + 11], "big", signed=True) / 100.0
            return TelemetryGPS(lat=lat, lon=lon, alt=alt)
        size = _LPP_DATA_SIZE.get(type_)
        if size is None:
            return None
        i += 2 + size
    return None


def try_decrypt_grp_txt(
    *,
    packet: Packet,
    channels: list[tuple[bytes, bytes]],
) -> IncomingChannelMessage | None:
    """Versucht, einen GRP_TXT-Paket-Body mit einem der bekannten
    Channel-Secrets zu entschlüsseln.

    ``channels`` ist eine Liste von ``(channel_hash[:1], channel_secret[32])``.
    Wir matchen zuerst den 1-Byte-Hash; bei Treffer wird ``mac_then_decrypt``
    versucht. Erste erfolgreiche Dekryption gewinnt.
    """
    if packet.payload_type != PayloadType.GRP_TXT:
        return None
    body = packet.payload
    if len(body) < PATH_HASH_SIZE + CIPHER_MAC_SIZE:
        return None
    chash = body[:PATH_HASH_SIZE]
    encrypted = body[PATH_HASH_SIZE:]
    for ch_hash, ch_secret in channels:
        if ch_hash[:PATH_HASH_SIZE] != chash:
            continue
        plain = mac_then_decrypt(ch_secret, encrypted)
        if plain is None:
            continue
        if len(plain) < _TIMESTAMP_LEN + 1:
            continue
        ts = int.from_bytes(plain[:_TIMESTAMP_LEN], "little", signed=False)
        txt_type = plain[_TIMESTAMP_LEN]
        if txt_type & 0xFC:  # high 6 bits must be zero
            continue
        try:
            body_str = (
                plain[_TIMESTAMP_LEN + 1 :].rstrip(b"\x00").decode("utf-8")
            )
        except UnicodeDecodeError:
            continue
        if ": " in body_str:
            sender, _, text = body_str.partition(": ")
        else:
            sender, text = "", body_str
        return IncomingChannelMessage(
            channel_secret=ch_secret,
            timestamp=ts,
            sender_name=sender,
            text=text,
        )
    return None
