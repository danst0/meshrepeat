"""MeshCore Wire-Paket-Format (1:1 zu firmware/lib/meshcore/src/Packet.cpp).

Layout::

    [header:1] [transport_codes:0|4] [path_len:1] [path:N*hash_size] [payload:rest]

Header-Byte::

    bits 1..0  route_type   (TRANSPORT_FLOOD/FLOOD/DIRECT/TRANSPORT_DIRECT)
    bits 5..2  payload_type (REQ/RESPONSE/TXT_MSG/ACK/ADVERT/...)
    bits 7..6  version

path_len-Byte::

    bits 7..6  hash_size - 1   (1..3 Byte)
    bits 5..0  hop_count       (0..63)
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import ClassVar

MAX_PATH_SIZE = 64
MAX_PACKET_PAYLOAD = 250


class RouteType(enum.IntEnum):
    TRANSPORT_FLOOD = 0x00
    FLOOD = 0x01
    DIRECT = 0x02
    TRANSPORT_DIRECT = 0x03


class PayloadType(enum.IntEnum):
    REQ = 0x00
    RESPONSE = 0x01
    TXT_MSG = 0x02
    ACK = 0x03
    ADVERT = 0x04
    GRP_TXT = 0x05
    GRP_DATA = 0x06
    ANON_REQ = 0x07
    PATH = 0x08
    TRACE = 0x09
    MULTIPART = 0x0A
    CONTROL = 0x0B
    RAW_CUSTOM = 0x0F


@dataclass
class Packet:
    """Decoded MeshCore-Paket.

    ``path`` enthält die rohen path-Bytes (count * hash_size), nicht
    die decodierten Hashes.
    """

    PATH_LEN_HASH_SIZE_SHIFT: ClassVar[int] = 6
    PATH_LEN_COUNT_MASK: ClassVar[int] = 0b00111111
    MAX_HASH_SIZE: ClassVar[int] = 3
    RESERVED_HASH_SIZE: ClassVar[int] = 4
    TRANSPORT_CODE_BYTES: ClassVar[int] = 4

    route_type: RouteType = RouteType.FLOOD
    payload_type: PayloadType = PayloadType.RAW_CUSTOM
    version: int = 0
    transport_codes: tuple[int, int] = (0, 0)
    hash_size: int = 1  # bytes per path-hash
    path: bytes = b""
    payload: bytes = b""
    snr: int | None = None  # nicht im Wire-Format, vom Funk-Empfänger annotiert

    @property
    def hop_count(self) -> int:
        return len(self.path) // self.hash_size if self.hash_size else 0

    @property
    def has_transport_codes(self) -> bool:
        return self.route_type in (
            RouteType.TRANSPORT_FLOOD,
            RouteType.TRANSPORT_DIRECT,
        )

    @property
    def header_byte(self) -> int:
        return (
            int(self.route_type) & 0x03
            | (int(self.payload_type) & 0x0F) << 2
            | (self.version & 0x03) << 6
        )

    @property
    def path_len_byte(self) -> int:
        if self.hash_size < 1 or self.hash_size > self.MAX_HASH_SIZE:
            raise ValueError(f"hash_size must be 1..{self.MAX_HASH_SIZE}, got {self.hash_size}")
        if self.hop_count > self.PATH_LEN_COUNT_MASK:
            raise ValueError(f"hop_count too large: {self.hop_count}")
        return ((self.hash_size - 1) << self.PATH_LEN_HASH_SIZE_SHIFT) | self.hop_count

    def encode(self) -> bytes:
        """On-air-Bytes für ``Packet::writeTo`` ohne SNR-Anhang."""
        out = bytearray()
        out.append(self.header_byte)
        if self.has_transport_codes:
            out += int.to_bytes(self.transport_codes[0], 2, "little")
            out += int.to_bytes(self.transport_codes[1], 2, "little")
        out.append(self.path_len_byte)
        out += self.path
        out += self.payload
        return bytes(out)

    _MIN_RAW_LEN: ClassVar[int] = 2  # header + path_len byte minimum

    @classmethod
    def decode(cls, raw: bytes) -> Packet:
        if len(raw) < cls._MIN_RAW_LEN:
            raise ValueError("packet too short")
        header = raw[0]
        route_type = RouteType(header & 0x03)
        payload_type = PayloadType((header >> 2) & 0x0F)
        version = (header >> 6) & 0x03

        i = 1
        tc = (0, 0)
        has_tc = route_type in (RouteType.TRANSPORT_FLOOD, RouteType.TRANSPORT_DIRECT)
        if has_tc:
            if len(raw) < i + cls.TRANSPORT_CODE_BYTES:
                raise ValueError("packet truncated in transport_codes")
            a = int.from_bytes(raw[i : i + 2], "little")
            b = int.from_bytes(raw[i + 2 : i + 4], "little")
            tc = (a, b)
            i += cls.TRANSPORT_CODE_BYTES

        if len(raw) < i + 1:
            raise ValueError("packet truncated before path_len")
        path_len_byte = raw[i]
        i += 1
        hash_size = (path_len_byte >> cls.PATH_LEN_HASH_SIZE_SHIFT) + 1
        hop_count = path_len_byte & cls.PATH_LEN_COUNT_MASK
        if hash_size == cls.RESERVED_HASH_SIZE:
            raise ValueError("reserved hash_size 4")
        path_bytes = hash_size * hop_count
        if path_bytes > MAX_PATH_SIZE:
            raise ValueError("path exceeds MAX_PATH_SIZE")
        if len(raw) < i + path_bytes:
            raise ValueError("packet truncated in path")
        path = bytes(raw[i : i + path_bytes])
        i += path_bytes

        payload = bytes(raw[i:])
        if len(payload) > MAX_PACKET_PAYLOAD:
            raise ValueError("payload exceeds MAX_PACKET_PAYLOAD")

        return cls(
            route_type=route_type,
            payload_type=payload_type,
            version=version,
            transport_codes=tc,
            hash_size=hash_size,
            path=path,
            payload=payload,
        )

    def add_path_hash(self, hash_bytes: bytes) -> None:
        if len(hash_bytes) != self.hash_size:
            raise ValueError(f"hash must be {self.hash_size} bytes")
        if self.hop_count >= self.PATH_LEN_COUNT_MASK:
            raise ValueError("path full")
        self.path = self.path + hash_bytes


@dataclass
class Advert:
    """ADVERT-Payload-Format::

        [pubkey:32] [timestamp:4 le] [signature:64] [app_data:0..32]

    Signiert wird ``pubkey || timestamp || app_data``.
    """

    pubkey: bytes
    timestamp: int
    app_data: bytes = b""
    signature: bytes = field(default=b"")

    SIG_OFFSET: ClassVar[int] = 32 + 4
    SIG_LEN: ClassVar[int] = 64
    HEADER_LEN: ClassVar[int] = 32 + 4 + 64

    @property
    def signed_message(self) -> bytes:
        return (
            self.pubkey
            + int.to_bytes(self.timestamp, 4, "little", signed=False)
            + self.app_data
        )

    def encode(self) -> bytes:
        if not self.signature:
            raise ValueError("Advert.signature is empty — sign first")
        return (
            self.pubkey
            + int.to_bytes(self.timestamp, 4, "little", signed=False)
            + self.signature
            + self.app_data
        )

    @classmethod
    def decode(cls, payload: bytes) -> Advert:
        if len(payload) < cls.HEADER_LEN:
            raise ValueError("advert payload too short")
        pubkey = bytes(payload[:32])
        timestamp = int.from_bytes(payload[32:36], "little", signed=False)
        signature = bytes(payload[36 : 36 + 64])
        app_data = bytes(payload[36 + 64 :])
        return cls(pubkey=pubkey, timestamp=timestamp, app_data=app_data, signature=signature)
