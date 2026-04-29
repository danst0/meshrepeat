"""Live-Traffic-Log: Ringbuffer aller Bridge-Events.

Pakete on-air sind verschlüsselt (Datagram, Channel-Group, Trace),
deshalb können wir nicht "von/an" als Klartext zeigen. Was wir sehen:

- Header-Byte: payload_type + route_type + version
- Bei ADVERT: erste 32 Bytes der Payload sind der Pubkey (Klartext)
- Path-Hashes: 1-3 Byte Prefixes der Repeater-Pubkeys, die das Paket
  schon weitergegeben haben (Klartext)
- Source-Site (welche WS-Verbindung das Paket angeliefert hat)
- Forward-Targets (welche Sites haben es weiterbekommen)
- Server-RX-Timestamp + Bytes
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import Lock
from typing import Any
from uuid import UUID

# MeshCore Header-Byte (siehe firmware/lib/meshcore/src/Packet.h):
#   bits 1..0  route_type   (00 transport-flood, 01 flood, 10 direct, 11 transport-direct)
#   bits 5..2  payload_type (siehe unten)
#   bits 7..6  version      (PAYLOAD_VER_1=01 in aktueller Firmware)

ROUTE_TYPE_NAMES = {
    0b00: "TRANSPORT_FLOOD",
    0b01: "FLOOD",
    0b10: "DIRECT",
    0b11: "TRANSPORT_DIRECT",
}

_HEADER_PLEN_BYTES = 2  # header + path-length-byte

PAYLOAD_TYPE_NAMES = {
    0x00: "REQ",
    0x01: "RESPONSE",
    0x02: "TXT_MSG",
    0x03: "ACK",
    0x04: "ADVERT",
    0x05: "GRP_TXT",
    0x06: "GRP_DATA",
    0x07: "ANON_REQ",
    0x08: "PATH",
    0x09: "TRACE",
    0x0A: "MULTIPART",
    0x0F: "RAW_CUSTOM",
}

# Path-Length Field (1 Byte): obere 2 Bits = hash-size-1, untere 6 Bits = hop-count


@dataclass
class TrafficEvent:
    ts: datetime
    site_id: UUID
    site_name: str | None
    scope: str
    route_type: str
    payload_type: str
    raw_size: int
    raw_hex: str
    path_hashes: list[str]
    advert_pubkey: str | None
    forwarded_to: list[dict[str, str]]
    dropped_reason: str | None

    def as_dict(self, *, include_raw: bool = True) -> dict[str, Any]:
        d: dict[str, Any] = {
            "ts": self.ts.isoformat(),
            "site_id": str(self.site_id),
            "site_name": self.site_name,
            "scope": self.scope,
            "route_type": self.route_type,
            "payload_type": self.payload_type,
            "raw_size": self.raw_size,
            "path_hashes": self.path_hashes,
            "advert_pubkey": self.advert_pubkey,
            "forwarded_to": self.forwarded_to,
            "dropped_reason": self.dropped_reason,
        }
        if include_raw:
            d["raw_hex"] = self.raw_hex
        return d


def parse_packet_meta(raw: bytes) -> tuple[str, str, list[str], str | None]:
    """Liest Header + Path-Hashes + (bei ADVERT) PubKey aus einem MeshCore-Paket.

    Returns ``(route_type_name, payload_type_name, path_hashes, advert_pubkey_hex|None)``.
    Path-Hashes sind hex-strings.
    """
    if not raw:
        return ("?", "?", [], None)
    header = raw[0]
    route_type_id = header & 0b11
    route_type = ROUTE_TYPE_NAMES.get(route_type_id, f"R{route_type_id:02b}")
    payload_type_id = (header >> 2) & 0b1111
    payload_type = PAYLOAD_TYPE_NAMES.get(payload_type_id, f"0x{payload_type_id:02X}")

    if len(raw) < _HEADER_PLEN_BYTES:
        return (route_type, payload_type, [], None)
    plen = raw[1]
    hash_size = ((plen >> 6) & 0b11) + 1
    hop_count = plen & 0b111111
    path_bytes_total = hash_size * hop_count

    path_hashes: list[str] = []
    if 2 + path_bytes_total <= len(raw):
        for i in range(hop_count):
            start = 2 + i * hash_size
            path_hashes.append(raw[start : start + hash_size].hex())

    advert_pubkey: str | None = None
    if payload_type == "ADVERT":
        # Nach Path-Header kommen ggf. transport_codes (4 Byte) bei TRANSPORT_*,
        # für FLOOD/DIRECT direkt der Payload. Im Advert: 32 Byte Pubkey + 4 Byte
        # Timestamp + 64 Byte Sig + bis 32 Byte AppData.
        body_start = 2 + path_bytes_total
        if route_type.startswith("TRANSPORT"):
            body_start += 4
        if body_start + 32 <= len(raw):
            advert_pubkey = raw[body_start : body_start + 32].hex()

    return (route_type, payload_type, path_hashes, advert_pubkey)


@dataclass
class TrafficLog:
    capacity: int = 500
    _events: deque[TrafficEvent] = field(default_factory=lambda: deque(maxlen=500))
    _lock: Lock = field(default_factory=Lock)
    _hook: Callable[[TrafficEvent], None] | None = None

    def __post_init__(self) -> None:
        # capacity wird via __init__ gesetzt; dequeu maxlen rebuilden
        self._events = deque(maxlen=self.capacity)

    def set_hook(self, hook: Callable[[TrafficEvent], None] | None) -> None:
        """Setzt eine Callback, die nach jedem ``record()`` synchron aufgerufen
        wird. Genutzt vom Packet-Spool, um Events zusätzlich in die DB zu
        spülen. Hook darf nicht blockieren — bei Bedarf in eine eigene Queue
        pushen."""
        self._hook = hook

    def record(self, event: TrafficEvent) -> None:
        with self._lock:
            self._events.append(event)
        hook = self._hook
        if hook is not None:
            with suppress(Exception):
                hook(event)

    def recent(self, *, limit: int = 100) -> list[TrafficEvent]:
        with self._lock:
            n = min(limit, len(self._events))
            return list(self._events)[-n:]

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)


def make_event(
    *,
    site_id: UUID,
    site_name: str | None,
    scope: str,
    raw: bytes,
    forwarded_to_pairs: list[tuple[UUID, str | None]],
    dropped_reason: str | None,
) -> TrafficEvent:
    route_type, payload_type, path_hashes, advert_pubkey = parse_packet_meta(raw)
    return TrafficEvent(
        ts=datetime.now(UTC),
        site_id=site_id,
        site_name=site_name,
        scope=scope,
        route_type=route_type,
        payload_type=payload_type,
        raw_size=len(raw),
        raw_hex=raw.hex(),
        path_hashes=path_hashes,
        advert_pubkey=advert_pubkey,
        forwarded_to=[
            {"site_id": str(sid), "name": name or ""}
            for sid, name in forwarded_to_pairs
        ],
        dropped_reason=dropped_reason,
    )
