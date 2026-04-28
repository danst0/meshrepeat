"""Inter-Site-Dedup-Cache.

Pro Paket-Hash hält der Cache ein ``set`` der Sites, die dieses Paket
schon gesehen haben. So können wir auf der Server-Seite verhindern, dass
ein Paket zurück an die Quelle (oder zwischen zwei Sites hin und her)
geschickt wird.

Speicher-Modell:
- ``OrderedDict`` mit Hash → ``CacheEntry`` für LRU-Verhalten und
  schnelle Move-to-End-Updates.
- ``CacheEntry.created_at`` als monotonic-Zeitstempel für TTL.
- Bei Capacity-Überschreitung wird der älteste (LRU) Eintrag verworfen.

``packet_key`` berechnet den Dedup-Schlüssel aus dem on-air-Paket.
Aktuell SHA-256 über das gesamte ``raw``-Feld; später ggf. erste N Byte
ohne SNR-Anhang (siehe WIRE.md).
"""

from __future__ import annotations

import hashlib
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from uuid import UUID


def packet_key(raw: bytes) -> bytes:
    """Stable Dedup-Key über ein on-air-Paket. SHA-256, 32 Bytes.

    Achtung: hashed das ganze raw inkl. path_len + path_hashes — die ändern
    sich pro Hop. Für Inter-Site-Dedup, wo derselbe Frame über mehrere
    Repeater mit unterschiedlichen Hop-Counts hochgereicht wird, lieber
    ``payload_dedup_key`` verwenden.
    """
    return hashlib.sha256(raw).digest()


def payload_dedup_key(raw: bytes) -> bytes:
    """Hop-invarianter Dedup-Key.

    Hashed nur die zwischen-Hops konstanten Felder (Header, optional
    Transport-Codes, Payload-Body) und ignoriert path_len/path_hashes,
    die jeder Repeater beim Forward inkrementiert. Bei Decode-Fehler
    Fallback auf ``packet_key`` — so bleiben malformed Frames trotzdem
    gegen Doppel-Empfang abgesichert.
    """
    # Lokaler Import, weil bridge.dedup auch ohne companion-Package
    # importiert werden können soll (z.B. in Smoke-Tests, wo der
    # Companion-Service abgeschaltet ist).
    from meshcore_companion.packet import Packet as MCPacket  # noqa: PLC0415

    try:
        pkt = MCPacket.decode(raw)
    except ValueError:
        return packet_key(raw)
    h = hashlib.sha256()
    h.update(bytes([pkt.header_byte]))
    if pkt.has_transport_codes:
        h.update(int.to_bytes(pkt.transport_codes[0], 2, "little"))
        h.update(int.to_bytes(pkt.transport_codes[1], 2, "little"))
    h.update(bytes([int(pkt.payload_type)]))
    h.update(pkt.payload)
    return h.digest()


@dataclass
class CacheEntry:
    seen_sites: set[UUID] = field(default_factory=set)
    created_at: float = 0.0


class DedupCache:
    """LRU + TTL Cache mit Pro-Eintrag-Site-Set."""

    def __init__(
        self,
        *,
        capacity: int,
        ttl_s: float,
        time_source: Callable[[], float] | None = None,
    ) -> None:
        self._capacity = capacity
        self._ttl = ttl_s
        self._now = time_source or time.monotonic
        self._entries: OrderedDict[bytes, CacheEntry] = OrderedDict()

    def __len__(self) -> int:
        return len(self._entries)

    def observe(self, key: bytes, site_id: UUID) -> bool:
        """Beobachtet ein Paket von ``site_id`` mit ``key``.

        Returns ``True`` falls die Site das Paket bislang noch nicht hatte
        (also "neu für diese Site"), ``False`` falls schon bekannt.

        In beiden Fällen wird der Cache-Eintrag bzgl. LRU/TTL touched.
        """
        self._evict_expired()
        entry = self._entries.get(key)
        if entry is None:
            entry = CacheEntry(seen_sites={site_id}, created_at=self._now())
            self._entries[key] = entry
            self._evict_overflow()
            return True
        # Existing entry — touch (move to end) and update set.
        self._entries.move_to_end(key)
        if site_id in entry.seen_sites:
            return False
        entry.seen_sites.add(site_id)
        return True

    def has_seen(self, key: bytes, site_id: UUID) -> bool:
        entry = self._entries.get(key)
        return entry is not None and site_id in entry.seen_sites

    def seen_sites(self, key: bytes) -> set[UUID]:
        entry = self._entries.get(key)
        return set(entry.seen_sites) if entry is not None else set()

    def _evict_expired(self) -> None:
        now = self._now()
        cutoff = now - self._ttl
        # OrderedDict iteration starts from oldest; stop at first non-expired.
        while self._entries:
            oldest_entry = next(iter(self._entries.values()))
            if oldest_entry.created_at >= cutoff:
                break
            self._entries.popitem(last=False)

    def _evict_overflow(self) -> None:
        while len(self._entries) > self._capacity:
            self._entries.popitem(last=False)
