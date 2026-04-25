"""Inter-Site-Routing.

Pro eingehendem ``pkt``-Frame:

1. Dedup-Key berechnen (SHA-256 der raw bytes).
2. Cache observieren — wenn Quelle das Paket schon hatte: drop (sollte
   in einem korrekt funktionierenden Mesh nicht passieren, aber wir
   dropen dann silent).
3. Pro Repeater im selben Scope: senden, sofern dieser Repeater das
   Paket noch nicht hat (laut Cache). Beim Senden wird der Empfänger
   im Cache als "kennt das Paket" markiert.

Companion-Hooks (Phase 4) hängen sich an dieselbe Stelle ein — sie
werden hier wie virtuelle Repeater behandelt.
"""

from __future__ import annotations

from dataclasses import dataclass

from meshcore_bridge.bridge.dedup import DedupCache, packet_key
from meshcore_bridge.bridge.registry import ConnectionRegistry, RepeaterConn
from meshcore_bridge.log import get_logger
from meshcore_bridge.wire import Packet


@dataclass
class RouteResult:
    forwarded_to: list[RepeaterConn]
    dropped_origin: bool = False


class Router:
    def __init__(self, registry: ConnectionRegistry, dedup: DedupCache) -> None:
        self._registry = registry
        self._dedup = dedup
        self._log = get_logger("router")

    async def on_packet(self, *, source: RepeaterConn, packet: Packet) -> RouteResult:
        key = packet_key(packet.raw)
        is_new_for_source = self._dedup.observe(key, source.site_id)
        if not is_new_for_source:
            self._log.debug(
                "drop_origin_known", site=str(source.site_id), key=key.hex()[:16]
            )
            return RouteResult(forwarded_to=[], dropped_origin=True)

        forwarded: list[RepeaterConn] = []
        for peer in list(self._registry.in_scope(source.scope)):
            if peer.site_id == source.site_id:
                continue
            if self._dedup.has_seen(key, peer.site_id):
                continue
            try:
                await peer.send(packet)
            except Exception as exc:  # noqa: BLE001 — wir wollen jeden Fehler isoliert behandeln
                self._log.warning(
                    "peer_send_failed",
                    site=str(peer.site_id),
                    error=str(exc),
                )
                continue
            self._dedup.observe(key, peer.site_id)
            forwarded.append(peer)

        return RouteResult(forwarded_to=forwarded)
