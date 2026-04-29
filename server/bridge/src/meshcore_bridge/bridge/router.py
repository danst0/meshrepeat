"""Inter-Site-Routing.

Pro eingehendem ``pkt``-Frame:

1. Hop-invarianten Dedup-Key berechnen (``payload_dedup_key`` — SHA-256
   über header + transport_codes + payload, ohne path_len/path_hashes).
2. Cache observieren — wenn Quelle das Paket schon hatte: drop. Tritt
   regulär auf, sobald derselbe LoRa-Frame über mehrere Repeater
   reinkommt (zweiter Repeater hatte den Key beim ersten Forward
   bereits ins seen-set bekommen).
3. Pro Repeater im selben Scope: senden, sofern dieser Repeater das
   Paket noch nicht hat (laut Cache). Beim Senden wird der Empfänger
   im Cache als "kennt das Paket" markiert.

Companion-Hooks (Phase 4) hängen sich an dieselbe Stelle ein — sie
werden hier wie virtuelle Repeater behandelt.
"""

from __future__ import annotations

from dataclasses import dataclass

from meshcore_bridge.bridge.dedup import DedupCache, payload_dedup_key
from meshcore_bridge.bridge.policy import PolicyEngine
from meshcore_bridge.bridge.registry import ConnectionRegistry, RepeaterConn
from meshcore_bridge.bridge.traffic import TrafficLog, make_event
from meshcore_bridge.log import get_logger
from meshcore_bridge.wire import Packet


@dataclass
class RouteResult:
    forwarded_to: list[RepeaterConn]
    dropped_origin: bool = False
    dropped_policy: str | None = None


class Router:
    def __init__(
        self,
        registry: ConnectionRegistry,
        dedup: DedupCache,
        policy: PolicyEngine | None = None,
        traffic: TrafficLog | None = None,
    ) -> None:
        self._registry = registry
        self._dedup = dedup
        self._policy = policy
        self._traffic = traffic
        self._log = get_logger("router")

    def _record_traffic(
        self,
        *,
        source: RepeaterConn,
        raw: bytes,
        forwarded: list[RepeaterConn],
        dropped_reason: str | None,
    ) -> None:
        if self._traffic is None:
            return
        self._traffic.record(
            make_event(
                site_id=source.site_id,
                site_name=source.name,
                scope=source.scope,
                raw=raw,
                forwarded_to_pairs=[(c.site_id, c.name) for c in forwarded],
                dropped_reason=dropped_reason,
            )
        )

    async def on_packet(self, *, source: RepeaterConn, packet: Packet) -> RouteResult:
        if self._policy is not None:
            decision = self._policy.evaluate(source_site=source.site_id)
            if not decision.allow:
                self._log.debug("drop_policy", site=str(source.site_id), reason=decision.reason)
                self._record_traffic(
                    source=source,
                    raw=packet.raw,
                    forwarded=[],
                    dropped_reason=decision.reason,
                )
                return RouteResult(forwarded_to=[], dropped_policy=decision.reason)

        key = payload_dedup_key(packet.raw)
        is_new_for_source = self._dedup.observe(key, source.site_id)
        if not is_new_for_source:
            self._log.debug("drop_origin_known", site=str(source.site_id), key=key.hex()[:16])
            self._record_traffic(
                source=source,
                raw=packet.raw,
                forwarded=[],
                dropped_reason="origin-known",
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
            except Exception as exc:
                self._log.warning(
                    "peer_send_failed",
                    site=str(peer.site_id),
                    error=str(exc),
                )
                continue
            self._dedup.observe(key, peer.site_id)
            forwarded.append(peer)

        self._record_traffic(
            source=source,
            raw=packet.raw,
            forwarded=forwarded,
            dropped_reason=None,
        )
        return RouteResult(forwarded_to=forwarded)
