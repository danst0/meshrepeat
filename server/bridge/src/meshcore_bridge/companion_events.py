"""asyncio Pub/Sub-Bus für Companion-UI-Push (SSE).

Pro Identity gibt es eine Menge an Subscriber-Queues. ``publish`` ist
non-blocking: volle Queues lassen wir liegen (drop-newest), damit ein
hängender Browser-Tab den Service nicht blockiert.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any
from uuid import UUID

from meshcore_bridge.log import get_logger

_log = get_logger("companion_events")

_QUEUE_MAX = 64


class CompanionEventBus:
    def __init__(self) -> None:
        self._subs: dict[UUID, set[asyncio.Queue[dict[str, Any]]]] = defaultdict(set)
        self._lock = asyncio.Lock()

    def subscribe(self, identity_id: UUID) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=_QUEUE_MAX)
        self._subs[identity_id].add(q)
        return q

    def unsubscribe(self, identity_id: UUID, q: asyncio.Queue[dict[str, Any]]) -> None:
        subs = self._subs.get(identity_id)
        if subs is None:
            return
        subs.discard(q)
        if not subs:
            self._subs.pop(identity_id, None)

    async def publish(self, identity_id: UUID, event: dict[str, Any]) -> None:
        subs = self._subs.get(identity_id)
        if not subs:
            return
        for q in list(subs):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                _log.warning(
                    "sse_queue_full_drop",
                    identity=str(identity_id),
                    type=event.get("type"),
                )
