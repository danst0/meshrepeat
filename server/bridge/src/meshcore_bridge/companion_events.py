"""asyncio Pub/Sub-Bus für Companion-UI-Push (SSE).

Pro Identity gibt es eine Menge an Subscriber-Queues. ``publish`` ist
non-blocking: volle Queues lassen wir liegen (drop-newest), damit ein
hängender Browser-Tab den Service nicht blockiert.

Der Bus trackt zusätzlich ``_last_active_monotonic`` — den Zeitpunkt der
letzten Subscriber-Aktivität. ``has_active_listener(grace_s)`` macht das
nach außen sichtbar, damit der CompanionService entscheiden kann, ob er
Übersetzungen sofort fährt (User ist auf der Webseite) oder dem Batch
überlässt.
"""

from __future__ import annotations

import asyncio
import time
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
        # monotonic()-Timestamp der letzten Subscriber-Aktivität (subscribe,
        # unsubscribe oder erfolgreiche Zustellung). 0.0 = noch nie aktiv.
        self._last_active_monotonic: float = 0.0

    def _touch(self) -> None:
        self._last_active_monotonic = time.monotonic()

    def subscribe(self, identity_id: UUID) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=_QUEUE_MAX)
        self._subs[identity_id].add(q)
        self._touch()
        return q

    def unsubscribe(self, identity_id: UUID, q: asyncio.Queue[dict[str, Any]]) -> None:
        subs = self._subs.get(identity_id)
        if subs is None:
            return
        subs.discard(q)
        if not subs:
            self._subs.pop(identity_id, None)
        # Auch beim Disconnect aktualisieren — der Grace-Period startet erst
        # ab hier, sonst flackert die Live-Übersetzung bei Reload.
        self._touch()

    async def publish(self, identity_id: UUID, event: dict[str, Any]) -> None:
        subs = self._subs.get(identity_id)
        if not subs:
            return
        self._touch()
        for q in list(subs):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                _log.warning(
                    "sse_queue_full_drop",
                    identity=str(identity_id),
                    type=event.get("type"),
                )

    def has_active_listener(self, grace_s: float) -> bool:
        """``True`` wenn aktuell mindestens ein Subscriber existiert (egal
        welche Identity) **oder** der letzte Aktivitäts-Tick weniger als
        ``grace_s`` Sekunden zurückliegt. Globaler Trigger: jeder offene
        SSE-Stream im Companion-UI zählt."""
        if any(self._subs.values()):
            return True
        if self._last_active_monotonic <= 0.0:
            return False
        return (time.monotonic() - self._last_active_monotonic) <= grace_s
