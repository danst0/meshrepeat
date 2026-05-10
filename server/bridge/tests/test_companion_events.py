"""Bus-Verhalten: Subscriber-Tracking + has_active_listener inkl. Grace."""

from __future__ import annotations

import time
from uuid import uuid4

import pytest

from meshcore_bridge.companion_events import CompanionEventBus


@pytest.mark.asyncio
async def test_no_listener_returns_false() -> None:
    bus = CompanionEventBus()
    assert bus.has_active_listener(grace_s=30.0) is False


@pytest.mark.asyncio
async def test_active_subscriber_returns_true() -> None:
    bus = CompanionEventBus()
    bus.subscribe(uuid4())
    # Selbst mit grace_s=0 muss True kommen, solange ein Sub offen ist.
    assert bus.has_active_listener(grace_s=0.0) is True


@pytest.mark.asyncio
async def test_grace_period_after_disconnect() -> None:
    bus = CompanionEventBus()
    ident = uuid4()

    q = bus.subscribe(ident)
    bus.unsubscribe(ident, q)

    # Sub ist weg, aber innerhalb der Grace gilt der Listener noch als aktiv.
    assert bus.has_active_listener(grace_s=60.0) is True

    # Aktivität künstlich in die Vergangenheit schieben → außerhalb der Grace.
    bus._last_active_monotonic = time.monotonic() - 120.0
    assert bus.has_active_listener(grace_s=60.0) is False
    # Innerhalb einer großzügigeren Grace bleibt es aber aktiv.
    assert bus.has_active_listener(grace_s=300.0) is True


@pytest.mark.asyncio
async def test_publish_refreshes_activity() -> None:
    bus = CompanionEventBus()
    ident = uuid4()

    q = bus.subscribe(ident)
    # Künstlich altes Activity-Tick — Sub-Existenz allein darf das nicht
    # ungültig machen, aber wir wollen sehen, dass publish() den Tick auffrischt.
    bus._last_active_monotonic = time.monotonic() - 1000.0
    # Mit Sub: True (Subs zählen unabhängig vom Timestamp).
    assert bus.has_active_listener(grace_s=10.0) is True

    await bus.publish(ident, {"type": "ping"})

    bus.unsubscribe(ident, q)
    # publish() hat den Tick aufgefrischt → Grace gilt jetzt ab dem publish.
    assert bus.has_active_listener(grace_s=10.0) is True
