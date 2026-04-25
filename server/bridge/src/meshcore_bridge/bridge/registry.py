"""Connection-Registry: pro Scope eine Map site_id → RepeaterConn.

``RepeaterConn`` ist eine schmale Sender-Abstraktion. Im Produktivbetrieb
wickelt sie eine WebSocket-Verbindung; in Tests wird sie durch ein
Fake mit Recording-List ersetzt.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID

from meshcore_bridge.wire import Frame


class FrameSink(Protocol):
    async def send_frame(self, frame: Frame) -> None: ...


@dataclass
class RepeaterConn:
    site_id: UUID
    scope: str
    sink: FrameSink
    user_id: UUID | None = None
    name: str | None = None

    async def send(self, frame: Frame) -> None:
        await self.sink.send_frame(frame)


@dataclass
class ConnectionRegistry:
    _by_site: dict[UUID, RepeaterConn] = field(default_factory=dict)
    _by_scope: dict[str, set[UUID]] = field(default_factory=dict)

    def add(self, conn: RepeaterConn) -> RepeaterConn | None:
        """Registriert eine Verbindung. Liefert die alte Verbindung
        derselben Site zurück (zwecks Schließen), falls vorhanden."""
        old = self._by_site.get(conn.site_id)
        if old is not None:
            self._remove_internal(old)
        self._by_site[conn.site_id] = conn
        self._by_scope.setdefault(conn.scope, set()).add(conn.site_id)
        return old

    def remove(self, site_id: UUID) -> None:
        conn = self._by_site.get(site_id)
        if conn is None:
            return
        self._remove_internal(conn)

    def _remove_internal(self, conn: RepeaterConn) -> None:
        self._by_site.pop(conn.site_id, None)
        members = self._by_scope.get(conn.scope)
        if members is not None:
            members.discard(conn.site_id)
            if not members:
                self._by_scope.pop(conn.scope, None)

    def get(self, site_id: UUID) -> RepeaterConn | None:
        return self._by_site.get(site_id)

    def in_scope(self, scope: str) -> Iterable[RepeaterConn]:
        members = self._by_scope.get(scope, set())
        for site_id in members:
            conn = self._by_site.get(site_id)
            if conn is not None:
                yield conn

    def __len__(self) -> int:
        return len(self._by_site)
