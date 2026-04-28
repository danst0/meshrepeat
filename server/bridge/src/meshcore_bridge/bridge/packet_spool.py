"""DB-Spool für Bridge-Pakete.

Der Router schreibt jedes Paket über ``TrafficLog.record()`` in einen
In-Memory-Ringbuffer. Damit die Wireshark-Inspector-Seite auch über
Server-Restarts hinweg historische Pakete zeigen kann, hängen wir uns
zusätzlich per Hook an den TrafficLog und schieben die Events in eine
neue DB-Tabelle ``raw_packets``.

Das Schreiben erfolgt über eine ``asyncio.Queue``: der Hook (synchron
aus dem Router-Pfad) macht ``put_nowait``; ein Background-Worker
drainiert in Batches und committet einmal je Batch. Bei Überlauf
wird gedroppt — ein Counter wird im Status-Endpoint sichtbar.

Retention: stündlicher Task löscht alles älter als 7 Tage.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager, suppress
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from meshcore_bridge.bridge.traffic import TrafficEvent, TrafficLog
from meshcore_bridge.db.models import RawPacket
from meshcore_bridge.log import get_logger

_DEFAULT_QUEUE_MAX = 5000
_DEFAULT_BATCH_SIZE = 100
_DEFAULT_FLUSH_INTERVAL_S = 1.0
_DEFAULT_RETENTION_DAYS = 7
_RETENTION_INTERVAL_S = 3600.0

SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]


class PacketSpool:
    """Async-Worker, der Bridge-TrafficEvents in die DB persistiert."""

    def __init__(
        self,
        sessionmaker: SessionFactory,
        *,
        queue_max: int = _DEFAULT_QUEUE_MAX,
        batch_size: int = _DEFAULT_BATCH_SIZE,
        flush_interval_s: float = _DEFAULT_FLUSH_INTERVAL_S,
        retention_days: int = _DEFAULT_RETENTION_DAYS,
    ) -> None:
        self._sessionmaker = sessionmaker
        self._queue: asyncio.Queue[TrafficEvent] = asyncio.Queue(maxsize=queue_max)
        self._batch_size = batch_size
        self._flush_interval_s = flush_interval_s
        self._retention = timedelta(days=retention_days)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._writer_task: asyncio.Task[None] | None = None
        self._retention_task: asyncio.Task[None] | None = None
        self._log = get_logger("packet_spool")
        self.dropped = 0
        self.written = 0

    def enqueue(self, event: TrafficEvent) -> None:
        """Sync-Hook für TrafficLog. Best-effort, droppt bei voller Queue."""
        loop = self._loop
        if loop is None:
            return
        try:
            loop.call_soon_threadsafe(self._put_nowait, event)
        except RuntimeError:
            # Loop schon zu — nichts zu tun
            self.dropped += 1

    def _put_nowait(self, event: TrafficEvent) -> None:
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self.dropped += 1

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._writer_task = asyncio.create_task(
            self._writer_loop(), name="packet_spool_writer"
        )
        self._retention_task = asyncio.create_task(
            self._retention_loop(), name="packet_spool_retention"
        )

    async def stop(self) -> None:
        for task in (self._writer_task, self._retention_task):
            if task is None:
                continue
            task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await task
        self._writer_task = None
        self._retention_task = None
        # Letzten Rest aus der Queue noch wegschreiben
        await self._flush_remaining()

    async def _writer_loop(self) -> None:
        while True:
            try:
                batch = await self._collect_batch()
                if not batch:
                    continue
                await self._write_batch(batch)
            except asyncio.CancelledError:
                raise
            except Exception:
                self._log.exception("packet_spool_writer_failed")
                await asyncio.sleep(1.0)

    async def _collect_batch(self) -> list[TrafficEvent]:
        """Wartet auf erstes Event, sammelt dann bis zu ``batch_size`` weitere
        innerhalb von ``flush_interval_s``."""
        first = await self._queue.get()
        batch = [first]
        deadline = asyncio.get_running_loop().time() + self._flush_interval_s
        while len(batch) < self._batch_size:
            timeout = deadline - asyncio.get_running_loop().time()
            if timeout <= 0:
                break
            try:
                ev = await asyncio.wait_for(self._queue.get(), timeout=timeout)
            except TimeoutError:
                break
            batch.append(ev)
        return batch

    async def _write_batch(self, batch: list[TrafficEvent]) -> None:
        rows = [_event_to_row(e) for e in batch]
        async with self._sessionmaker() as session:
            session.add_all(rows)
            await session.commit()
        self.written += len(rows)

    async def _flush_remaining(self) -> None:
        rest: list[TrafficEvent] = []
        while True:
            try:
                rest.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        if rest:
            try:
                await self._write_batch(rest)
            except Exception:
                self._log.exception("packet_spool_final_flush_failed")

    async def _retention_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(_RETENTION_INTERVAL_S)
                await self._purge_old()
            except asyncio.CancelledError:
                raise
            except Exception:
                self._log.exception("packet_spool_retention_failed")

    async def _purge_old(self) -> None:
        cutoff = datetime.now(UTC) - self._retention
        async with self._sessionmaker() as session:
            result = await session.execute(
                delete(RawPacket).where(RawPacket.ts < cutoff)
            )
            await session.commit()
        deleted = getattr(result, "rowcount", 0) or 0
        if deleted:
            self._log.info("packet_spool_purged", rows=deleted)

    def stats(self) -> dict[str, int]:
        return {
            "queued": self._queue.qsize(),
            "queue_max": self._queue.maxsize,
            "written": self.written,
            "dropped": self.dropped,
        }


def _event_to_row(event: TrafficEvent) -> RawPacket:
    return RawPacket(
        ts=event.ts,
        site_id=event.site_id,
        site_name=event.site_name,
        scope=event.scope,
        route_type=event.route_type,
        payload_type=event.payload_type,
        raw=bytes.fromhex(event.raw_hex),
        path_hashes=",".join(event.path_hashes),
        advert_pubkey=event.advert_pubkey,
        forwarded_to=json.dumps(event.forwarded_to),
        dropped_reason=event.dropped_reason,
    )


def attach(spool: PacketSpool, traffic: TrafficLog) -> None:
    traffic.set_hook(spool.enqueue)


@asynccontextmanager
async def lifecycle(
    spool: PacketSpool, traffic: TrafficLog
) -> AsyncIterator[PacketSpool]:
    attach(spool, traffic)
    await spool.start()
    try:
        yield spool
    finally:
        traffic.set_hook(None)
        await spool.stop()
