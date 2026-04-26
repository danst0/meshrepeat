"""WebSocket-Endpoint für Repeater-Uplink (`/api/v1/bridge`).

Flow:
1. WS-Accept.
2. Erste Binary-Message → muss ``hello``-Frame sein.
3. Server validiert site_id + token gegen DB; matched scope.
4. Bei Erfolg: ``helloack`` zurück; Connection in der Registry; Heartbeat-
   und Routing-Loop starten.
5. Eingehende ``pkt``-Frames werden gerouted; ``hback`` aktualisiert
   Heartbeat-Status.
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from typing import cast

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from meshcore_bridge.auth.tokens import token_prefix, verify_bearer_token
from meshcore_bridge.bridge import ConnectionRegistry, RepeaterConn, Router
from meshcore_bridge.db import Repeater, get_session
from meshcore_bridge.log import get_logger
from meshcore_bridge.wire import (
    PROTO_VERSION,
    Bye,
    Frame,
    FrameDecodeError,
    Heartbeat,
    HeartbeatAck,
    Hello,
    HelloAck,
    Packet,
    decode_frame,
    encode_frame,
)

router = APIRouter()
_log = get_logger("bridge_ws")

WS_CLOSE_NORMAL = 1000
WS_CLOSE_INTERNAL = 1011
WS_CLOSE_BAD_REQUEST = 4400
WS_CLOSE_UNAUTHORIZED = 4401
WS_CLOSE_FORBIDDEN = 4403
WS_CLOSE_GONE = 4410
WS_CLOSE_VERSION = 4426


class _WsSink:
    def __init__(self, ws: WebSocket) -> None:
        self._ws = ws

    async def send_frame(self, frame: Frame) -> None:
        await self._ws.send_bytes(encode_frame(frame))


@router.websocket("/api/v1/bridge")
async def bridge_socket(ws: WebSocket) -> None:
    cfg = ws.app.state.config
    registry: ConnectionRegistry = ws.app.state.bridge_registry
    routing: Router = ws.app.state.bridge_router
    max_bytes: int = cfg.bridge.max_frame_bytes
    hb_iv: int = cfg.bridge.heartbeat_interval_s
    hb_timeout: int = cfg.bridge.heartbeat_timeout_s

    await ws.accept()

    # Hello aus erster Message lesen
    try:
        hello_raw = await asyncio.wait_for(ws.receive_bytes(), timeout=10.0)
    except WebSocketDisconnect:
        return  # client gone, no close needed
    except TimeoutError:
        try:
            await ws.close(code=WS_CLOSE_BAD_REQUEST, reason="no hello")
        except RuntimeError:
            pass
        return

    if len(hello_raw) > max_bytes:
        await ws.close(code=1009, reason="frame too large")
        return

    try:
        first = decode_frame(hello_raw)
    except FrameDecodeError:
        await ws.close(code=WS_CLOSE_BAD_REQUEST, reason="invalid hello")
        return

    if not isinstance(first, Hello):
        await ws.close(code=WS_CLOSE_BAD_REQUEST, reason="expected hello")
        return

    if first.proto != PROTO_VERSION:
        await ws.close(code=WS_CLOSE_VERSION, reason="proto mismatch")
        return

    # DB-Lookup: Token-Prefix → Kandidaten → Argon2-Verify
    repeater = await _authenticate(first)
    if repeater is None:
        await ws.close(code=WS_CLOSE_UNAUTHORIZED, reason="invalid token")
        return
    if repeater.revoked_at is not None:
        await ws.close(code=WS_CLOSE_GONE, reason="token revoked")
        return
    if repeater.scope != first.scope:
        await ws.close(code=WS_CLOSE_FORBIDDEN, reason="scope mismatch")
        return
    if repeater.site_id != first.site:
        await ws.close(code=WS_CLOSE_FORBIDDEN, reason="site mismatch")
        return

    log = _log.bind(site=str(repeater.site_id), scope=repeater.scope, name=repeater.name)
    log.info("repeater_connected")

    # last_seen aktualisieren
    async with get_session() as db:
        row = await db.get(Repeater, repeater.id)
        if row is not None:
            row.last_seen_at = datetime.now(UTC)
            await db.commit()

    sink = _WsSink(ws)
    conn = RepeaterConn(
        site_id=repeater.site_id,
        scope=repeater.scope,
        sink=sink,
        user_id=repeater.owner_id,
        name=repeater.name,
    )
    old_conn = registry.add(conn)
    if old_conn is not None:
        log.warning("replacing_stale_connection")

    await sink.send_frame(
        HelloAck(
            proto=PROTO_VERSION,
            policy_ep=0,
            srv_time=int(time.time()),
            max_bytes=max_bytes,
            hb_iv=hb_iv,
        )
    )

    last_hback_at = time.monotonic()
    hb_task = asyncio.create_task(_heartbeat_loop(ws, sink, hb_iv))

    # Companion: alle Identities im selben Scope kriegen jetzt einen
    # frischen Advert über diese neue Verbindung.
    companion = getattr(ws.app.state, "companion_service", None)
    if companion is not None:
        try:
            await companion.on_repeater_connected(scope=repeater.scope)
        except Exception:
            log.exception("companion_on_connect_hook_failed")

    try:
        while True:
            try:
                data = await asyncio.wait_for(
                    ws.receive_bytes(), timeout=hb_timeout
                )
            except TimeoutError:
                if time.monotonic() - last_hback_at > hb_timeout:
                    log.warning("heartbeat_timeout")
                    await ws.close(code=WS_CLOSE_INTERNAL, reason="heartbeat timeout")
                    return
                continue

            if len(data) > max_bytes:
                await ws.close(code=1009, reason="frame too large")
                return

            try:
                frame = decode_frame(data)
            except FrameDecodeError as exc:
                log.warning("invalid_frame", error=str(exc))
                await ws.close(code=WS_CLOSE_BAD_REQUEST, reason="invalid frame")
                return

            if isinstance(frame, Packet):
                _payload_type = frame.raw[0] >> 2 & 0x0F if frame.raw else None
                log.info(
                    "rx_from_repeater",
                    site=str(conn.site_id),
                    name=conn.name,
                    scope=conn.scope,
                    bytes=len(frame.raw),
                    payload_type=_payload_type,
                    head=frame.raw[:8].hex() if frame.raw else "",
                )
                await routing.on_packet(source=conn, packet=frame)
                companion = getattr(ws.app.state, "companion_service", None)
                if companion is not None:
                    await companion.on_inbound_packet(
                        raw=frame.raw, scope=conn.scope
                    )
            elif isinstance(frame, HeartbeatAck):
                last_hback_at = time.monotonic()
            elif isinstance(frame, Heartbeat):
                # Repeater-initiiertes HB ist erlaubt, beantworten wir
                await sink.send_frame(HeartbeatAck(seq=frame.seq))
            elif isinstance(frame, Bye):
                log.info("repeater_bye", reason=frame.reason)
                await ws.close(code=WS_CLOSE_NORMAL)
                return
            elif isinstance(frame, Hello):
                log.warning("hello_after_handshake")
                await ws.close(code=WS_CLOSE_BAD_REQUEST, reason="duplicate hello")
                return
            # HelloAck/Flow vom Repeater ignorieren wir still

    except WebSocketDisconnect:
        log.info("repeater_disconnected")
    except Exception:  # pragma: no cover - defensive
        log.exception("bridge_loop_error")
        try:
            await ws.close(code=WS_CLOSE_INTERNAL)
        except Exception:
            pass
    finally:
        hb_task.cancel()
        registry.remove(repeater.site_id)


async def _heartbeat_loop(ws: WebSocket, sink: _WsSink, hb_iv: int) -> None:
    seq = 0
    try:
        while True:
            await asyncio.sleep(hb_iv)
            seq += 1
            try:
                await sink.send_frame(Heartbeat(seq=seq, ts=int(time.time())))
            except Exception:
                return
    except asyncio.CancelledError:
        return


async def _authenticate(hello: Hello) -> Repeater | None:
    prefix = token_prefix(hello.tok)
    async with get_session() as db:
        result = await db.execute(
            select(Repeater).where(Repeater.token_prefix == prefix)
        )
        candidates = list(result.scalars())
        for candidate in candidates:
            if candidate.site_id != hello.site:
                continue
            if verify_bearer_token(candidate.token_hash, hello.tok):
                return cast(Repeater, candidate)
    return None
