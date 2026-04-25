"""FastAPI-Application-Factory.

Hängt Auth-Routen, Repeater-Routen und WebSocket-Endpoint zusammen,
initialisiert DB-Engine und Bridge-State auf ``app.state``.
"""

from __future__ import annotations

import asyncio
import signal
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from importlib.resources import files

from fastapi import FastAPI
from fastapi.templating import Jinja2Templates

from meshcore_bridge.auth.email import ConsoleEmailSender, SmtpEmailSender
from meshcore_bridge.bridge import (
    ConnectionRegistry,
    DedupCache,
    PolicyEngine,
    Router,
    TrafficLog,
)
from meshcore_bridge.config import AppConfig
from meshcore_bridge.db import close_engine, get_session, init_engine
from meshcore_bridge.log import get_logger
from meshcore_bridge.web import (
    admin_routes,
    auth_routes,
    bridge_ws,
    companion_routes,
    repeater_routes,
)
from meshcore_bridge.wire import Packet as WirePacket
from meshcore_companion.packet import Packet as MCPacket
from meshcore_companion.service import CompanionService


def build_app(cfg: AppConfig) -> FastAPI:
    log = get_logger("app")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        log.info("starting", db=str(cfg.storage.sqlite_path))
        await init_engine(cfg.storage.sqlite_path)
        registry = ConnectionRegistry()
        dedup = DedupCache(
            capacity=cfg.bridge.dedup.lru_capacity,
            ttl_s=cfg.bridge.dedup.ttl_s,
        )
        policy = PolicyEngine(cfg.bridge.policy)
        traffic = TrafficLog(capacity=500)
        app.state.config = cfg
        app.state.bridge_registry = registry
        app.state.bridge_dedup = dedup
        app.state.bridge_policy = policy
        app.state.bridge_traffic = traffic
        app.state.bridge_router = Router(registry, dedup, policy, traffic)

        # SIGHUP → Config + Policy hot-reload
        def _reload_policy() -> None:
            try:
                new_cfg = AppConfig.load()
            except Exception:
                log.exception("policy_reload_failed")
                return
            policy.update(new_cfg.bridge.policy)

        try:
            loop = asyncio.get_running_loop()
            loop.add_signal_handler(signal.SIGHUP, _reload_policy)
        except (NotImplementedError, RuntimeError):
            log.warning("sighup_handler_not_installed")

        templates_dir = files("meshcore_bridge.web") / "templates"
        app.state.templates = Jinja2Templates(directory=str(templates_dir))

        # CompanionService aufsetzen (sofern db_key vorhanden ist)
        companion_service: CompanionService | None = None
        if cfg.companion.enabled and cfg.db_key:
            async def _inject(packet: MCPacket, scope: str) -> None:
                wire = WirePacket(raw=packet.encode())
                for conn in list(registry.in_scope(scope)):
                    try:
                        await conn.send(wire)
                    except Exception:
                        pass

            companion_service = CompanionService(
                master_key=cfg.db_key,
                sessionmaker=get_session,
                inject=_inject,
                advert_interval_s=cfg.companion.advert_interval_s,
            )
            await companion_service.start()
            app.state.companion_service = companion_service
            log.info("companion_started", identities=len(companion_service))
        else:
            app.state.companion_service = None
            if cfg.companion.enabled and not cfg.db_key:
                log.warning("companion_disabled_no_db_key")

        if cfg.web.smtp.enabled and cfg.web.smtp.host:
            auth_routes.set_email_sender(
                SmtpEmailSender(
                    host=cfg.web.smtp.host,
                    port=cfg.web.smtp.port,
                    username=cfg.web.smtp.username or None,
                    password=cfg.web.smtp.password or None,
                    sender=cfg.web.smtp.sender,
                    use_tls=cfg.web.smtp.use_tls,
                    starttls=cfg.web.smtp.starttls,
                )
            )
            log.info("smtp_enabled", host=cfg.web.smtp.host, port=cfg.web.smtp.port)
        else:
            auth_routes.set_email_sender(ConsoleEmailSender())
            log.warning("smtp_disabled_using_console_sender")

        yield

        log.info("stopping")
        if companion_service is not None:
            await companion_service.stop()
        await close_engine()

    app = FastAPI(title="MeshCore Spiegel", lifespan=lifespan)
    app.include_router(auth_routes.router)
    app.include_router(repeater_routes.router)
    app.include_router(bridge_ws.router)
    app.include_router(admin_routes.router)
    app.include_router(admin_routes.ui_router)
    app.include_router(companion_routes.router)
    app.include_router(companion_routes.ui_router)
    return app
