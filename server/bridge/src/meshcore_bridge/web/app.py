"""FastAPI-Application-Factory.

Hängt Auth-Routen, Repeater-Routen und WebSocket-Endpoint zusammen,
initialisiert DB-Engine und Bridge-State auf ``app.state``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from importlib.resources import files

from fastapi import FastAPI
from fastapi.templating import Jinja2Templates

from meshcore_bridge.bridge import ConnectionRegistry, DedupCache, Router
from meshcore_bridge.config import AppConfig
from meshcore_bridge.db import close_engine, init_engine
from meshcore_bridge.log import get_logger
from meshcore_bridge.web import auth_routes, bridge_ws, repeater_routes


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
        app.state.config = cfg
        app.state.bridge_registry = registry
        app.state.bridge_dedup = dedup
        app.state.bridge_router = Router(registry, dedup)

        templates_dir = files("meshcore_bridge.web") / "templates"
        app.state.templates = Jinja2Templates(directory=str(templates_dir))

        yield

        log.info("stopping")
        await close_engine()

    app = FastAPI(title="MeshCore Spiegel", lifespan=lifespan)
    app.include_router(auth_routes.router)
    app.include_router(repeater_routes.router)
    app.include_router(bridge_ws.router)
    return app
