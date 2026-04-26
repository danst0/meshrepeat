"""Liveness- und Readiness-Probes für Docker- und Traefik-Healthchecks.

``/healthz`` antwortet sofort (Prozess+Loop laufen). ``/readyz`` prüft
zusätzlich DB-Erreichbarkeit und meldet, ob der Companion-Service läuft —
genug Information, um Watchtower/Traefik klare Signale zu geben.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from meshcore_bridge.db import get_session

router = APIRouter()


@router.get("/healthz", include_in_schema=False)
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz", include_in_schema=False)
async def readyz(request: Request) -> JSONResponse:
    state = request.app.state
    cfg = getattr(state, "config", None)

    db_ok = False
    try:
        async with get_session() as s:
            await s.execute(text("SELECT 1"))
        db_ok = True
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={"status": "db_error", "detail": str(e)[:200]},
        )

    payload: dict[str, Any] = {
        "status": "ready" if db_ok else "db_error",
        "db_ok": db_ok,
        "companion_enabled": bool(cfg and cfg.companion.enabled) if cfg else False,
        "companion_loaded": bool(getattr(state, "companion_service", None)),
        "bridge_connections": len(getattr(state, "bridge_registry", []) or []),
    }
    return JSONResponse(payload)
