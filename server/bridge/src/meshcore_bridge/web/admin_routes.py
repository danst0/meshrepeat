"""Admin-API: Status, Reload, Cache-Dumps, Traffic-Log. Nur für Rolle ``admin``."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from meshcore_bridge.bridge import PolicyState
from meshcore_bridge.config import AppConfig
from meshcore_bridge.db import User
from meshcore_bridge.web.deps import admin_required, get_config

router = APIRouter(prefix="/api/v1/admin")
ui_router = APIRouter(prefix="/admin")


def _templates(request: Request) -> Jinja2Templates:
    return request.app.state.templates  # type: ignore[no-any-return]


def _state_to_dict(s: PolicyState) -> dict[str, Any]:
    return {
        "default": s.default,
        "rate_limit_pkts_per_s": s.rate_limit_pkts_per_s,
        "rate_limit_burst": s.rate_limit_burst,
        "sites_tracked": s.sites_tracked,
        "stats": {
            "allowed": s.stats.allowed,
            "denied_default": s.stats.denied_default,
            "denied_rate_limit": s.stats.denied_rate_limit,
        },
    }


@router.get("/status")
async def status(
    request: Request,
    _user: User = Depends(admin_required),
    cfg: AppConfig = Depends(get_config),
) -> dict[str, Any]:
    state = request.app.state
    registry = state.bridge_registry
    dedup = state.bridge_dedup
    policy = state.bridge_policy
    traffic = state.bridge_traffic

    by_scope: dict[str, list[dict[str, Any]]] = {}
    for conn in registry._by_site.values():
        by_scope.setdefault(conn.scope, []).append(
            {
                "site_id": str(conn.site_id),
                "name": conn.name,
            }
        )

    return {
        "server_time": datetime.now(UTC).isoformat(),
        "version": "0.1.0",
        "config_summary": {
            "max_frame_bytes": cfg.bridge.max_frame_bytes,
            "heartbeat_interval_s": cfg.bridge.heartbeat_interval_s,
            "dedup_ttl_s": cfg.bridge.dedup.ttl_s,
            "dedup_capacity": cfg.bridge.dedup.lru_capacity,
        },
        "connections": {
            "total": len(registry),
            "by_scope": by_scope,
        },
        "dedup": {
            "entries": len(dedup),
        },
        "traffic": {
            "buffered_events": len(traffic),
        },
        "policy": _state_to_dict(PolicyState.of(policy)),
    }


@router.post("/policy/reload")
async def policy_reload(
    request: Request,
    _user: User = Depends(admin_required),
) -> dict[str, Any]:
    cfg = AppConfig.load()
    request.app.state.bridge_policy.update(cfg.bridge.policy)
    request.app.state.config = cfg
    return {"ok": True, "policy": _state_to_dict(PolicyState.of(request.app.state.bridge_policy))}


@router.post("/dedup/clear")
async def dedup_clear(
    request: Request,
    _user: User = Depends(admin_required),
) -> dict[str, Any]:
    dedup = request.app.state.bridge_dedup
    n = len(dedup)
    dedup._entries.clear()
    return {"ok": True, "cleared": n}


@router.get("/traffic")
async def traffic(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    _user: User = Depends(admin_required),
) -> dict[str, Any]:
    log = request.app.state.bridge_traffic
    return {
        "events": [e.as_dict() for e in log.recent(limit=limit)],
        "buffered": len(log),
    }


@ui_router.get("/traffic", response_class=HTMLResponse)
async def traffic_page(
    request: Request,
    user: User = Depends(admin_required),
) -> HTMLResponse:
    return _templates(request).TemplateResponse(
        request,
        "admin_traffic.html.j2",
        {"user": user, "flash": None},
    )


@ui_router.get("/", response_class=HTMLResponse)
async def admin_index(
    request: Request,
    user: User = Depends(admin_required),
) -> HTMLResponse:
    return _templates(request).TemplateResponse(
        request,
        "admin_index.html.j2",
        {"user": user, "flash": None},
    )
