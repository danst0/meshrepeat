"""Admin-API: Status, Reload, Cache-Dumps, Traffic-Log. Nur für Rolle ``admin``."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi import status as http_status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from meshcore_bridge.bridge import PolicyState
from meshcore_bridge.bridge.traffic import (
    PAYLOAD_TYPE_NAMES,
    ROUTE_TYPE_NAMES,
    parse_packet_meta,
)
from meshcore_bridge.config import AppConfig
from meshcore_bridge.db import RawPacket, Repeater, User
from meshcore_bridge.web.deps import admin_required, get_config, get_db

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


@router.get("/repeaters")
async def list_repeaters(
    _user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Liste aller bekannten Repeater (für Inspector-Dropdown)."""
    rows = (
        await db.execute(select(Repeater).order_by(Repeater.name.asc()))
    ).scalars().all()
    return {
        "repeaters": [
            {
                "id": str(r.id),
                "site_id": str(r.site_id),
                "name": r.name,
                "scope": r.scope,
                "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
                "revoked": r.revoked_at is not None,
            }
            for r in rows
        ]
    }


_SINCE_PRESETS = {
    "5m": timedelta(minutes=5),
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
}


def _row_summary(row: RawPacket) -> dict[str, Any]:
    ts = row.ts if row.ts.tzinfo is not None else row.ts.replace(tzinfo=UTC)
    return {
        "id": row.id,
        "ts": ts.isoformat(),
        "site_id": str(row.site_id),
        "site_name": row.site_name,
        "scope": row.scope,
        "route_type": row.route_type,
        "payload_type": row.payload_type,
        "raw_size": len(row.raw),
        "path_hashes": [h for h in row.path_hashes.split(",") if h],
        "advert_pubkey": row.advert_pubkey,
        "dropped_reason": row.dropped_reason,
    }


@router.get("/inspector/packets")
async def inspector_packets(
    repeater_id: str | None = Query(default=None),
    site_id: str | None = Query(default=None),
    payload_type: str | None = Query(default=None),
    since: str | None = Query(default=None, description="5m, 1h, 24h, 7d"),
    limit: int = Query(default=200, ge=1, le=2000),
    _user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Liste persistierter Pakete, neueste zuerst, optional gefiltert."""
    target_site_id: UUID | None = None
    if repeater_id:
        try:
            rep_uuid = UUID(repeater_id)
        except ValueError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_400_BAD_REQUEST,
                detail="invalid repeater_id",
            ) from exc
        rep = await db.get(Repeater, rep_uuid)
        if rep is None:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND, detail="repeater not found"
            )
        target_site_id = rep.site_id
    elif site_id:
        try:
            target_site_id = UUID(site_id)
        except ValueError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_400_BAD_REQUEST, detail="invalid site_id"
            ) from exc

    stmt = select(RawPacket)
    if target_site_id is not None:
        stmt = stmt.where(RawPacket.site_id == target_site_id)
    if payload_type:
        stmt = stmt.where(RawPacket.payload_type == payload_type)
    if since:
        delta = _SINCE_PRESETS.get(since)
        if delta is None:
            raise HTTPException(
                status_code=http_status.HTTP_400_BAD_REQUEST,
                detail=f"invalid since (use one of {list(_SINCE_PRESETS)})",
            )
        cutoff = datetime.now(UTC) - delta
        stmt = stmt.where(RawPacket.ts >= cutoff)
    stmt = stmt.order_by(desc(RawPacket.ts)).limit(limit)

    rows = (await db.execute(stmt)).scalars().all()
    return {
        "packets": [_row_summary(r) for r in rows],
        "filters": {
            "repeater_id": repeater_id,
            "site_id": site_id,
            "payload_type": payload_type,
            "since": since,
            "limit": limit,
        },
    }


@router.get("/inspector/packets/{packet_id}")
async def inspector_packet_detail(
    packet_id: int,
    _user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    row = await db.get(RawPacket, packet_id)
    if row is None:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND)
    summary = _row_summary(row)
    raw = bytes(row.raw)
    # Header-Bit-Decode
    header = raw[0] if raw else 0
    decoded: dict[str, Any] = {
        "header_byte": f"0x{header:02X}" if raw else None,
        "header_bits": f"{header:08b}" if raw else None,
        "route_type_bits": header & 0b11 if raw else None,
        "payload_type_bits": (header >> 2) & 0b1111 if raw else None,
        "version": (header >> 6) & 0b11 if raw else None,
    }
    # Path-Bytes-Range (für Hex-Highlighting)
    region = {"header": [0, 1], "path_len": [1, 2]}
    if len(raw) >= 2:
        plen = raw[1]
        hash_size = ((plen >> 6) & 0b11) + 1
        hop_count = plen & 0b111111
        path_end = 2 + hash_size * hop_count
        region["path"] = [2, min(path_end, len(raw))]
        region["body"] = [min(path_end, len(raw)), len(raw)]
    decoded["regions"] = region

    # Re-parse für Konsistenz mit Live-Code (deckt Edge Cases ab)
    rp_route, rp_payload, rp_hashes, rp_advert = parse_packet_meta(raw)
    decoded["parsed"] = {
        "route_type": rp_route,
        "payload_type": rp_payload,
        "path_hashes": rp_hashes,
        "advert_pubkey": rp_advert,
    }

    try:
        forwarded = json.loads(row.forwarded_to)
    except json.JSONDecodeError:
        forwarded = []

    return {
        **summary,
        "raw_hex": raw.hex(),
        "decoded": decoded,
        "forwarded_to": forwarded,
    }


@router.get("/inspector/spool")
async def inspector_spool_stats(
    request: Request,
    _user: User = Depends(admin_required),
) -> dict[str, Any]:
    spool = getattr(request.app.state, "bridge_packet_spool", None)
    if spool is None:
        return {"enabled": False}
    return {"enabled": True, **spool.stats()}


@router.get("/inspector/stats")
async def inspector_stats(
    since: str = Query(default="24h"),
    _user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Aggregierte Pakete im Zeitfenster — global + per Repeater/Site.

    Quelle: ``raw_packets``-Tabelle (7-Tage-Spool). Nutzt die vorhandenen
    Indizes ``ix_raw_packets_ts`` und ``ix_raw_packets_site_ts``.
    """
    delta = _SINCE_PRESETS.get(since)
    if delta is None:
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail=f"invalid since (use one of {list(_SINCE_PRESETS)})",
        )
    cutoff = datetime.now(UTC) - delta
    raw_size = func.length(RawPacket.raw)

    total_row = (
        await db.execute(
            select(func.count(), func.coalesce(func.sum(raw_size), 0)).where(
                RawPacket.ts >= cutoff
            )
        )
    ).one()

    pt_rows = (
        await db.execute(
            select(
                RawPacket.payload_type,
                func.count(),
                func.coalesce(func.sum(raw_size), 0),
            )
            .where(RawPacket.ts >= cutoff)
            .group_by(RawPacket.payload_type)
            .order_by(desc(func.count()))
        )
    ).all()

    rt_rows = (
        await db.execute(
            select(RawPacket.route_type, func.count())
            .where(RawPacket.ts >= cutoff)
            .group_by(RawPacket.route_type)
            .order_by(desc(func.count()))
        )
    ).all()

    site_rows = (
        await db.execute(
            select(
                RawPacket.site_id,
                RawPacket.site_name,
                RawPacket.scope,
                func.count(),
                func.coalesce(func.sum(raw_size), 0),
                func.count(RawPacket.dropped_reason),
            )
            .where(RawPacket.ts >= cutoff)
            .group_by(RawPacket.site_id, RawPacket.site_name, RawPacket.scope)
            .order_by(desc(func.count()))
        )
    ).all()

    drop_rows = (
        await db.execute(
            select(RawPacket.dropped_reason, func.count())
            .where(RawPacket.ts >= cutoff, RawPacket.dropped_reason.is_not(None))
            .group_by(RawPacket.dropped_reason)
            .order_by(desc(func.count()))
        )
    ).all()

    return {
        "since": since,
        "cutoff": cutoff.isoformat(),
        "total": {"count": int(total_row[0]), "bytes": int(total_row[1])},
        "by_payload_type": [
            {"key": key, "count": int(count), "bytes": int(b)}
            for key, count, b in pt_rows
        ],
        "by_route_type": [
            {"key": key, "count": int(count)} for key, count in rt_rows
        ],
        "by_site": [
            {
                "site_id": str(site_id),
                "site_name": site_name,
                "scope": scope,
                "count": int(count),
                "bytes": int(b),
                "dropped": int(dropped),
            }
            for site_id, site_name, scope, count, b, dropped in site_rows
        ],
        "by_dropped_reason": [
            {"reason": reason, "count": int(count)} for reason, count in drop_rows
        ],
    }


@ui_router.get("/inspector", response_class=HTMLResponse)
async def inspector_page(
    request: Request,
    user: User = Depends(admin_required),
) -> HTMLResponse:
    return _templates(request).TemplateResponse(
        request,
        "admin_inspector.html.j2",
        {
            "user": user,
            "flash": None,
            "payload_types": list(PAYLOAD_TYPE_NAMES.values()),
            "route_types": list(ROUTE_TYPE_NAMES.values()),
        },
    )


@ui_router.get("/stats", response_class=HTMLResponse)
async def stats_page(
    request: Request,
    user: User = Depends(admin_required),
) -> HTMLResponse:
    return _templates(request).TemplateResponse(
        request,
        "admin_stats.html.j2",
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
