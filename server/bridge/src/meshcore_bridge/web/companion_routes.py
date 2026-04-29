"""Companion-Web-UI + REST.

Owner können hier ihre Companion-Identitäten verwalten und Nachrichten
senden / einsehen.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, select
from sqlalchemy import func as sa_func
from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncSession

from meshcore_bridge.db import (
    CompanionChannel,
    CompanionContact,
    CompanionIdentity,
    CompanionMessage,
    User,
)
from meshcore_bridge.web.deps import admin_required, current_user_required, get_db
from meshcore_companion.coords import cluster_outlier_mask, is_valid_coord

router = APIRouter(prefix="/api/v1/companion")
ui_router = APIRouter(prefix="/companion")
internal_router = APIRouter(prefix="/api/v1/internal/companion")


def _loopback_only(request: Request) -> None:
    """Hard-Block für alles außer 127.0.0.1 / ::1 / localhost.
    Traefik kommt im docker-Netz mit Bridge-IP (172.x.) → blockiert.
    docker exec curl aus demselben Container → 127.0.0.1 → erlaubt.
    Kein User-Cookie / kein Token — gedacht für admin-CLI vom Host."""
    host = (request.client.host if request.client else "") or ""
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(status_code=403, detail=f"loopback only (got {host!r})")


def _templates(request: Request) -> Jinja2Templates:
    return request.app.state.templates  # type: ignore[no-any-return]


def _service(request: Request):  # type: ignore[no-untyped-def]
    return getattr(request.app.state, "companion_service", None)


def _ts_iso(dt: datetime | None) -> str | None:
    """ISO-8601 mit garantiertem TZ-Suffix. SQLite-server_default speichert
    in UTC, gibt aber naive datetime zurück → ohne Suffix interpretiert
    der Browser als lokal und zeigt 2 h zu früh (CEST). Wir ergänzen UTC
    falls naive."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.isoformat()


def _identity_dict(row: CompanionIdentity) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "name": row.name,
        "scope": row.scope,
        "pubkey_hex": row.pubkey.hex(),
        "created_at": _ts_iso(row.created_at),
        "archived_at": _ts_iso(row.archived_at),
    }


# ---------- REST ----------


@router.get("/identities")
async def list_identities(
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> list[dict[str, Any]]:
    rows = list(
        (
            await db.execute(
                select(CompanionIdentity).where(
                    CompanionIdentity.user_id == user.id,
                    CompanionIdentity.archived_at.is_(None),
                )
            )
        ).scalars()
    )
    return [_identity_dict(r) for r in rows]


@router.post("/identities", response_model=None)
async def create_identity(
    request: Request,
    name: Annotated[str, Form()],
    scope: Annotated[str, Form()],
    user: User = Depends(current_user_required),
) -> dict[str, Any]:
    svc = _service(request)
    if svc is None:
        raise HTTPException(status_code=503, detail="companion-service not running")
    if scope == "pool:new":
        scope = f"pool:{uuid4()}"
    loaded = await svc.add_identity(user_id=user.id, name=name.strip(), scope=scope)
    return {
        "id": str(loaded.id),
        "name": loaded.name,
        "scope": loaded.scope,
        "pubkey_hex": loaded.pubkey.hex(),
    }


@router.post("/identities/{identity_id}/advert", response_model=None)
async def broadcast_advert(
    request: Request,
    identity_id: UUID,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Sofort einen Advert für diese Identity in den Scope pushen."""
    row = await db.get(CompanionIdentity, identity_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(status_code=404)
    svc = _service(request)
    if svc is None:
        raise HTTPException(status_code=503, detail="companion-service not running")
    loaded = svc.get(identity_id)
    if loaded is None:
        raise HTTPException(status_code=409, detail="identity not loaded in service")
    await svc._send_advert(loaded)
    return {"ok": True, "scope": loaded.scope}


@router.post("/identities/{identity_id}/archive", response_model=None)
async def archive_identity(
    request: Request,
    identity_id: UUID,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> dict[str, bool]:
    row = await db.get(CompanionIdentity, identity_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(status_code=404)
    svc = _service(request)
    if svc is None:
        raise HTTPException(status_code=503)
    ok = await svc.archive_identity(identity_id)
    return {"ok": ok}


@router.get("/messages")
async def list_messages(
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict[str, Any]]:
    # Join: nur eigene Identitäten
    own_ids = list(
        (
            await db.execute(
                select(CompanionIdentity.id).where(CompanionIdentity.user_id == user.id)
            )
        ).scalars()
    )
    if not own_ids:
        return []
    rows = list(
        (
            await db.execute(
                select(CompanionMessage)
                .where(CompanionMessage.identity_id.in_(own_ids))
                .order_by(desc(CompanionMessage.ts))
                .limit(limit)
            )
        ).scalars()
    )
    return [
        {
            "id": str(m.id),
            "identity_id": str(m.identity_id),
            "direction": m.direction,
            "payload_type": m.payload_type,
            "peer_pubkey": m.peer_pubkey.hex() if m.peer_pubkey else None,
            "peer_name": m.peer_name,
            "channel_name": m.channel_name,
            "text": m.text,
            "ts": _ts_iso(m.ts),
        }
        for m in rows
    ]


@router.post("/messages/dm", response_model=None)
async def send_dm(
    request: Request,
    identity_id: Annotated[UUID, Form()],
    peer_pubkey_hex: Annotated[str, Form()],
    text: Annotated[str, Form()],
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    row = await db.get(CompanionIdentity, identity_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(status_code=404)
    try:
        peer = bytes.fromhex(peer_pubkey_hex.strip())
    except ValueError as e:
        raise HTTPException(status_code=400, detail="bad pubkey hex") from e
    if len(peer) != 32:
        raise HTTPException(status_code=400, detail="pubkey must be 32 bytes")
    svc = _service(request)
    if svc is None:
        raise HTTPException(status_code=503)
    ok = await svc.send_dm(identity_id=identity_id, peer_pubkey=peer, text=text)
    return {"ok": ok, "ts": datetime.now(UTC).isoformat()}


@router.get("/contacts")
async def list_contacts(
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> list[dict[str, Any]]:
    own_ids = list(
        (
            await db.execute(
                select(CompanionIdentity.id).where(CompanionIdentity.user_id == user.id)
            )
        ).scalars()
    )
    if not own_ids:
        return []
    rows = list(
        (
            await db.execute(
                select(CompanionContact).where(CompanionContact.identity_id.in_(own_ids))
            )
        ).scalars()
    )
    return [
        {
            "identity_id": str(c.identity_id),
            "peer_pubkey": c.peer_pubkey.hex(),
            "peer_name": c.peer_name,
            "last_seen_at": _ts_iso(c.last_seen_at),
        }
        for c in rows
    ]


# ---------- Channels ----------


def _channel_dict(c: CompanionChannel) -> dict[str, Any]:
    return {
        "id": str(c.id),
        "identity_id": str(c.identity_id),
        "name": c.name,
        "channel_hash_hex": c.channel_hash.hex(),
        "created_at": _ts_iso(c.created_at),
    }


async def _user_owns_identity(db: AsyncSession, user_id: UUID, identity_id: UUID) -> bool:
    row = await db.get(CompanionIdentity, identity_id)
    return row is not None and row.user_id == user_id


@router.get("/channels")
async def list_channels(
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> list[dict[str, Any]]:
    own_ids = list(
        (
            await db.execute(
                select(CompanionIdentity.id).where(CompanionIdentity.user_id == user.id)
            )
        ).scalars()
    )
    if not own_ids:
        return []
    rows = list(
        (
            await db.execute(
                select(CompanionChannel).where(CompanionChannel.identity_id.in_(own_ids))
            )
        ).scalars()
    )
    return [_channel_dict(c) for c in rows]


@router.post("/channels", response_model=None)
async def create_channel(
    request: Request,
    identity_id: Annotated[UUID, Form()],
    name: Annotated[str, Form()],
    password: Annotated[str, Form()],
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    if not await _user_owns_identity(db, user.id, identity_id):
        raise HTTPException(status_code=404)
    svc = _service(request)
    if svc is None:
        raise HTTPException(status_code=503, detail="companion-service not running")
    channel = await svc.add_channel(identity_id=identity_id, name=name.strip(), password=password)
    if channel is None:
        raise HTTPException(status_code=409, detail="identity not loaded or duplicate name")
    return _channel_dict(channel)


@router.post("/messages/channel", response_model=None)
async def send_channel_message(
    request: Request,
    identity_id: Annotated[UUID, Form()],
    channel_id: Annotated[UUID, Form()],
    text: Annotated[str, Form()],
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    if not await _user_owns_identity(db, user.id, identity_id):
        raise HTTPException(status_code=404)
    svc = _service(request)
    if svc is None:
        raise HTTPException(status_code=503)
    ok = await svc.send_channel(identity_id=identity_id, channel_id=channel_id, text=text)
    if not ok:
        raise HTTPException(status_code=404, detail="channel not found")
    return {"ok": ok, "ts": datetime.now(UTC).isoformat()}


# ---------- Conversations (per identity) ----------


def _hop_count(raw: bytes | None) -> int | None:
    """Liest die Hop-Anzahl aus dem rohen MeshCore-Paket (path_len // hash_size).
    Eigene Out-Messages, Pakete ohne raw oder dekodier-Fehler → None."""
    if not raw:
        return None
    try:
        from meshcore_companion.packet import Packet as MCPacket  # noqa: PLC0415

        return MCPacket.decode(raw).hop_count
    except (ValueError, ImportError):
        return None


def _message_dict(m: CompanionMessage, *, room_sender_name: str | None = None) -> dict[str, Any]:
    return {
        "id": str(m.id),
        "direction": m.direction,
        "payload_type": m.payload_type,
        "peer_pubkey_hex": m.peer_pubkey.hex() if m.peer_pubkey else None,
        "peer_name": m.peer_name,
        "channel_name": m.channel_name,
        "text": m.text,
        "ts": _ts_iso(m.ts),
        "hops": _hop_count(m.raw),
        "room_sender_prefix_hex": (m.room_sender_pubkey.hex() if m.room_sender_pubkey else None),
        "room_sender_name": room_sender_name,
    }


async def _resolve_room_sender_names(
    db: AsyncSession,
    identity_id: UUID,
    messages: list[CompanionMessage],
) -> dict[bytes, str]:
    """Eine Subquery für alle in den Messages vorkommenden 4-Byte-Author-
    Prefixes — vermeidet N+1. Bei Prefix-Kollisionen gewinnt der Contact
    mit dem jüngsten last_seen_at."""
    prefixes = {bytes(m.room_sender_pubkey) for m in messages if m.room_sender_pubkey}
    if not prefixes:
        return {}
    rows = list(
        (
            await db.execute(
                select(CompanionContact).where(
                    CompanionContact.identity_id == identity_id,
                    sa_func.substr(CompanionContact.peer_pubkey, 1, 4).in_(prefixes),
                )
            )
        ).scalars()
    )
    out: dict[bytes, str] = {}
    out_seen: dict[bytes, datetime] = {}
    for c in rows:
        if not c.peer_name:
            continue
        prefix = bytes(c.peer_pubkey[:4])
        last = c.last_seen_at or datetime.min.replace(tzinfo=UTC)
        prev = out_seen.get(prefix)
        if prev is None or last > prev:
            out[prefix] = c.peer_name
            out_seen[prefix] = last
    return out


@router.get("/identities/{identity_id}/threads")
async def list_identity_threads(
    identity_id: UUID,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """DM-Threads (gruppiert nach peer_pubkey) und Channel-Threads für eine
    Identity. Channels erscheinen auch ohne Posts."""
    if not await _user_owns_identity(db, user.id, identity_id):
        raise HTTPException(status_code=404)

    # Top 100 Kontakte (mit Pubkey, sortiert nach last_seen DESC) — die
    # zeigen wir auch ohne aktiven Thread in der Sidebar, damit man neue
    # DMs direkt anstossen kann.
    contact_rows = list(
        (
            await db.execute(
                select(CompanionContact)
                .where(CompanionContact.identity_id == identity_id)
                .order_by(desc(CompanionContact.last_seen_at))
                .limit(100)
            )
        ).scalars()
    )
    channels = list(
        (
            await db.execute(
                select(CompanionChannel)
                .where(CompanionChannel.identity_id == identity_id)
                .order_by(CompanionChannel.name)
            )
        ).scalars()
    )

    # Letzte Nachricht pro peer / channel — Snippet für die Sidebar.
    msgs = list(
        (
            await db.execute(
                select(CompanionMessage)
                .where(CompanionMessage.identity_id == identity_id)
                .order_by(desc(CompanionMessage.ts))
                .limit(500)
            )
        ).scalars()
    )
    last_msg_by_peer: dict[bytes, CompanionMessage] = {}
    chan_last: dict[str, CompanionMessage] = {}
    for m in msgs:
        if m.peer_pubkey is not None and m.peer_pubkey not in last_msg_by_peer:
            last_msg_by_peer[m.peer_pubkey] = m
        elif m.peer_pubkey is None and m.channel_name and m.channel_name not in chan_last:
            chan_last[m.channel_name] = m

    dms: list[dict[str, Any]] = []
    for c in contact_rows:
        last = last_msg_by_peer.get(c.peer_pubkey)
        last_ts = _ts_iso(last.ts) if last else _ts_iso(c.last_seen_at)
        dms.append(
            {
                "id": str(c.id),
                "peer_pubkey_hex": c.peer_pubkey.hex(),
                "peer_name": c.peer_name,
                "favorite": bool(c.favorite),
                "node_type": c.node_type,
                "last_ts": last_ts,
                "last_text": last.text if last else None,
                "last_direction": last.direction if last else None,
            }
        )
    # Reihenfolge: Favoriten zuerst, innerhalb sortiert nach last_ts DESC.
    # Python sort() ist stable, daher zwei Pässe.
    dms.sort(key=lambda t: t["last_ts"] or "", reverse=True)
    dms.sort(key=lambda t: not t["favorite"])  # False sortiert vor True

    chan_rows = []
    for ch in channels:
        last = chan_last.get(ch.name)
        chan_rows.append(
            {
                "id": str(ch.id),
                "name": ch.name,
                "channel_hash_hex": ch.channel_hash.hex(),
                "last_ts": _ts_iso(last.ts) if last else None,
                "last_text": last.text if last else None,
                "last_direction": last.direction if last else None,
            }
        )
    chan_rows.sort(key=lambda c: c["last_ts"] or "", reverse=True)

    return {"dms": dms, "channels": chan_rows}


@router.get("/identities/{identity_id}/dms/{peer_pubkey_hex}")
async def list_dm_messages(
    identity_id: UUID,
    peer_pubkey_hex: str,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    before_ts: str | None = Query(default=None),
) -> dict[str, Any]:
    """Cursor-paginierte DM-History. Cursor = ``ts`` der ältesten
    bisherigen Page als ISO-String. Antwort enthält ``messages`` (älteste
    zuerst, zur direkten Anzeige) und ``next_cursor`` (älteste ts der Page
    oder ``null`` wenn weniger als ``limit`` zurückkam = Ende erreicht).
    """
    if not await _user_owns_identity(db, user.id, identity_id):
        raise HTTPException(status_code=404)
    try:
        peer = bytes.fromhex(peer_pubkey_hex.strip())
    except ValueError as e:
        raise HTTPException(status_code=400, detail="bad pubkey hex") from e
    if len(peer) != 32:
        raise HTTPException(status_code=400, detail="pubkey must be 32 bytes")

    q = (
        select(CompanionMessage)
        .where(
            CompanionMessage.identity_id == identity_id,
            CompanionMessage.peer_pubkey == peer,
        )
        .order_by(desc(CompanionMessage.ts))
        .limit(limit)
    )
    if before_ts:
        try:
            q = q.where(CompanionMessage.ts < datetime.fromisoformat(before_ts))
        except ValueError as e:
            raise HTTPException(status_code=400, detail="bad before_ts") from e
    rows = list((await db.execute(q)).scalars())
    next_cursor = _ts_iso(rows[-1].ts) if len(rows) == limit and rows else None
    rows.reverse()
    name_by_prefix = await _resolve_room_sender_names(db, identity_id, rows)
    return {
        "messages": [
            _message_dict(
                m,
                room_sender_name=(
                    name_by_prefix.get(bytes(m.room_sender_pubkey))
                    if m.room_sender_pubkey
                    else None
                ),
            )
            for m in rows
        ],
        "next_cursor": next_cursor,
    }


@router.get("/identities/{identity_id}/contacts")
async def list_identity_contacts(
    identity_id: UUID,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, Any]]:
    """Letzte ``limit`` Kontakte einer Identity (default 100), sortiert
    nach last_seen_at DESC. Frontend hebt Favoriten weiterhin via
    favorite-Flag hervor; Top-Reihenfolge ist aber Aktualität, nicht
    Favorit-Priorität — sonst würden alte Favoriten neue Mesh-Sender
    aus der Liste verdrängen."""
    if not await _user_owns_identity(db, user.id, identity_id):
        raise HTTPException(status_code=404)
    rows = list(
        (
            await db.execute(
                select(CompanionContact)
                .where(CompanionContact.identity_id == identity_id)
                .order_by(desc(CompanionContact.last_seen_at))
                .limit(limit)
            )
        ).scalars()
    )
    return [
        {
            "id": str(c.id),
            "peer_pubkey_hex": c.peer_pubkey.hex(),
            "peer_name": c.peer_name,
            "favorite": c.favorite,
            "last_seen_at": _ts_iso(c.last_seen_at),
            "lat": c.last_lat,
            "lon": c.last_lon,
        }
        for c in rows
    ]


@router.post("/identities/{identity_id}/contacts", response_model=None)
async def upsert_contact(
    identity_id: UUID,
    peer_pubkey_hex: Annotated[str, Form()],
    peer_name: Annotated[str, Form()] = "",
    favorite: Annotated[bool, Form()] = False,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Erzeugt oder aktualisiert einen CompanionContact ohne Mesh-Advert.
    Use case: User markiert einen aus Channel-Posts bekannten Sender (im
    AT_TARGETS-Pool, aber noch ohne DB-Row) als Favorit — der Klick legt
    den Contact an und setzt favorite=true gleichzeitig.

    Bei bestehendem Contact: peer_name nur überschreiben falls leer,
    favorite nur setzen wenn explizit ``favorite=true`` gesendet wird
    (kein versehentliches Demoten).
    """
    if not await _user_owns_identity(db, user.id, identity_id):
        raise HTTPException(status_code=404)
    try:
        peer = bytes.fromhex(peer_pubkey_hex.strip())
    except ValueError as e:
        raise HTTPException(status_code=400, detail="bad pubkey hex") from e
    if len(peer) != 32:
        raise HTTPException(status_code=400, detail="pubkey must be 32 bytes")

    contact = (
        await db.execute(
            select(CompanionContact).where(
                CompanionContact.identity_id == identity_id,
                CompanionContact.peer_pubkey == peer,
            )
        )
    ).scalar_one_or_none()
    name_clean = peer_name.strip() or None
    if contact is None:
        contact = CompanionContact(
            identity_id=identity_id,
            peer_pubkey=peer,
            peer_name=name_clean,
            last_seen_at=datetime.now(UTC),
            favorite=favorite,
        )
        db.add(contact)
    else:
        if name_clean and not contact.peer_name:
            contact.peer_name = name_clean
        if favorite:
            contact.favorite = True
    await db.commit()
    await db.refresh(contact)
    return {
        "id": str(contact.id),
        "peer_pubkey_hex": contact.peer_pubkey.hex(),
        "peer_name": contact.peer_name,
        "favorite": contact.favorite,
    }


@router.post("/contacts/{contact_id}/favorite", response_model=None)
async def toggle_contact_favorite_rest(
    contact_id: UUID,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """REST-Variante (JSON statt 303-Redirect) zum Favorit-Toggle —
    für Frontend-fetch ohne Page-Reload."""
    contact = await db.get(CompanionContact, contact_id)
    if contact is None:
        raise HTTPException(status_code=404)
    ident = await db.get(CompanionIdentity, contact.identity_id)
    if ident is None or ident.user_id != user.id:
        raise HTTPException(status_code=404)
    contact.favorite = not contact.favorite
    await db.commit()
    return {"id": str(contact.id), "favorite": contact.favorite}


async def _validate_peer_for_request(
    db: AsyncSession, user_id: UUID, identity_id: UUID, peer_pubkey_hex: str
) -> bytes:
    """Owns-Identity-Check + Pubkey-Hex-Parse. Hilft den /status- und
    /telemetry-Endpoints, identische Eingabe-Validierung zu teilen."""
    if not await _user_owns_identity(db, user_id, identity_id):
        raise HTTPException(status_code=404)
    try:
        peer = bytes.fromhex(peer_pubkey_hex.strip())
    except ValueError as e:
        raise HTTPException(status_code=400, detail="bad pubkey hex") from e
    if len(peer) != 32:
        raise HTTPException(status_code=400, detail="pubkey must be 32 bytes")
    return peer


@router.post("/identities/{identity_id}/contacts/{peer_pubkey_hex}/telemetry", response_model=None)
async def request_contact_telemetry(
    request: Request,
    identity_id: UUID,
    peer_pubkey_hex: str,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Schickt einen REQ_TYPE_GET_TELEMETRY_DATA an den angegebenen Peer.
    Antwort kommt asynchron zurück und füllt last_lat/last_lon, falls
    der Peer LPP_GPS in der Telemetrie liefert."""
    peer = await _validate_peer_for_request(db, user.id, identity_id, peer_pubkey_hex)
    svc = _service(request)
    if svc is None:
        raise HTTPException(status_code=503, detail="companion-service not running")
    ok = await svc.request_telemetry(identity_id=identity_id, peer_pubkey=peer)
    if not ok:
        raise HTTPException(status_code=409, detail="identity not loaded in service")
    return {"ok": True, "ts": datetime.now(UTC).isoformat()}


@router.post("/identities/{identity_id}/contacts/{peer_pubkey_hex}/login", response_model=None)
async def request_contact_login(
    request: Request,
    identity_id: UUID,
    peer_pubkey_hex: str,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
    password: Annotated[str, Form()] = "",
) -> dict[str, Any]:
    """ANON_REQ-Login bei einem Repeater. Voraussetzung dafür, dass dieser
    auf nachfolgende REQ_TYPE_GET_STATUS / GET_TELEMETRY_DATA antwortet —
    Repeater verwerfen REQs von unbekannten Sendern (ACL-Check).
    Leeres Passwort = Guest-Login (bei den meisten Repeatern OK)."""
    peer = await _validate_peer_for_request(db, user.id, identity_id, peer_pubkey_hex)
    svc = _service(request)
    if svc is None:
        raise HTTPException(status_code=503, detail="companion-service not running")
    ok = await svc.request_login(identity_id=identity_id, peer_pubkey=peer, password=password)
    if not ok:
        raise HTTPException(status_code=409, detail="identity not loaded in service")
    return {"ok": True, "ts": datetime.now(UTC).isoformat()}


@router.get(
    "/identities/{identity_id}/contacts/{peer_pubkey_hex}/login-state",
    response_model=None,
)
async def get_contact_login_state(
    request: Request,
    identity_id: UUID,
    peer_pubkey_hex: str,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Aktueller in-memory Login-Status für (Identity, Peer). Wird vom
    Companion-Frontend gepollt, um „eingeloggt"-Pill am Konvo-Header zu
    rendern. Geht beim Container-Restart verloren — Werte sind eine
    Heuristik, kein verlässlicher Server-Vertrag."""
    peer = await _validate_peer_for_request(db, user.id, identity_id, peer_pubkey_hex)
    svc = _service(request)
    if svc is None:
        raise HTTPException(status_code=503, detail="companion-service not running")
    session = svc.get_login_session(identity_id, peer)
    if session is None:
        return {"logged_in": False}
    expires_in_s = max(0, int(session.expires_at - time.monotonic()))
    expires_at = (datetime.now(UTC) + timedelta(seconds=expires_in_s)).isoformat()
    return {
        "logged_in": True,
        "expires_at": expires_at,
        "is_admin": session.is_admin,
        "permissions": session.permissions,
    }


@router.post("/identities/{identity_id}/contacts/{peer_pubkey_hex}/status", response_model=None)
async def request_contact_status(
    request: Request,
    identity_id: UUID,
    peer_pubkey_hex: str,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Schickt einen REQ_TYPE_GET_STATUS — wirkt wie ein Ping mit Stats.
    Antwort kommt asynchron zurück: System-Message in der Konvo + SSE-Event
    ``status_response`` mit ``rtt_ms`` und ``stats``."""
    peer = await _validate_peer_for_request(db, user.id, identity_id, peer_pubkey_hex)
    svc = _service(request)
    if svc is None:
        raise HTTPException(status_code=503, detail="companion-service not running")
    ok = await svc.request_status(identity_id=identity_id, peer_pubkey=peer)
    if not ok:
        raise HTTPException(status_code=409, detail="identity not loaded in service")
    return {"ok": True, "ts": datetime.now(UTC).isoformat()}


@router.get("/identities/{identity_id}/map")
async def list_identity_map_pins(
    identity_id: UUID,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
    hours: int = Query(default=168, ge=1, le=8760),
    include_outliers: bool = Query(default=False),
) -> list[dict[str, Any]]:
    """Bekannte Kontakte mit Geokoordinaten, deren letzter Advert
    innerhalb der letzten ``hours`` Stunden eintraf (default 168h = 7
    Tage). Begrenzung verhindert, dass alte/abgewanderte Knoten die
    Karte vollmüllen.

    Filter:
    - Hard-Filter via ``is_valid_coord`` (Range, NaN/Inf, Null-Insel)
    - Cluster-Filter via ``cluster_outlier_mask`` (Distanz zum Median).
      Beide deaktivierbar mit ``include_outliers=1`` (Debug)."""
    if not await _user_owns_identity(db, user.id, identity_id):
        raise HTTPException(status_code=404)
    cutoff = datetime.now(UTC) - timedelta(hours=hours)
    rows = list(
        (
            await db.execute(
                select(CompanionContact).where(
                    CompanionContact.identity_id == identity_id,
                    CompanionContact.last_lat.is_not(None),
                    CompanionContact.last_lon.is_not(None),
                    CompanionContact.last_seen_at >= cutoff,
                )
            )
        ).scalars()
    )
    if not include_outliers:
        rows = [r for r in rows if is_valid_coord(r.last_lat, r.last_lon)]
        mask = cluster_outlier_mask(
            [(r.last_lat, r.last_lon) for r in rows]  # type: ignore[misc]
        )
        rows = [r for r, outlier in zip(rows, mask, strict=True) if not outlier]
    return [
        {
            "peer_pubkey_hex": c.peer_pubkey.hex(),
            "peer_name": c.peer_name,
            "lat": c.last_lat,
            "lon": c.last_lon,
            "favorite": c.favorite,
            "last_seen_at": _ts_iso(c.last_seen_at),
        }
        for c in rows
    ]


@router.post("/admin/identities/{identity_id}/cleanup-coords")
async def admin_cleanup_coords(
    identity_id: UUID,
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db),
    dry_run: bool = Query(default=True),
) -> dict[str, Any]:
    """Setzt unplausible ``last_lat``/``last_lon`` einer Identity auf
    NULL. Dry-Run liefert nur die Liste der Kandidaten zurück.

    Plausibilität: Hard-Filter (Range/NaN/Null-Insel) plus Cluster-
    Filter über die aktuell gültigen Punkte (Median-Distanz)."""
    del user  # nur für Admin-Auth
    rows = list(
        (
            await db.execute(
                select(CompanionContact).where(
                    CompanionContact.identity_id == identity_id,
                    CompanionContact.last_lat.is_not(None),
                    CompanionContact.last_lon.is_not(None),
                )
            )
        ).scalars()
    )
    invalid = [r for r in rows if not is_valid_coord(r.last_lat, r.last_lon)]
    valid = [r for r in rows if is_valid_coord(r.last_lat, r.last_lon)]
    mask = cluster_outlier_mask(
        [(r.last_lat, r.last_lon) for r in valid]  # type: ignore[misc]
    )
    cluster_outliers = [r for r, outlier in zip(valid, mask, strict=True) if outlier]
    candidates = invalid + cluster_outliers

    payload: dict[str, Any] = {
        "identity_id": str(identity_id),
        "dry_run": dry_run,
        "considered": len(rows),
        "invalid": len(invalid),
        "cluster_outliers": len(cluster_outliers),
        "candidates": [
            {
                "peer_pubkey_hex": c.peer_pubkey.hex(),
                "peer_name": c.peer_name,
                "lat": c.last_lat,
                "lon": c.last_lon,
                "reason": "invalid"
                if not is_valid_coord(c.last_lat, c.last_lon)
                else "cluster_outlier",
            }
            for c in candidates
        ],
    }
    if dry_run:
        return payload
    for c in candidates:
        c.last_lat = None
        c.last_lon = None
    await db.commit()
    payload["applied"] = len(candidates)
    return payload


@router.get("/identities/{identity_id}/channels/{channel_id}/messages")
async def list_channel_messages(
    identity_id: UUID,
    channel_id: UUID,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    before_ts: str | None = Query(default=None),
) -> dict[str, Any]:
    """Wie list_dm_messages, aber für einen Channel."""
    if not await _user_owns_identity(db, user.id, identity_id):
        raise HTTPException(status_code=404)
    channel = await db.get(CompanionChannel, channel_id)
    if channel is None or channel.identity_id != identity_id:
        raise HTTPException(status_code=404)

    q = (
        select(CompanionMessage)
        .where(
            CompanionMessage.identity_id == identity_id,
            CompanionMessage.peer_pubkey.is_(None),
            CompanionMessage.channel_name == channel.name,
        )
        .order_by(desc(CompanionMessage.ts))
        .limit(limit)
    )
    if before_ts:
        try:
            q = q.where(CompanionMessage.ts < datetime.fromisoformat(before_ts))
        except ValueError as e:
            raise HTTPException(status_code=400, detail="bad before_ts") from e
    rows = list((await db.execute(q)).scalars())
    next_cursor = _ts_iso(rows[-1].ts) if len(rows) == limit and rows else None
    rows.reverse()
    return {
        "messages": [_message_dict(m) for m in rows],
        "next_cursor": next_cursor,
    }


# ---------- Volltext-Suche (FTS5) ----------


@router.get("/identities/{identity_id}/search")
async def search_messages(
    identity_id: UUID,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
    q: str = Query(..., min_length=2, max_length=200),
    limit: int = Query(default=30, ge=1, le=100),
) -> dict[str, Any]:
    """FTS5-Volltext-Suche über companion_messages.text der Identity.
    Liefert Hits mit ``snippet`` (server-side <mark>...</mark>) plus
    Konvo-Kontext (DM-peer / channel) zum Springen im Frontend.
    """
    if not await _user_owns_identity(db, user.id, identity_id):
        raise HTTPException(status_code=404)

    # FTS5 MATCH-Syntax: einfache Suchterms erlauben, aber Anführungs-/
    # Spezialzeichen escapen (in Phrase wrappen). Wir verwenden quoted
    # phrase pro Token, durch Whitespace getrennt — robust gegen
    # User-Input.
    tokens = [t.replace('"', "") for t in q.strip().split() if t.strip()]
    if not tokens:
        raise HTTPException(status_code=400, detail="empty query")
    fts_query = " ".join(f'"{t}"' for t in tokens)

    sql = sql_text(
        """
        SELECT msg_id, identity_id, peer_pubkey, peer_name,
               channel_name, ts, direction,
               snippet(companion_messages_fts, 0, '<mark>', '</mark>', '…', 16) AS snippet
        FROM companion_messages_fts
        WHERE companion_messages_fts MATCH :q
          AND identity_id = :identity_id
        ORDER BY ts DESC
        LIMIT :limit
        """
    )
    rows = (
        (
            await db.execute(
                sql,
                {"q": fts_query, "identity_id": identity_id.bytes, "limit": limit},
            )
        )
        .mappings()
        .all()
    )

    # Pro Channel müssen wir die channel_id auflösen (Frontend springt per id).
    channel_ids: dict[str, str] = {}
    if any(r["channel_name"] for r in rows):
        ch_rows = list(
            (
                await db.execute(
                    select(CompanionChannel.id, CompanionChannel.name).where(
                        CompanionChannel.identity_id == identity_id
                    )
                )
            ).all()
        )
        channel_ids = {name: str(cid) for cid, name in ch_rows}

    hits: list[dict[str, Any]] = []
    for r in rows:
        msg_id_b = r["msg_id"]
        peer_b = r["peer_pubkey"]
        ch_name = r["channel_name"]
        is_dm = peer_b is not None
        # ts ist als ISO-String mit/ohne TZ in der UNINDEXED-Spalte gelandet
        # (SQLite serialisiert DateTime so). Wir lassen ihn 1:1 durch.
        hit: dict[str, Any] = {
            "id": _bytes_to_uuid_str(msg_id_b),
            "kind": "dm" if is_dm else "channel",
            "ts": r["ts"],
            "direction": r["direction"],
            "snippet": r["snippet"],
        }
        if is_dm:
            hit["peer_pubkey_hex"] = peer_b.hex()
            hit["peer_name"] = r["peer_name"]
        else:
            hit["channel_name"] = ch_name
            hit["channel_id"] = channel_ids.get(ch_name)
        hits.append(hit)

    return {"hits": hits}


def _bytes_to_uuid_str(b: bytes | None) -> str | None:
    if b is None:
        return None
    if isinstance(b, bytes) and len(b) == 16:
        return str(UUID(bytes=b))
    return str(b)


# ---------- Loopback-Admin-Scan ----------


@internal_router.post("/{identity_id}/scan", response_model=None)
async def internal_companion_scan(
    request: Request,
    identity_id: UUID,
    _: None = Depends(_loopback_only),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=10, ge=1, le=50),
    max_age_hours: int = Query(default=2, ge=1, le=72),
    delay_ms: int = Query(default=800, ge=100, le=10000),
    actions: str = Query(default="login,status"),
    name_like: str | None = Query(default=None),
) -> dict[str, Any]:
    """Triggert für die Top-``limit`` Kontakte einer Identity (sortiert nach
    last_seen DESC, jünger als ``max_age_hours``) sequenziell die in
    ``actions`` aufgelisteten REQs (login, status, telemetry). Pause
    ``delay_ms`` zwischen Requests, damit das Mesh-Burst nicht überfährt.
    Optional ``name_like`` filtert peer_name case-insensitive (Substring).
    Kein Cookie/Token nötig — Loopback-only."""
    svc = _service(request)
    if svc is None:
        raise HTTPException(status_code=503, detail="companion-service not running")

    ident = await db.get(CompanionIdentity, identity_id)
    if ident is None:
        raise HTTPException(status_code=404)

    cutoff = datetime.now(UTC) - timedelta(hours=max_age_hours)
    stmt = (
        select(CompanionContact)
        .where(
            CompanionContact.identity_id == identity_id,
            CompanionContact.last_seen_at >= cutoff,
        )
        .order_by(desc(CompanionContact.last_seen_at))
        .limit(limit)
    )
    if name_like:
        # SQLite-LIKE ist case-insensitive für ASCII; für Umlaute
        # exakt sein zu wollen wäre overkill für eine Diagnose-CLI.
        stmt = stmt.where(CompanionContact.peer_name.ilike(f"%{name_like}%"))
    rows = list((await db.execute(stmt)).scalars())

    valid_actions = [a.strip() for a in actions.split(",") if a.strip()]
    targets: list[dict[str, Any]] = []
    for c in rows:
        triggered: list[str] = []
        for action in valid_actions:
            try:
                if action == "login":
                    await svc.request_login(identity_id=identity_id, peer_pubkey=c.peer_pubkey)
                elif action == "status":
                    await svc.request_status(identity_id=identity_id, peer_pubkey=c.peer_pubkey)
                elif action == "telemetry":
                    await svc.request_telemetry(identity_id=identity_id, peer_pubkey=c.peer_pubkey)
                else:
                    continue
                triggered.append(action)
            except Exception as e:  # pragma: no cover — diagnose only
                msg = str(e)[:40]
                triggered.append(f"{action}:err({msg})")
            await asyncio.sleep(delay_ms / 1000.0)
        targets.append(
            {
                "peer_name": c.peer_name,
                "peer_pubkey_hex": c.peer_pubkey.hex(),
                "last_seen_at": _ts_iso(c.last_seen_at),
                "triggered": triggered,
            }
        )

    return {
        "identity": ident.name,
        "scanned": len(targets),
        "targets": targets,
    }


# ---------- SSE Push-Stream ----------


@router.get("/identities/{identity_id}/stream")
async def companion_stream(
    request: Request,
    identity_id: UUID,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """text/event-stream — ein offener SSE-Channel pro Browser-Tab. Wir
    pushen DM-/Channel-Empfang, Sent-Echos und Contact-Updates."""
    if not await _user_owns_identity(db, user.id, identity_id):
        raise HTTPException(status_code=404)
    bus = getattr(request.app.state, "companion_events", None)
    if bus is None:
        raise HTTPException(status_code=503, detail="event-bus not available")

    queue: asyncio.Queue[dict[str, Any]] = bus.subscribe(identity_id)

    async def gen() -> AsyncIterator[bytes]:
        try:
            # Initialer Comment, damit der Browser sofort 200 sieht.
            yield b": ok\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    evt = await asyncio.wait_for(queue.get(), timeout=20.0)
                except TimeoutError:
                    yield b": keep-alive\n\n"
                    continue
                payload = json.dumps(evt, separators=(",", ":")).encode("utf-8")
                yield b"data: " + payload + b"\n\n"
        finally:
            bus.unsubscribe(identity_id, queue)

    headers = {
        "Cache-Control": "no-cache, no-transform",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    }
    return StreamingResponse(gen(), media_type="text/event-stream", headers=headers)


# ---------- UI ----------


@ui_router.get("/", response_class=HTMLResponse)
async def companion_index(
    request: Request,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    identities = list(
        (
            await db.execute(
                select(CompanionIdentity)
                .where(
                    CompanionIdentity.user_id == user.id,
                    CompanionIdentity.archived_at.is_(None),
                )
                .order_by(CompanionIdentity.created_at)
            )
        ).scalars()
    )
    return _templates(request).TemplateResponse(
        request,
        "companion_index.html.j2",
        {
            "user": user,
            "identities": identities,
            "flash": None,
        },
    )


@ui_router.post("/identities", response_model=None)
async def companion_identity_create(
    request: Request,
    name: Annotated[str, Form()],
    scope: Annotated[str, Form()],
    user: User = Depends(current_user_required),
) -> RedirectResponse:
    svc = _service(request)
    if svc is None:
        raise HTTPException(status_code=503)
    actual_scope = f"pool:{uuid4()}" if scope == "pool:new" else scope
    await svc.add_identity(user_id=user.id, name=name.strip(), scope=actual_scope)
    return RedirectResponse(url="/companion/", status_code=303)


@ui_router.post("/contacts/{contact_id}/favorite", response_model=None)
async def companion_contact_toggle_favorite(
    contact_id: UUID,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    contact = await db.get(CompanionContact, contact_id)
    if contact is None:
        raise HTTPException(status_code=404)
    ident = await db.get(CompanionIdentity, contact.identity_id)
    if ident is None or ident.user_id != user.id:
        raise HTTPException(status_code=404)
    contact.favorite = not contact.favorite
    await db.commit()
    return RedirectResponse(url="/companion/", status_code=303)


@ui_router.get("/{identity_id}/", response_class=HTMLResponse)
async def companion_detail(
    request: Request,
    identity_id: UUID,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    identity = await db.get(CompanionIdentity, identity_id)
    if identity is None or identity.user_id != user.id:
        raise HTTPException(status_code=404)
    channels = list(
        (
            await db.execute(
                select(CompanionChannel)
                .where(CompanionChannel.identity_id == identity_id)
                .order_by(CompanionChannel.name)
            )
        ).scalars()
    )

    # @-Reply-Targets: bekannte Namen für Auto-Complete im Compose-Feld.
    # Quelle: DM-Kontakte (Pubkey + Name) plus distinct sender_names aus
    # Channel-Posts (nur Name; Channel-Posts haben kryptographisch keinen
    # Pubkey, "@[Name]" ist eine reine Anzeigekonvention).
    contact_rows = list(
        (
            await db.execute(
                select(CompanionContact).where(CompanionContact.identity_id == identity_id)
            )
        ).scalars()
    )
    chan_sender_rows = list(
        (
            await db.execute(
                select(CompanionMessage.peer_name)
                .where(
                    CompanionMessage.identity_id == identity_id,
                    CompanionMessage.channel_name.is_not(None),
                    CompanionMessage.peer_name.is_not(None),
                )
                .distinct()
            )
        ).scalars()
    )
    seen: set[str] = set()
    at_targets: list[dict[str, Any]] = []
    for c in contact_rows:
        if not c.peer_name:
            continue
        key = c.peer_name.lower()
        if key in seen:
            continue
        seen.add(key)
        # contact_id + favorite mitgeben — sonst fällt das Frontend bei
        # alten Kontakten (nicht in den Top-100 von /threads) auf einen
        # AT_TARGETS-Pseudo-Eintrag mit favorite=false zurück, der den
        # echten DB-Stand maskiert.
        at_targets.append(
            {
                "name": c.peer_name,
                "pubkey_hex": c.peer_pubkey.hex(),
                "contact_id": str(c.id),
                "favorite": bool(c.favorite),
                "node_type": c.node_type,
            }
        )
    for name in chan_sender_rows:
        if not name:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        at_targets.append({"name": name, "pubkey_hex": None, "contact_id": None, "favorite": False})
    at_targets.sort(key=lambda t: t["name"].lower())

    return _templates(request).TemplateResponse(
        request,
        "companion_detail.html.j2",
        {
            "user": user,
            "identity": identity,
            "channels": channels,
            "at_targets": at_targets,
            "flash": None,
        },
    )


@ui_router.post("/{identity_id}/rename", response_model=None)
async def companion_identity_rename(
    request: Request,
    identity_id: UUID,
    name: Annotated[str, Form()],
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    if not await _user_owns_identity(db, user.id, identity_id):
        raise HTTPException(status_code=404)
    svc = _service(request)
    if svc is None:
        raise HTTPException(status_code=503)
    if not await svc.rename_identity(identity_id, name):
        raise HTTPException(status_code=400, detail="invalid name")
    return RedirectResponse(url=f"/companion/{identity_id}/#tab=settings", status_code=303)


@ui_router.post("/{identity_id}/advert", response_model=None)
async def companion_identity_advert(
    request: Request,
    identity_id: UUID,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    if not await _user_owns_identity(db, user.id, identity_id):
        raise HTTPException(status_code=404)
    svc = _service(request)
    if svc is None:
        raise HTTPException(status_code=503)
    loaded = svc.get(identity_id)
    if loaded is None:
        raise HTTPException(status_code=409, detail="identity not loaded in service")
    await svc._send_advert(loaded)
    return RedirectResponse(url=f"/companion/{identity_id}/#tab=settings", status_code=303)


@ui_router.post("/{identity_id}/archive", response_model=None)
async def companion_identity_archive(
    request: Request,
    identity_id: UUID,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    if not await _user_owns_identity(db, user.id, identity_id):
        raise HTTPException(status_code=404)
    svc = _service(request)
    if svc is None:
        raise HTTPException(status_code=503)
    await svc.archive_identity(identity_id)
    return RedirectResponse(url="/companion/", status_code=303)


@ui_router.post("/{identity_id}/channels", response_model=None)
async def companion_identity_channel_create(
    request: Request,
    identity_id: UUID,
    name: Annotated[str, Form()],
    password: Annotated[str, Form()],
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    if not await _user_owns_identity(db, user.id, identity_id):
        raise HTTPException(status_code=404)
    svc = _service(request)
    if svc is None:
        raise HTTPException(status_code=503)
    await svc.add_channel(identity_id=identity_id, name=name.strip(), password=password)
    return RedirectResponse(url=f"/companion/{identity_id}/#tab=settings", status_code=303)


@ui_router.post("/channels/{channel_id}/delete", response_model=None)
async def companion_channel_delete(
    request: Request,
    channel_id: UUID,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    channel = await db.get(CompanionChannel, channel_id)
    if channel is None:
        raise HTTPException(status_code=404)
    ident = await db.get(CompanionIdentity, channel.identity_id)
    if ident is None or ident.user_id != user.id:
        raise HTTPException(status_code=404)
    svc = _service(request)
    if svc is None:
        raise HTTPException(status_code=503)
    identity_id = channel.identity_id
    await svc.delete_channel(channel_id)
    return RedirectResponse(url=f"/companion/{identity_id}/#tab=settings", status_code=303)
