"""Companion-Web-UI + REST.

Owner können hier ihre Companion-Identitäten verwalten und Nachrichten
senden / einsehen.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from meshcore_bridge.db import (
    CompanionChannel,
    CompanionContact,
    CompanionIdentity,
    CompanionMessage,
    User,
)
from meshcore_bridge.web.deps import current_user_required, get_db

router = APIRouter(prefix="/api/v1/companion")
ui_router = APIRouter(prefix="/companion")


def _templates(request: Request) -> Jinja2Templates:
    return request.app.state.templates  # type: ignore[no-any-return]


def _service(request: Request):  # type: ignore[no-untyped-def]
    return getattr(request.app.state, "companion_service", None)


def _identity_dict(row: CompanionIdentity) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "name": row.name,
        "scope": row.scope,
        "pubkey_hex": row.pubkey.hex(),
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "archived_at": row.archived_at.isoformat() if row.archived_at else None,
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
            "ts": m.ts.isoformat() if m.ts else None,
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
            "last_seen_at": c.last_seen_at.isoformat() if c.last_seen_at else None,
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
        "created_at": c.created_at.isoformat() if c.created_at else None,
    }


async def _user_owns_identity(
    db: AsyncSession, user_id: UUID, identity_id: UUID
) -> bool:
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
    channel = await svc.add_channel(
        identity_id=identity_id, name=name.strip(), password=password
    )
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
    ok = await svc.send_channel(
        identity_id=identity_id, channel_id=channel_id, text=text
    )
    if not ok:
        raise HTTPException(status_code=404, detail="channel not found")
    return {"ok": ok, "ts": datetime.now(UTC).isoformat()}


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
                select(CompanionIdentity).where(
                    CompanionIdentity.user_id == user.id,
                    CompanionIdentity.archived_at.is_(None),
                )
            )
        ).scalars()
    )
    own_ids = [i.id for i in identities]
    contacts: list[CompanionContact] = []
    channels: list[CompanionChannel] = []
    if own_ids:
        contacts = list(
            (
                await db.execute(
                    select(CompanionContact)
                    .where(CompanionContact.identity_id.in_(own_ids))
                    .order_by(desc(CompanionContact.last_seen_at))
                )
            ).scalars()
        )
        channels = list(
            (
                await db.execute(
                    select(CompanionChannel)
                    .where(CompanionChannel.identity_id.in_(own_ids))
                    .order_by(CompanionChannel.name)
                )
            ).scalars()
        )

    contacts_by_identity: dict[str, list[dict[str, Any]]] = {}
    for c in contacts:
        contacts_by_identity.setdefault(str(c.identity_id), []).append(
            {
                "peer_pubkey_hex": c.peer_pubkey.hex(),
                "peer_name": c.peer_name,
                "last_seen_at": c.last_seen_at.isoformat() if c.last_seen_at else None,
            }
        )
    channels_by_identity: dict[str, list[dict[str, Any]]] = {}
    identity_names: dict[str, str] = {str(i.id): i.name for i in identities}
    for ch in channels:
        channels_by_identity.setdefault(str(ch.identity_id), []).append(
            {
                "id": str(ch.id),
                "name": ch.name,
                "channel_hash_hex": ch.channel_hash.hex(),
            }
        )

    return _templates(request).TemplateResponse(
        request,
        "companion_index.html.j2",
        {
            "user": user,
            "identities": identities,
            "contacts_by_identity": contacts_by_identity,
            "channels_by_identity": channels_by_identity,
            "channels": channels,
            "identity_names": identity_names,
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


@ui_router.post("/identities/{identity_id}/advert", response_model=None)
async def companion_advert_send(
    request: Request,
    identity_id: UUID,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    row = await db.get(CompanionIdentity, identity_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(status_code=404)
    svc = _service(request)
    if svc is None:
        raise HTTPException(status_code=503)
    loaded = svc.get(identity_id)
    if loaded is None:
        raise HTTPException(status_code=409, detail="identity not loaded in service")
    await svc._send_advert(loaded)
    return RedirectResponse(url="/companion/", status_code=303)


@ui_router.post("/messages/dm", response_model=None)
async def companion_dm_send(
    request: Request,
    identity_id: Annotated[UUID, Form()],
    peer_pubkey_hex: Annotated[str, Form()],
    text: Annotated[str, Form()],
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
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
    await svc.send_dm(identity_id=identity_id, peer_pubkey=peer, text=text)
    return RedirectResponse(url="/companion/", status_code=303)


@ui_router.post("/channels", response_model=None)
async def companion_channel_create(
    request: Request,
    identity_id: Annotated[UUID, Form()],
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
    return RedirectResponse(url="/companion/", status_code=303)


@ui_router.post("/messages/channel", response_model=None)
async def companion_channel_send(
    request: Request,
    identity_id: Annotated[UUID, Form()],
    channel_id: Annotated[UUID, Form()],
    text: Annotated[str, Form()],
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    if not await _user_owns_identity(db, user.id, identity_id):
        raise HTTPException(status_code=404)
    svc = _service(request)
    if svc is None:
        raise HTTPException(status_code=503)
    await svc.send_channel(identity_id=identity_id, channel_id=channel_id, text=text)
    return RedirectResponse(url="/companion/", status_code=303)
