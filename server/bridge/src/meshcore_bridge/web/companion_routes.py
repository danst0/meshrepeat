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


# ---------- Conversations (per identity) ----------


def _message_dict(m: CompanionMessage) -> dict[str, Any]:
    return {
        "id": str(m.id),
        "direction": m.direction,
        "payload_type": m.payload_type,
        "peer_pubkey_hex": m.peer_pubkey.hex() if m.peer_pubkey else None,
        "peer_name": m.peer_name,
        "channel_name": m.channel_name,
        "text": m.text,
        "ts": m.ts.isoformat() if m.ts else None,
    }


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

    msgs = list(
        (
            await db.execute(
                select(CompanionMessage)
                .where(CompanionMessage.identity_id == identity_id)
                .order_by(desc(CompanionMessage.ts))
            )
        ).scalars()
    )
    contacts = list(
        (
            await db.execute(
                select(CompanionContact).where(
                    CompanionContact.identity_id == identity_id
                )
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
    contacts_by_pk: dict[bytes, CompanionContact] = {
        c.peer_pubkey: c for c in contacts
    }

    dm_seen: dict[bytes, dict[str, Any]] = {}
    chan_last: dict[str, CompanionMessage] = {}
    for m in msgs:
        if m.peer_pubkey is not None and m.peer_pubkey not in dm_seen:
            contact = contacts_by_pk.get(m.peer_pubkey)
            dm_seen[m.peer_pubkey] = {
                "peer_pubkey_hex": m.peer_pubkey.hex(),
                "peer_name": (contact.peer_name if contact else None) or m.peer_name,
                "favorite": bool(contact and contact.favorite),
                "last_ts": m.ts.isoformat() if m.ts else None,
                "last_text": m.text,
                "last_direction": m.direction,
            }
        if (
            m.peer_pubkey is None
            and m.channel_name
            and m.channel_name not in chan_last
        ):
            chan_last[m.channel_name] = m

    # Auch Kontakte ohne Nachrichten sichtbar machen (mind. Favoriten),
    # damit man als Erster eine DM starten kann.
    for c in contacts:
        if c.peer_pubkey in dm_seen:
            continue
        if not c.favorite:
            continue
        dm_seen[c.peer_pubkey] = {
            "peer_pubkey_hex": c.peer_pubkey.hex(),
            "peer_name": c.peer_name,
            "favorite": True,
            "last_ts": c.last_seen_at.isoformat() if c.last_seen_at else None,
            "last_text": None,
            "last_direction": None,
        }

    dms = list(dm_seen.values())
    dms.sort(key=lambda t: t["last_ts"] or "", reverse=True)
    dms.sort(key=lambda t: not t["favorite"])  # stable: favorites first

    chan_rows = []
    for ch in channels:
        last = chan_last.get(ch.name)
        chan_rows.append(
            {
                "id": str(ch.id),
                "name": ch.name,
                "channel_hash_hex": ch.channel_hash.hex(),
                "last_ts": last.ts.isoformat() if last and last.ts else None,
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
    limit: int = Query(default=200, ge=1, le=1000),
    since: str | None = Query(default=None),
) -> list[dict[str, Any]]:
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
    if since:
        try:
            q = q.where(CompanionMessage.ts > datetime.fromisoformat(since))
        except ValueError as e:
            raise HTTPException(status_code=400, detail="bad since") from e
    rows = list((await db.execute(q)).scalars())
    rows.reverse()
    return [_message_dict(m) for m in rows]


@router.get("/identities/{identity_id}/channels/{channel_id}/messages")
async def list_channel_messages(
    identity_id: UUID,
    channel_id: UUID,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=200, ge=1, le=1000),
    since: str | None = Query(default=None),
) -> list[dict[str, Any]]:
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
    if since:
        try:
            q = q.where(CompanionMessage.ts > datetime.fromisoformat(since))
        except ValueError as e:
            raise HTTPException(status_code=400, detail="bad since") from e
    rows = list((await db.execute(q)).scalars())
    rows.reverse()
    return [_message_dict(m) for m in rows]


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
    return _templates(request).TemplateResponse(
        request,
        "companion_detail.html.j2",
        {
            "user": user,
            "identity": identity,
            "channels": channels,
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
    return RedirectResponse(
        url=f"/companion/{identity_id}/#tab=settings", status_code=303
    )


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
    return RedirectResponse(
        url=f"/companion/{identity_id}/#tab=settings", status_code=303
    )


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
    return RedirectResponse(
        url=f"/companion/{identity_id}/#tab=settings", status_code=303
    )


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
    return RedirectResponse(
        url=f"/companion/{identity_id}/#tab=settings", status_code=303
    )
