"""Repeater-CRUD-Routen für eingeloggte User."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from meshcore_bridge.auth.tokens import (
    generate_bearer_token,
    hash_bearer_token,
    token_prefix,
)
from meshcore_bridge.config import AppConfig
from meshcore_bridge.db import Repeater, User
from meshcore_bridge.web.deps import current_user_required, get_config, get_db

router = APIRouter()


def _templates(request: Request) -> Jinja2Templates:
    return request.app.state.templates  # type: ignore[no-any-return]


def _host(cfg: AppConfig) -> str:
    return cfg.web.base_url.split("://", 1)[-1]


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    repeaters = list(
        (
            await db.execute(
                select(Repeater).where(Repeater.owner_id == user.id).order_by(Repeater.created_at)
            )
        ).scalars()
    )
    return _templates(request).TemplateResponse(
        request,
        "dashboard.html.j2",
        {"user": user, "repeaters": repeaters, "flash": None},
    )


@router.get("/repeaters", response_class=HTMLResponse)
async def repeaters_index(
    request: Request,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    return RedirectResponse(url="/dashboard", status_code=303)


@router.get("/repeaters/new", response_class=HTMLResponse)
async def repeater_new_form(
    request: Request,
    user: User = Depends(current_user_required),
) -> HTMLResponse:
    return _templates(request).TemplateResponse(
        request,
        "repeater_new.html.j2",
        {"user": user, "flash": None, "name": None, "scope": "public"},
    )


@router.post("/repeaters", response_model=None)
async def repeater_create(
    request: Request,
    name: Annotated[str, Form()],
    scope: Annotated[str, Form()],
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
    cfg: AppConfig = Depends(get_config),
) -> HTMLResponse | RedirectResponse:
    name = name.strip()
    if not name:
        return _templates(request).TemplateResponse(
            request,
            "repeater_new.html.j2",
            {
                "user": user,
                "flash": {"kind": "error", "message": "Name darf nicht leer sein."},
                "name": "",
                "scope": scope,
            },
            status_code=400,
        )

    # Phase 1: jeder neue Pool ist ein eigener UUID-Pool. Pool-Sharing
    # zwischen Usern kommt in Phase 3.
    if scope == "public":
        scope_value = "public"
    elif scope == "pool:new":
        scope_value = f"pool:{uuid4()}"
    elif scope.startswith("pool:"):
        scope_value = scope
    else:
        scope_value = "public"

    token = generate_bearer_token()
    repeater = Repeater(
        owner_id=user.id,
        name=name,
        scope=scope_value,
        token_prefix=token_prefix(token),
        token_hash=hash_bearer_token(token),
    )
    db.add(repeater)
    await db.commit()
    await db.refresh(repeater)

    return _templates(request).TemplateResponse(
        request,
        "repeater_show.html.j2",
        {
            "user": user,
            "repeater": repeater,
            "new_token": token,
            "host": _host(cfg),
            "flash": {"kind": "ok", "message": "Repeater angelegt."},
        },
    )


async def _load_owned_repeater(repeater_id: UUID, *, user: User, db: AsyncSession) -> Repeater:
    repeater = await db.get(Repeater, repeater_id)
    if repeater is None or repeater.owner_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return repeater


@router.get("/repeaters/{repeater_id}", response_class=HTMLResponse)
async def repeater_show(
    request: Request,
    repeater_id: UUID,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
    cfg: AppConfig = Depends(get_config),
) -> HTMLResponse:
    repeater = await _load_owned_repeater(repeater_id, user=user, db=db)
    return _templates(request).TemplateResponse(
        request,
        "repeater_show.html.j2",
        {
            "user": user,
            "repeater": repeater,
            "new_token": None,
            "host": _host(cfg),
            "flash": None,
        },
    )


@router.post("/repeaters/{repeater_id}/rotate-token", response_class=HTMLResponse)
async def repeater_rotate_token(
    request: Request,
    repeater_id: UUID,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
    cfg: AppConfig = Depends(get_config),
) -> HTMLResponse:
    repeater = await _load_owned_repeater(repeater_id, user=user, db=db)
    token = generate_bearer_token()
    repeater.token_prefix = token_prefix(token)
    repeater.token_hash = hash_bearer_token(token)
    repeater.revoked_at = None
    await db.commit()
    return _templates(request).TemplateResponse(
        request,
        "repeater_show.html.j2",
        {
            "user": user,
            "repeater": repeater,
            "new_token": token,
            "host": _host(cfg),
            "flash": {"kind": "ok", "message": "Token rotiert."},
        },
    )


@router.post("/repeaters/{repeater_id}/delete")
async def repeater_delete(
    request: Request,
    repeater_id: UUID,
    user: User = Depends(current_user_required),
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    repeater = await _load_owned_repeater(repeater_id, user=user, db=db)
    await db.delete(repeater)
    await db.commit()
    return RedirectResponse(url="/dashboard", status_code=303)
