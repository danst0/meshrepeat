"""FastAPI dependency helpers — current user, DB session, auth gates."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from meshcore_bridge.auth.sessions import decode_cookie, load_session
from meshcore_bridge.config import AppConfig
from meshcore_bridge.db import User, get_session


async def get_db() -> AsyncIterator[AsyncSession]:
    async with get_session() as db:
        yield db


def get_config(request: Request) -> AppConfig:
    cfg = getattr(request.app.state, "config", None)
    if cfg is None:
        raise RuntimeError("AppConfig not attached to app.state")
    return cfg  # type: ignore[no-any-return]


async def current_user_optional(
    request: Request,
    db: AsyncSession = Depends(get_db),
    cfg: AppConfig = Depends(get_config),
) -> User | None:
    cookie_value = request.cookies.get(cfg.web.session_cookie_name)
    if not cookie_value:
        return None
    sid = decode_cookie(cookie_value)
    if sid is None:
        return None
    sess = await load_session(
        db,
        sid,
        idle_timeout=timedelta(days=cfg.web.session_idle_timeout_days),
    )
    if sess is None:
        return None
    return await db.get(User, sess.user_id)


async def current_user_required(
    user: User | None = Depends(current_user_optional),
) -> User:
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    return user


async def admin_required(user: User = Depends(current_user_required)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    return user
