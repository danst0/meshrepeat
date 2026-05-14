"""FastAPI dependency helpers — current user, DB session, auth gates."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from meshcore_bridge.auth.sessions import decode_cookie, load_session
from meshcore_bridge.auth.tokens import token_prefix, verify_bearer_token
from meshcore_bridge.config import AppConfig
from meshcore_bridge.db import CompanionApiToken, User, get_session


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


VALID_TOKEN_SCOPES = frozenset({"read", "write", "admin"})
_COOKIE_SCOPES = frozenset({"*"})


@dataclass(frozen=True)
class CompanionAuth:
    """Auth-Ergebnis für Companion-Routen. Cookie-Session liefert
    ``identity_lock=None`` und Scopes ``{"*"}``; ein API-Token sperrt auf
    seine identity_id und limitiert die Scopes auf die im Token gesetzten."""

    user: User
    identity_lock: UUID | None
    scopes: frozenset[str]

    def require_scope(self, scope: str) -> None:
        if "*" in self.scopes:
            return
        if scope not in self.scopes:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="scope missing")

    def require_identity(self, identity_id: UUID) -> None:
        if self.identity_lock is not None and self.identity_lock != identity_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="identity locked"
            )


def _parse_bearer(request: Request) -> str | None:
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    candidate = auth[7:].strip()
    return candidate or None


async def _resolve_token(db: AsyncSession, raw_token: str) -> CompanionApiToken | None:
    prefix = token_prefix(raw_token)
    rows = list(
        (
            await db.execute(
                select(CompanionApiToken).where(CompanionApiToken.prefix == prefix)
            )
        ).scalars()
    )
    now = datetime.now(UTC)
    for row in rows:
        if row.revoked_at is not None:
            continue
        if row.expires_at is not None:
            exp = row.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=UTC)
            if exp <= now:
                continue
        if verify_bearer_token(row.token_hash, raw_token):
            row.last_used_at = now
            await db.commit()
            return row
    return None


async def companion_auth(
    request: Request,
    db: AsyncSession = Depends(get_db),
    cfg: AppConfig = Depends(get_config),
) -> CompanionAuth:
    """Auth für Companion-REST: erst Bearer-Token, sonst Session-Cookie.

    Token: ``Authorization: Bearer <token>``. Lockt auf seine identity_id
    und seine Scopes (CSV ``read,write``). Routen-Code prüft Scope und
    Identity via ``CompanionAuth.require_scope`` / ``require_identity``.

    Cookie: liefert ``identity_lock=None`` und Scopes ``{"*"}`` — also
    volles Routing-Set wie bisher.
    """
    raw = _parse_bearer(request)
    if raw is not None:
        token = await _resolve_token(db, raw)
        if token is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        user = await db.get(User, token.user_id)
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        scopes = frozenset(
            s.strip() for s in token.scopes.split(",") if s.strip()
        ) & VALID_TOKEN_SCOPES
        return CompanionAuth(user=user, identity_lock=token.identity_id, scopes=scopes)

    cookie_value = request.cookies.get(cfg.web.session_cookie_name)
    if not cookie_value:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    sid = decode_cookie(cookie_value)
    if sid is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    sess = await load_session(
        db,
        sid,
        idle_timeout=timedelta(days=cfg.web.session_idle_timeout_days),
    )
    if sess is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    user = await db.get(User, sess.user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    return CompanionAuth(user=user, identity_lock=None, scopes=_COOKIE_SCOPES)
