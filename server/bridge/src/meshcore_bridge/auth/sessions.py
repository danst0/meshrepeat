"""Server-side Cookie-Sessions.

Eine Session ist 32 Random-Bytes; in der DB gespeichert mit User-Bezug.
Cookie trägt nur die Bytes (hex-encoded) — keine signierten Tokens, kein
JWT. Vorteile: serverseitige Revocation, keine Auth-State-Drift.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from meshcore_bridge.db.models import Session as SessionRow

SESSION_BYTES = 32
SESSION_HEX_LEN = SESSION_BYTES * 2


def _new_session_id() -> bytes:
    return secrets.token_bytes(SESSION_BYTES)


def encode_cookie(session_id: bytes) -> str:
    return session_id.hex()


def decode_cookie(cookie_value: str) -> bytes | None:
    """Returns raw session bytes, or ``None`` if the cookie value is malformed."""
    if len(cookie_value) != SESSION_HEX_LEN:
        return None
    try:
        return bytes.fromhex(cookie_value)
    except ValueError:
        return None


async def create_session(
    db: AsyncSession,
    *,
    user_id: UUID,
    user_agent: str | None = None,
) -> bytes:
    sid = _new_session_id()
    db.add(SessionRow(id=sid, user_id=user_id, user_agent=user_agent))
    await db.commit()
    return sid


async def load_session(
    db: AsyncSession,
    session_id: bytes,
    *,
    idle_timeout: timedelta,
) -> SessionRow | None:
    row = await db.get(SessionRow, session_id)
    if row is None:
        return None
    now = datetime.now(UTC)
    last_seen = row.last_seen_at
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=UTC)
    if now - last_seen > idle_timeout:
        await db.delete(row)
        await db.commit()
        return None
    row.last_seen_at = now
    await db.commit()
    return row


async def destroy_session(db: AsyncSession, session_id: bytes) -> None:
    await db.execute(delete(SessionRow).where(SessionRow.id == session_id))
    await db.commit()


async def destroy_all_user_sessions(db: AsyncSession, user_id: UUID) -> None:
    await db.execute(delete(SessionRow).where(SessionRow.user_id == user_id))
    await db.commit()


async def cleanup_expired(db: AsyncSession, *, idle_timeout: timedelta) -> int:
    cutoff = datetime.now(UTC) - idle_timeout
    result = await db.execute(
        delete(SessionRow).where(SessionRow.last_seen_at < cutoff)
    )
    await db.commit()
    rowcount: int = getattr(result, "rowcount", 0) or 0
    return rowcount


async def list_user_sessions(db: AsyncSession, user_id: UUID) -> list[SessionRow]:
    result = await db.execute(
        select(SessionRow).where(SessionRow.user_id == user_id)
    )
    return list(result.scalars())
