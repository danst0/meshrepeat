from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from meshcore_bridge.auth.sessions import (
    SESSION_BYTES,
    SESSION_HEX_LEN,
    create_session,
    decode_cookie,
    destroy_session,
    encode_cookie,
    list_user_sessions,
    load_session,
)
from meshcore_bridge.db.models import Session as SessionRow
from meshcore_bridge.db.models import User


def _make_user(email: str = "a@b.de") -> User:
    return User(email=email, password_hash="x", role="owner")


def test_encode_decode_cookie_roundtrip() -> None:
    sid = b"\x01" * SESSION_BYTES
    cookie = encode_cookie(sid)
    assert len(cookie) == SESSION_HEX_LEN
    assert decode_cookie(cookie) == sid


def test_decode_cookie_rejects_malformed() -> None:
    assert decode_cookie("zz") is None
    assert decode_cookie("not-hex-but-right-length-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz") is None


@pytest.mark.asyncio
async def test_create_load_destroy(db) -> None:
    u = _make_user()
    db.add(u)
    await db.commit()

    sid = await create_session(db, user_id=u.id, user_agent="pytest")
    assert len(sid) == SESSION_BYTES

    row = await load_session(db, sid, idle_timeout=timedelta(days=1))
    assert row is not None
    assert row.user_id == u.id
    assert row.user_agent == "pytest"

    await destroy_session(db, sid)
    assert await load_session(db, sid, idle_timeout=timedelta(days=1)) is None


@pytest.mark.asyncio
async def test_load_session_drops_idle(db) -> None:
    u = _make_user()
    db.add(u)
    await db.commit()
    sid = await create_session(db, user_id=u.id)

    row = await db.get(SessionRow, sid)
    assert row is not None
    row.last_seen_at = datetime.now(UTC) - timedelta(hours=2)
    await db.commit()

    assert await load_session(db, sid, idle_timeout=timedelta(hours=1)) is None
    assert await db.get(SessionRow, sid) is None


@pytest.mark.asyncio
async def test_list_sessions_filters_by_user(db) -> None:
    a = _make_user("a@x.de")
    b = _make_user("b@x.de")
    db.add_all([a, b])
    await db.commit()
    await create_session(db, user_id=a.id)
    await create_session(db, user_id=a.id)
    await create_session(db, user_id=b.id)

    sessions_a = await list_user_sessions(db, a.id)
    sessions_b = await list_user_sessions(db, b.id)
    assert len(sessions_a) == 2
    assert len(sessions_b) == 1
