"""Async SQLAlchemy engine + session management."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from meshcore_bridge.db.models import Base

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


async def init_engine(sqlite_path: Path) -> AsyncEngine:
    """Create the async engine, ensure parent dir exists, run create_all.

    Phase 1 uses ``Base.metadata.create_all`` for simplicity. Phase 5
    switches to Alembic-managed migrations exclusively (the alembic
    setup is committed alongside but not yet wired into startup).
    """
    global _engine, _sessionmaker

    sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    url = f"sqlite+aiosqlite:///{sqlite_path}"
    _engine = create_async_engine(url, echo=False, future=True)
    _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)

    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return _engine


async def close_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None


@asynccontextmanager
async def get_session() -> AsyncIterator[AsyncSession]:
    if _sessionmaker is None:
        raise RuntimeError("DB not initialized — call init_engine() first")
    async with _sessionmaker() as session:
        yield session
