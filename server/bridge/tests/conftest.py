"""Shared pytest fixtures."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from pathlib import Path
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from meshcore_bridge.db import User
from meshcore_bridge.db.models import Base
from meshcore_companion.service import CompanionService


@pytest.fixture(scope="session")
def event_loop() -> asyncio.AbstractEventLoop:
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def service_env(tmp_path: Path):
    """Hochgefahrene CompanionService-Umgebung mit eigener SQLite, einem
    User und einem In-Memory-Inject-Sink. Liefert
    ``(svc, sessionmaker, user_id, sent)``."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'svc.sqlite'}"
    engine = create_async_engine(url, future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)

    async with sessionmaker() as db:
        u = User(
            id=uuid4(),
            email="t@t",
            password_hash="x",
            role="owner",
        )
        db.add(u)
        await db.commit()
        user_id = u.id

    master_key = os.urandom(32)
    sent: list[tuple[bytes, str]] = []

    async def inject(pkt, scope):
        sent.append((pkt.encode(), scope))

    svc = CompanionService(
        master_key=master_key,
        sessionmaker=sessionmaker,
        inject=inject,
        advert_interval_s=3600,
    )
    await svc.start()

    try:
        yield svc, sessionmaker, user_id, sent
    finally:
        await svc.stop()
        await engine.dispose()


@pytest_asyncio.fixture
async def db(tmp_path: Path) -> AsyncIterator[AsyncSession]:
    url = f"sqlite+aiosqlite:///{tmp_path / 'test.sqlite'}"
    engine = create_async_engine(url, future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        yield session
    await engine.dispose()


@pytest.fixture
def fast_argon2():
    """Beschleunigt Argon2 für Tests, die Passwort-Hashing in der heißen Schleife haben."""
    from meshcore_bridge.auth import passwords

    original = passwords._DEFAULT_HASHER
    passwords._DEFAULT_HASHER = passwords.make_hasher(
        time_cost=1, memory_cost_kib=1024, parallelism=1
    )
    yield
    passwords._DEFAULT_HASHER = original
