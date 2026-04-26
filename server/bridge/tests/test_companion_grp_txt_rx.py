"""Integration: GRP_TXT-Empfang im CompanionService persistiert
empfangene Channel-Posts und unterdrückt eigene Echo-Posts."""

from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from meshcore_bridge.db import (
    CompanionChannel,
    CompanionIdentity,
    CompanionMessage,
    User,
)
from meshcore_bridge.db.models import Base
from meshcore_companion.crypto import LocalIdentity, derive_channel_secret
from meshcore_companion.node import CompanionNode
from meshcore_companion.packet import PayloadType
from meshcore_companion.service import CompanionService


@pytest_asyncio.fixture
async def service_env(tmp_path: Path):
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


@pytest.mark.asyncio
async def test_inbound_grp_txt_persists_message(service_env) -> None:
    svc, sessionmaker, user_id, _sent = service_env

    loaded = await svc.add_identity(
        user_id=user_id, name="Antonia", scope="public"
    )
    ch = await svc.add_channel(
        identity_id=loaded.id, name="tech", password="hunter2"
    )
    assert ch is not None

    # externer Sender: gleiches channel-secret/name
    secret = derive_channel_secret("tech", "hunter2")
    sender = CompanionNode(LocalIdentity.generate())
    pkt = sender.make_channel_message(
        channel_secret=secret,
        channel_hash=ch.channel_hash,
        text="hello world",
        sender_name="alice",
        timestamp=1000,
    )

    await svc.on_inbound_packet(raw=pkt.encode(), scope="public")

    async with sessionmaker() as db:
        rows = list(
            (
                await db.execute(
                    select(CompanionMessage).where(
                        CompanionMessage.identity_id == loaded.id,
                        CompanionMessage.channel_name == "tech",
                    )
                )
            ).scalars()
        )
    assert len(rows) == 1
    assert rows[0].direction == "in"
    assert rows[0].peer_name == "alice"
    assert rows[0].text == "hello world"
    assert rows[0].payload_type == int(PayloadType.GRP_TXT)


@pytest.mark.asyncio
async def test_inbound_grp_txt_suppresses_own_echo(service_env) -> None:
    svc, sessionmaker, user_id, _sent = service_env

    loaded = await svc.add_identity(
        user_id=user_id, name="Antonia", scope="public"
    )
    ch = await svc.add_channel(
        identity_id=loaded.id, name="tech", password="hunter2"
    )
    assert ch is not None

    # Wir simulieren ein Echo unseres eigenen Posts: sender_name == loaded.name
    secret = derive_channel_secret("tech", "hunter2")
    other = CompanionNode(LocalIdentity.generate())
    pkt = other.make_channel_message(
        channel_secret=secret,
        channel_hash=ch.channel_hash,
        text="self echo",
        sender_name="Antonia",
        timestamp=2000,
    )

    await svc.on_inbound_packet(raw=pkt.encode(), scope="public")

    async with sessionmaker() as db:
        rows = list(
            (
                await db.execute(
                    select(CompanionMessage).where(
                        CompanionMessage.identity_id == loaded.id,
                        CompanionMessage.channel_name == "tech",
                    )
                )
            ).scalars()
        )
    assert rows == []


@pytest.mark.asyncio
async def test_inbound_grp_txt_wrong_scope_ignored(service_env) -> None:
    svc, sessionmaker, user_id, _sent = service_env

    loaded = await svc.add_identity(
        user_id=user_id, name="Antonia", scope="public"
    )
    ch = await svc.add_channel(
        identity_id=loaded.id, name="tech", password="hunter2"
    )
    assert ch is not None

    secret = derive_channel_secret("tech", "hunter2")
    sender = CompanionNode(LocalIdentity.generate())
    pkt = sender.make_channel_message(
        channel_secret=secret,
        channel_hash=ch.channel_hash,
        text="x",
        sender_name="alice",
        timestamp=3000,
    )

    await svc.on_inbound_packet(
        raw=pkt.encode(), scope=f"pool:{uuid4()}"
    )

    async with sessionmaker() as db:
        rows = list(
            (
                await db.execute(
                    select(CompanionMessage).where(
                        CompanionMessage.identity_id == loaded.id
                    )
                )
            ).scalars()
        )
    # nur eigene Outbox darf da sein (keine), keine Inbox-Persistierung
    inbound = [r for r in rows if r.direction == "in"]
    assert inbound == []


@pytest.mark.asyncio
async def test_rename_identity_updates_db_and_memory(service_env) -> None:
    svc, sessionmaker, user_id, _sent = service_env
    loaded = await svc.add_identity(
        user_id=user_id, name="Old", scope="public"
    )
    ok = await svc.rename_identity(loaded.id, "New")
    assert ok is True
    assert svc.get(loaded.id).name == "New"

    async with sessionmaker() as db:
        row = await db.get(CompanionIdentity, loaded.id)
    assert row is not None
    assert row.name == "New"


@pytest.mark.asyncio
async def test_public_channel_uses_meshcore_psk(service_env) -> None:
    """Regression: Public-Channel muss den echten MeshCore-PSK haben,
    nicht derive_channel_secret('public','public'), sonst können wir
    den globalen Public-Channel-Verkehr nicht dekodieren."""
    import base64
    import hashlib

    from sqlalchemy import select

    svc, sessionmaker, user_id, _sent = service_env
    loaded = await svc.add_identity(
        user_id=user_id, name="Antonia", scope="public"
    )
    expected_real = base64.b64decode("izOH6cXN6mrJ5e26oRXNcg==")
    expected_secret = expected_real.ljust(32, b"\x00")
    expected_hash = hashlib.sha256(expected_real).digest()[:1]

    async with sessionmaker() as db:
        ch = (
            await db.execute(
                select(CompanionChannel).where(
                    CompanionChannel.identity_id == loaded.id,
                    CompanionChannel.name == "public",
                )
            )
        ).scalar_one()
    assert ch.secret == expected_secret
    assert ch.channel_hash == expected_hash


@pytest.mark.asyncio
async def test_public_channel_inbound_with_real_psk(service_env) -> None:
    """Ein externer Knoten mit dem echten MeshCore-Public-PSK postet —
    unser Companion muss das dekodieren und persistieren."""
    import base64

    from sqlalchemy import select

    svc, sessionmaker, user_id, _sent = service_env
    loaded = await svc.add_identity(
        user_id=user_id, name="Antonia", scope="public"
    )

    real = base64.b64decode("izOH6cXN6mrJ5e26oRXNcg==")
    secret_padded = real.ljust(32, b"\x00")
    chash = __import__("hashlib").sha256(real).digest()[:1]

    sender = CompanionNode(LocalIdentity.generate())
    pkt = sender.make_channel_message(
        channel_secret=secret_padded,
        channel_hash=chash,
        text="hello public",
        sender_name="external",
        timestamp=4242,
    )
    await svc.on_inbound_packet(raw=pkt.encode(), scope="public")

    async with sessionmaker() as db:
        rows = list(
            (
                await db.execute(
                    select(CompanionMessage).where(
                        CompanionMessage.identity_id == loaded.id,
                        CompanionMessage.channel_name == "public",
                    )
                )
            ).scalars()
        )
    assert len(rows) == 1
    assert rows[0].text == "hello public"
    assert rows[0].peer_name == "external"


@pytest.mark.asyncio
async def test_delete_channel(service_env) -> None:
    svc, sessionmaker, user_id, _sent = service_env
    loaded = await svc.add_identity(
        user_id=user_id, name="X", scope="public"
    )
    ch = await svc.add_channel(
        identity_id=loaded.id, name="tech", password="p"
    )
    assert ch is not None
    ok = await svc.delete_channel(ch.id)
    assert ok is True

    async with sessionmaker() as db:
        gone = await db.get(CompanionChannel, ch.id)
    assert gone is None
