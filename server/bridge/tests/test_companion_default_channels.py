"""Pre-Seeded Hashtag-Channels (Mesh Rheinland) und Favorit-Flag.

Quelle der Channel-Liste:
https://www.meshrheinland.de/meshcore/channels — der Public-Channel ist
nach Identity-Anlage favorisiert; die Hashtag-Channels werden automatisch
mitangelegt und vom User bei Bedarf manuell als Favorit markiert.
"""

from __future__ import annotations

import hashlib

import pytest
from sqlalchemy import select

from meshcore_bridge.db import CompanionChannel
from meshcore_companion.service import (
    DEFAULT_HASH_CHANNELS,
    _hash_channel_secret_and_hash,
)


@pytest.mark.asyncio
async def test_add_identity_seeds_default_channels(service_env) -> None:
    svc, sessionmaker, user_id, _sent = service_env
    loaded = await svc.add_identity(user_id=user_id, name="Antonia", scope="public")

    async with sessionmaker() as db:
        rows = list(
            (
                await db.execute(
                    select(CompanionChannel).where(CompanionChannel.identity_id == loaded.id)
                )
            ).scalars()
        )
    by_name = {c.name: c for c in rows}

    # Public + alle Hashtag-Channels existieren
    assert "public" in by_name
    for name in DEFAULT_HASH_CHANNELS:
        assert name in by_name, f"missing default channel: {name}"

    # Favorit-Default: Public ja, Hashtag-Channels nein
    assert by_name["public"].favorite is True
    for name in DEFAULT_HASH_CHANNELS:
        assert by_name[name].favorite is False, f"{name} unexpectedly favorited"


@pytest.mark.asyncio
async def test_hash_channel_psk_matches_meshcore_convention(service_env) -> None:
    """Hash-Channel-PSK = sha256("#" + name)[:16], gepaddet auf 32 Byte;
    Channel-Hash = sha256(PSK_real16)[:1]. ``name`` ist ohne Sigil
    in der DB; das ``#`` ist Anzeige-Konvention, gehört aber laut
    Mesh-Rheinland-Doku in den Hash-Input."""
    svc, sessionmaker, user_id, _sent = service_env
    loaded = await svc.add_identity(user_id=user_id, name="Antonia", scope="public")

    async with sessionmaker() as db:
        ch = (
            await db.execute(
                select(CompanionChannel).where(
                    CompanionChannel.identity_id == loaded.id,
                    CompanionChannel.name == "test",
                )
            )
        ).scalar_one()

    real = hashlib.sha256(b"#test").digest()[:16]
    expected_secret = real.ljust(32, b"\x00")
    expected_hash = hashlib.sha256(real).digest()[:1]
    assert ch.secret == expected_secret
    assert ch.channel_hash == expected_hash
    # Helper kriegt den nackten Namen, präfixt selbst.
    assert _hash_channel_secret_and_hash("test") == (expected_secret, expected_hash)


@pytest.mark.asyncio
async def test_ensure_hash_channels_preserves_user_favorite(service_env) -> None:
    """Wiederholtes Seeden darf ein vom User gesetztes Favorit-Flag auf
    einem Hashtag-Channel nicht zurücksetzen."""
    svc, sessionmaker, user_id, _sent = service_env
    loaded = await svc.add_identity(user_id=user_id, name="Antonia", scope="public")

    async with sessionmaker() as db:
        ch = (
            await db.execute(
                select(CompanionChannel).where(
                    CompanionChannel.identity_id == loaded.id,
                    CompanionChannel.name == "nrw",
                )
            )
        ).scalar_one()
        ch.favorite = True
        await db.commit()
        ch_id = ch.id

    # Erneutes Seeden (idempotent)
    await svc._ensure_hash_channels(loaded.id)

    async with sessionmaker() as db:
        ch = await db.get(CompanionChannel, ch_id)
        assert ch is not None
        assert ch.favorite is True


@pytest.mark.asyncio
async def test_existing_public_channel_gets_favorited_on_start(service_env) -> None:
    """Bestands-DB ohne favorite-Flag (Migration läuft); _ensure_public_channel
    setzt favorite=True für den Public-Channel idempotent nach."""
    svc, sessionmaker, user_id, _sent = service_env
    loaded = await svc.add_identity(user_id=user_id, name="Antonia", scope="public")

    async with sessionmaker() as db:
        ch = (
            await db.execute(
                select(CompanionChannel).where(
                    CompanionChannel.identity_id == loaded.id,
                    CompanionChannel.name == "public",
                )
            )
        ).scalar_one()
        ch.favorite = False
        await db.commit()

    await svc._ensure_public_channel(loaded.id)

    async with sessionmaker() as db:
        ch = (
            await db.execute(
                select(CompanionChannel).where(
                    CompanionChannel.identity_id == loaded.id,
                    CompanionChannel.name == "public",
                )
            )
        ).scalar_one()
        assert ch.favorite is True
