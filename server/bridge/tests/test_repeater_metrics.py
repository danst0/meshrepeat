"""Tests für ``meshcore_bridge.bridge.repeater_metrics``.

Reiner Logik-Test gegen eine isolierte Test-DB-Session (siehe
``conftest.py::db``-Fixture). Synthetische ``CompanionContact``- und
``RawPacket``-Rows werden inserted; die Aggregations-Funktion wird
direkt aufgerufen und ihre Outputs auf Erwartung geprüft.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from meshcore_bridge.bridge.repeater_metrics import (
    DEFAULT_WEIGHTS,
    compute_repeater_metrics,
    liveness_decay,
)
from meshcore_bridge.db import (
    CompanionContact,
    CompanionIdentity,
    RawPacket,
    User,
)


def _make_pubkey(byte: int) -> bytes:
    """32-Byte-Pubkey, dessen erstes Byte ``byte`` ist (für 1-Byte-Hashes)."""
    return bytes([byte]) + b"\x00" * 31


async def _seed_user_and_identity(db: AsyncSession) -> CompanionIdentity:
    user = User(
        id=uuid4(),
        email="t@example.com",
        password_hash="x",
        role="owner",
    )
    db.add(user)
    await db.flush()
    ident = CompanionIdentity(
        id=uuid4(),
        user_id=user.id,
        name="ident",
        pubkey=b"\xff" * 32,
        privkey_enc=b"\x00" * 32,
        scope="public",
    )
    db.add(ident)
    await db.flush()
    return ident


async def _add_repeater(
    db: AsyncSession,
    ident: CompanionIdentity,
    *,
    pubkey: bytes,
    name: str,
    last_seen_at: datetime | None = None,
    last_lat: float | None = None,
    last_lon: float | None = None,
) -> None:
    db.add(
        CompanionContact(
            identity_id=ident.id,
            peer_pubkey=pubkey,
            peer_name=name,
            node_type=2,
            last_seen_at=last_seen_at,
            last_lat=last_lat,
            last_lon=last_lon,
        )
    )


async def _add_packet(
    db: AsyncSession,
    *,
    ts: datetime,
    path_hashes: str,
    advert_pubkey: str | None = None,
    payload_type: str = "TXT_MSG",
) -> None:
    db.add(
        RawPacket(
            ts=ts,
            site_id=uuid4(),
            site_name="t",
            scope="public",
            route_type="FLOOD",
            payload_type=payload_type,
            raw=b"\x00" * 8,
            path_hashes=path_hashes,
            advert_pubkey=advert_pubkey,
        )
    )


# --------------------------------------------------------------------------- #
# Pure-Logic
# --------------------------------------------------------------------------- #


def test_liveness_decay_monotonic() -> None:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    s_now = liveness_decay(now, now)
    s_1h = liveness_decay(now - timedelta(hours=1), now)
    s_24h = liveness_decay(now - timedelta(hours=24), now)
    s_7d = liveness_decay(now - timedelta(days=7), now)
    assert s_now == 1.0
    assert 0.95 < s_1h < 1.0
    assert 0.30 < s_24h < 0.45  # exp(-1) ≈ 0.367
    assert s_7d < s_24h < s_1h < s_now
    assert liveness_decay(None, now) == 0.0


def test_liveness_decay_naive_datetime_assumed_utc() -> None:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    naive = datetime(2026, 1, 1, 12, 0)  # ohne tz
    assert liveness_decay(naive, now) == pytest.approx(1.0)


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_no_repeaters_returns_empty(db: AsyncSession) -> None:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    result = await compute_repeater_metrics(db, timedelta(days=7), now=now)
    assert result.metrics == []
    assert result.repeater_count == 0


@pytest.mark.asyncio
async def test_unique_hash_match_full_count(db: AsyncSession) -> None:
    """Eindeutiger 1-Byte-Hash → full forward_count = 1.0."""
    ident = await _seed_user_and_identity(db)
    pub_a = _make_pubkey(0xAA)
    await _add_repeater(db, ident, pubkey=pub_a, name="A")
    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    await _add_packet(db, ts=now - timedelta(minutes=5), path_hashes="aa")
    await db.commit()

    result = await compute_repeater_metrics(db, timedelta(hours=24), now=now)
    assert result.repeater_count == 1
    m = result.metrics[0]
    assert m.name == "A"
    assert m.forward_count == pytest.approx(1.0)
    assert m.unique_paths == 1
    assert m.forward_share == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_ambiguous_hash_split_weight(db: AsyncSession) -> None:
    """Zwei Repeater mit kollidierendem 1-Byte-Präfix → 0.5 forward_count je."""
    ident = await _seed_user_and_identity(db)
    pub_a = bytes([0xAA]) + b"\x01" * 31
    pub_b = bytes([0xAA]) + b"\x02" * 31
    await _add_repeater(db, ident, pubkey=pub_a, name="A")
    await _add_repeater(db, ident, pubkey=pub_b, name="B")
    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    await _add_packet(db, ts=now - timedelta(minutes=5), path_hashes="aa")
    await db.commit()

    result = await compute_repeater_metrics(db, timedelta(hours=24), now=now)
    by_name = {m.name: m for m in result.metrics}
    assert by_name["A"].forward_count == pytest.approx(0.5)
    assert by_name["B"].forward_count == pytest.approx(0.5)


@pytest.mark.asyncio
async def test_bottleneck_requires_min_paths(db: AsyncSession) -> None:
    """Origin mit nur einem Pfad → kein Bottleneck-Eintrag."""
    ident = await _seed_user_and_identity(db)
    await _add_repeater(db, ident, pubkey=_make_pubkey(0xAA), name="A")
    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    origin_pub = (b"\xcc" + b"\x00" * 31).hex()
    await _add_packet(
        db,
        ts=now - timedelta(minutes=5),
        path_hashes="aa",
        advert_pubkey=origin_pub,
        payload_type="ADVERT",
    )
    await db.commit()
    result = await compute_repeater_metrics(db, timedelta(hours=24), now=now)
    m = next(m for m in result.metrics if m.name == "A")
    assert m.bottleneck_origins == 0
    # Reach zählt aber: 1 Origin gesehen.
    assert m.reach_endpoints == 1


@pytest.mark.asyncio
async def test_bottleneck_intersection(db: AsyncSession) -> None:
    """Wenn Origin X über zwei distinkte Pfade kommt, beide aber durch A
    laufen → A ist Bottleneck für X. B nur in einem Pfad → kein Bottleneck."""
    ident = await _seed_user_and_identity(db)
    pub_a = _make_pubkey(0xAA)
    pub_b = _make_pubkey(0xBB)
    pub_c = _make_pubkey(0xCC)
    await _add_repeater(db, ident, pubkey=pub_a, name="A")
    await _add_repeater(db, ident, pubkey=pub_b, name="B")
    await _add_repeater(db, ident, pubkey=pub_c, name="C")
    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    origin_pub = (b"\xdd" + b"\x00" * 31).hex()
    # Pfad 1: A → B
    await _add_packet(
        db,
        ts=now - timedelta(minutes=5),
        path_hashes="aa,bb",
        advert_pubkey=origin_pub,
        payload_type="ADVERT",
    )
    # Pfad 2: A → C  (B fehlt, A bleibt Pflicht)
    await _add_packet(
        db,
        ts=now - timedelta(minutes=4),
        path_hashes="aa,cc",
        advert_pubkey=origin_pub,
        payload_type="ADVERT",
    )
    await db.commit()
    result = await compute_repeater_metrics(db, timedelta(hours=24), now=now)
    by_name = {m.name: m for m in result.metrics}
    assert by_name["A"].bottleneck_origins == 1
    assert by_name["B"].bottleneck_origins == 0
    assert by_name["C"].bottleneck_origins == 0


@pytest.mark.asyncio
async def test_reach_counts_distinct_origins(db: AsyncSession) -> None:
    ident = await _seed_user_and_identity(db)
    await _add_repeater(db, ident, pubkey=_make_pubkey(0xAA), name="A")
    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    o1 = (b"\xc1" + b"\x00" * 31).hex()
    o2 = (b"\xc2" + b"\x00" * 31).hex()
    for o in (o1, o1, o2):  # o1 doppelt, o2 einfach → reach = 2
        await _add_packet(
            db,
            ts=now - timedelta(minutes=2),
            path_hashes="aa",
            advert_pubkey=o,
            payload_type="ADVERT",
        )
    await db.commit()
    result = await compute_repeater_metrics(db, timedelta(hours=24), now=now)
    m = next(m for m in result.metrics if m.name == "A")
    assert m.reach_endpoints == 2


@pytest.mark.asyncio
async def test_reach_excludes_self_advert(db: AsyncSession) -> None:
    """Self-Advert (origin == repeater pubkey) zählt nicht zu Reach —
    der Repeater erreicht sich nicht selbst."""
    ident = await _seed_user_and_identity(db)
    pub_a = _make_pubkey(0xAA)
    await _add_repeater(db, ident, pubkey=pub_a, name="A")
    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    await _add_packet(
        db,
        ts=now - timedelta(minutes=1),
        path_hashes="aa",
        advert_pubkey=pub_a.hex(),
        payload_type="ADVERT",
    )
    await db.commit()
    result = await compute_repeater_metrics(db, timedelta(hours=24), now=now)
    m = next(m for m in result.metrics if m.name == "A")
    assert m.reach_endpoints == 0
    assert m.advert_count == 1  # self-advert wird hier aber gezählt


@pytest.mark.asyncio
async def test_window_excludes_old_packets(db: AsyncSession) -> None:
    ident = await _seed_user_and_identity(db)
    await _add_repeater(db, ident, pubkey=_make_pubkey(0xAA), name="A")
    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    await _add_packet(db, ts=now - timedelta(hours=2), path_hashes="aa")
    await _add_packet(db, ts=now - timedelta(days=2), path_hashes="aa")
    await db.commit()
    result = await compute_repeater_metrics(db, timedelta(hours=24), now=now)
    m = result.metrics[0]
    assert m.forward_count == pytest.approx(1.0)
    assert result.total_packets == 1


@pytest.mark.asyncio
async def test_dedup_per_pubkey_across_identities(db: AsyncSession) -> None:
    """Selber Repeater-Pubkey, mehrfach in CompanionContact (über mehrere
    Identities) → nur eine Zeile im Ergebnis, jüngstes last_seen_at gewinnt."""
    ident = await _seed_user_and_identity(db)
    pub_a = _make_pubkey(0xAA)
    older = datetime(2026, 1, 1, 8, 0, tzinfo=UTC)
    newer = datetime(2026, 1, 1, 11, 0, tzinfo=UTC)
    await _add_repeater(db, ident, pubkey=pub_a, name="A", last_seen_at=older)
    # Zweite Companion-Identity, gleicher Repeater-Pubkey, neueres last_seen.
    user2 = User(id=uuid4(), email="u2@example.com", password_hash="x", role="owner")
    db.add(user2)
    await db.flush()
    ident2 = CompanionIdentity(
        id=uuid4(),
        user_id=user2.id,
        name="i2",
        pubkey=b"\xee" * 32,
        privkey_enc=b"\x00" * 32,
        scope="public",
    )
    db.add(ident2)
    await db.flush()
    await _add_repeater(db, ident2, pubkey=pub_a, name="A", last_seen_at=newer)
    await db.commit()

    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    result = await compute_repeater_metrics(db, timedelta(hours=24), now=now)
    assert len(result.metrics) == 1
    assert result.metrics[0].last_seen_at == newer


@pytest.mark.asyncio
async def test_total_score_weights(db: AsyncSession) -> None:
    """Total-Score = gewichtetes Mittel der vier Sub-Scores."""
    ident = await _seed_user_and_identity(db)
    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    await _add_repeater(db, ident, pubkey=_make_pubkey(0xAA), name="A", last_seen_at=now)
    await _add_packet(db, ts=now - timedelta(minutes=1), path_hashes="aa")
    await db.commit()

    result = await compute_repeater_metrics(db, timedelta(hours=24), now=now)
    m = result.metrics[0]
    expected = (
        DEFAULT_WEIGHTS["forwarding"] * m.forwarding_score
        + DEFAULT_WEIGHTS["bottleneck"] * m.bottleneck_score
        + DEFAULT_WEIGHTS["reach"] * m.reach_score
        + DEFAULT_WEIGHTS["liveness"] * m.liveness_score
    )
    assert m.total_score == pytest.approx(expected)


@pytest.mark.asyncio
async def test_30d_window_marks_truncated(db: AsyncSession) -> None:
    ident = await _seed_user_and_identity(db)
    await _add_repeater(db, ident, pubkey=_make_pubkey(0xAA), name="A")
    await db.commit()
    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    result_7d = await compute_repeater_metrics(db, timedelta(days=7), now=now)
    result_30d = await compute_repeater_metrics(db, timedelta(days=30), now=now)
    assert result_7d.forward_truncated_to_7d is False
    assert result_30d.forward_truncated_to_7d is True
