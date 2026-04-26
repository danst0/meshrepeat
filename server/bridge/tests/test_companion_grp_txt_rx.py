"""Integration: GRP_TXT-Empfang im CompanionService persistiert
empfangene Channel-Posts und unterdrückt eigene Echo-Posts."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from meshcore_bridge.db import (
    CompanionChannel,
    CompanionContact,
    CompanionIdentity,
    CompanionMessage,
    User,
)
from meshcore_bridge.db.models import Base
from meshcore_companion.crypto import (
    LocalIdentity,
    derive_channel_secret,
    encrypt_then_mac,
)
from meshcore_companion.node import CompanionNode, encode_advert_app_data
from meshcore_companion.packet import Packet, PayloadType, RouteType
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
async def test_inbound_grp_txt_dedups_same_raw(service_env) -> None:
    """Bei mehreren verbundenen Repeatern liefert jeder denselben LoRa-
    Frame einmal. Wir dürfen ihn nur einmal in der DB persistieren."""
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
        text="dup",
        sender_name="alice",
        timestamp=5000,
    )
    raw = pkt.encode()

    # 3x dasselbe raw — simuliert 3 Repeater-Connections
    for _ in range(3):
        await svc.on_inbound_packet(raw=raw, scope="public")

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


@pytest.mark.asyncio
async def test_inbound_grp_txt_dedups_across_hops(service_env) -> None:
    """Zwei Repeater forwarden denselben LoRa-Frame mit unterschiedlichen
    Path-Hashes (Hop-Anzahl). Das raw differiert, der payload-Body ist
    identisch — Dedup muss trotzdem greifen."""
    from meshcore_companion.packet import Packet, PayloadType, RouteType

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
        text="hop-test",
        sender_name="alice",
        timestamp=6000,
    )
    # Variante A: 1 Hop, path = b"\xaa"
    raw_a = Packet(
        route_type=RouteType.FLOOD,
        payload_type=PayloadType.GRP_TXT,
        path=b"\xaa",
        payload=pkt.payload,
    ).encode()
    # Variante B: 2 Hops, path = b"\xaa\xbb"
    raw_b = Packet(
        route_type=RouteType.FLOOD,
        payload_type=PayloadType.GRP_TXT,
        path=b"\xaa\xbb",
        payload=pkt.payload,
    ).encode()
    assert raw_a != raw_b  # unterschiedliche raws

    await svc.on_inbound_packet(raw=raw_a, scope="public")
    await svc.on_inbound_packet(raw=raw_b, scope="public")

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
async def test_inbound_advert_persists_lat_lon(service_env) -> None:
    """ADVERT mit Geokoordinaten füllt CompanionContact.last_lat/last_lon —
    Grundlage für die Karten-Ansicht."""
    svc, sessionmaker, user_id, _sent = service_env
    loaded = await svc.add_identity(
        user_id=user_id, name="Antonia", scope="public"
    )
    other = CompanionNode(LocalIdentity.generate())
    app_data = encode_advert_app_data(name="Drusilla", lat=51.0, lon=7.0)
    pkt = other.make_advert(app_data=app_data, timestamp=1000)
    await svc.on_inbound_packet(raw=pkt.encode(), scope="public")

    async with sessionmaker() as db:
        rows = list(
            (
                await db.execute(
                    select(CompanionContact).where(
                        CompanionContact.identity_id == loaded.id
                    )
                )
            ).scalars()
        )
    assert len(rows) == 1
    assert rows[0].peer_name == "Drusilla"
    assert rows[0].last_lat == pytest.approx(51.0, abs=1e-5)
    assert rows[0].last_lon == pytest.approx(7.0, abs=1e-5)


@pytest.mark.asyncio
async def test_inbound_advert_without_lat_lon_keeps_previous(service_env) -> None:
    """Ein Advert ohne Geo-Flag darf vorhandene Koordinaten nicht löschen."""
    svc, sessionmaker, user_id, _sent = service_env
    loaded = await svc.add_identity(
        user_id=user_id, name="Antonia", scope="public"
    )
    other = CompanionNode(LocalIdentity.generate())

    pkt1 = other.make_advert(
        app_data=encode_advert_app_data(name="Drusilla", lat=51.0, lon=7.0),
        timestamp=1000,
    )
    await svc.on_inbound_packet(raw=pkt1.encode(), scope="public")
    pkt2 = other.make_advert(
        app_data=encode_advert_app_data(name="Drusilla"),  # no lat/lon
        timestamp=1100,
    )
    await svc.on_inbound_packet(raw=pkt2.encode(), scope="public")

    async with sessionmaker() as db:
        row = (
            await db.execute(
                select(CompanionContact).where(
                    CompanionContact.identity_id == loaded.id
                )
            )
        ).scalar_one()
    assert row.last_lat == pytest.approx(51.0, abs=1e-5)
    assert row.last_lon == pytest.approx(7.0, abs=1e-5)


@pytest.mark.asyncio
async def test_inbound_dm_persists_with_sender_ts_and_dedups_retries(
    service_env,
) -> None:
    """Zwei Retry-Pakete mit gleichem Sender-ts dürfen nur einmal in der
    DB landen. Außerdem: ts in DB = Sender-ts (nicht Empfangszeit)."""
    import struct

    svc, sessionmaker, user_id, _sent = service_env
    loaded = await svc.add_identity(
        user_id=user_id, name="Antonia", scope="public"
    )
    peer = LocalIdentity.generate()
    async with sessionmaker() as db:
        db.add(
            CompanionContact(
                identity_id=loaded.id,
                peer_pubkey=peer.pub_key,
                peer_name="Octavia",
                last_seen_at=datetime.now(UTC),
            )
        )
        await db.commit()

    sender_ts = 1700000000
    plaintext = struct.pack("<I", sender_ts) + bytes([0]) + b"hello"
    secret = peer.calc_shared_secret(loaded.pubkey)
    encrypted = encrypt_then_mac(secret, plaintext)
    body = loaded.pubkey[:1] + peer.pub_key[:1] + encrypted
    pkt = Packet(
        route_type=RouteType.FLOOD,
        payload_type=PayloadType.TXT_MSG,
        payload=body,
    )
    raw_a = pkt.encode()

    # Retry mit anderem flags-byte (attempt=1 statt 0) → anderer encrypted
    # body, aber gleicher (peer, ts)
    plaintext_retry = struct.pack("<I", sender_ts) + bytes([0x01]) + b"hello"
    encrypted_retry = encrypt_then_mac(secret, plaintext_retry)
    body_retry = loaded.pubkey[:1] + peer.pub_key[:1] + encrypted_retry
    pkt_retry = Packet(
        route_type=RouteType.FLOOD,
        payload_type=PayloadType.TXT_MSG,
        payload=body_retry,
    )
    raw_b = pkt_retry.encode()

    # Erster Receive: persisted
    await svc.on_inbound_packet(raw=raw_a, scope="public")
    # zweiter Receive (echte retry vom Sender): muss dedupen
    await svc.on_inbound_packet(raw=raw_b, scope="public")

    async with sessionmaker() as db:
        rows = list(
            (
                await db.execute(
                    select(CompanionMessage).where(
                        CompanionMessage.identity_id == loaded.id,
                        CompanionMessage.payload_type == int(PayloadType.TXT_MSG),
                    )
                )
            ).scalars()
        )
    assert len(rows) == 1
    assert rows[0].text == "hello"
    # ts stammt vom Sender (SQLite gibt naive datetime zurück, daher
    # auf naive normalisieren für den Vergleich)
    db_ts = rows[0].ts
    if db_ts.tzinfo is not None:
        db_ts = db_ts.replace(tzinfo=None)
    assert db_ts == datetime.fromtimestamp(sender_ts, UTC).replace(tzinfo=None)


@pytest.mark.asyncio
async def test_inbound_dm_emits_path_ack_on_flood(service_env) -> None:
    """Bei FLOOD-RX einer DM muss der Service ein PATH-Datagram (mit
    ACK-Hash piggybacked) an den Sender zurückschicken — sonst lernt der
    Sender keinen Out-Path und retried weiter Flood."""
    import struct

    svc, sessionmaker, user_id, sent = service_env
    loaded = await svc.add_identity(
        user_id=user_id, name="Antonia", scope="public"
    )
    peer = LocalIdentity.generate()
    async with sessionmaker() as db:
        db.add(
            CompanionContact(
                identity_id=loaded.id,
                peer_pubkey=peer.pub_key,
                peer_name="Octavia",
                last_seen_at=datetime.now(UTC),
            )
        )
        await db.commit()

    sender_ts = 1700000000
    plaintext = struct.pack("<I", sender_ts) + bytes([0]) + b"hi"
    secret = peer.calc_shared_secret(loaded.pubkey)
    encrypted = encrypt_then_mac(secret, plaintext)
    body = loaded.pubkey[:1] + peer.pub_key[:1] + encrypted
    pkt = Packet(
        route_type=RouteType.FLOOD,
        payload_type=PayloadType.TXT_MSG,
        path=b"\xaa",  # 1 Hop
        payload=body,
    )
    sent.clear()
    await svc.on_inbound_packet(raw=pkt.encode(), scope="public")

    # Erster gesendeter Frame nach RX = unser PATH-Return
    path_frames = [
        (raw, sc) for raw, sc in sent
        if Packet.decode(raw).payload_type == PayloadType.PATH
    ]
    assert len(path_frames) == 1
    path_raw, _ = path_frames[0]
    path_pkt = Packet.decode(path_raw)
    assert path_pkt.payload[:1] == peer.pub_key[:1]
    assert path_pkt.payload[1:2] == loaded.pubkey[:1]


@pytest.mark.asyncio
async def test_telemetry_request_emits_req_packet(service_env) -> None:
    """request_telemetry baut ein REQ und schickt es via inject."""
    svc, _sessionmaker, user_id, sent = service_env
    loaded = await svc.add_identity(
        user_id=user_id, name="Antonia", scope="public"
    )
    sent.clear()  # advert von add_identity raus

    peer = LocalIdentity.generate()
    ok = await svc.request_telemetry(
        identity_id=loaded.id, peer_pubkey=peer.pub_key
    )
    assert ok is True
    assert len(sent) == 1
    raw, scope = sent[0]
    assert scope == "public"
    pkt = Packet.decode(raw)
    assert pkt.payload_type == PayloadType.REQ
    # Body: dest_hash(1) + src_hash(1) + encrypted(>=18)
    assert pkt.payload[:1] == peer.pub_key[:1]
    assert pkt.payload[1:2] == loaded.pubkey[:1]


@pytest.mark.asyncio
async def test_telemetry_response_persists_geo(service_env) -> None:
    """Externer Peer sendet RESPONSE mit LPP_GPS — Companion persistiert
    last_lat/last_lon im zugehörigen CompanionContact."""
    import struct

    svc, sessionmaker, user_id, _sent = service_env
    loaded = await svc.add_identity(
        user_id=user_id, name="Antonia", scope="public"
    )
    # Peer als Contact eintragen (sonst kann response nicht decoded werden)
    peer = LocalIdentity.generate()
    async with sessionmaker() as db:
        db.add(
            CompanionContact(
                identity_id=loaded.id,
                peer_pubkey=peer.pub_key,
                peer_name="Drusilla",
                last_seen_at=datetime.now(UTC),
            )
        )
        await db.commit()

    # LPP-Buffer mit GPS
    lat, lon, alt = 51.1907, 6.5722, 42.0
    voltage = bytes([1, 116]) + struct.pack(">H", 385)
    lat_i, lon_i, alt_i = int(lat * 10000), int(lon * 10000), int(alt * 100)
    def b3(v: int) -> bytes:
        u = v + (1 << 24) if v < 0 else v
        return bytes([(u >> 16) & 0xFF, (u >> 8) & 0xFF, u & 0xFF])
    gps = bytes([1, 136]) + b3(lat_i) + b3(lon_i) + b3(alt_i)
    lpp_buf = voltage + gps

    # Reply-Plaintext: tag(4) + lpp_buf
    plaintext = struct.pack("<I", 0xDEADBEEF) + lpp_buf
    secret = peer.calc_shared_secret(loaded.pubkey)
    encrypted = encrypt_then_mac(secret, plaintext)
    body = loaded.pubkey[:1] + peer.pub_key[:1] + encrypted
    pkt = Packet(
        route_type=RouteType.FLOOD,
        payload_type=PayloadType.RESPONSE,
        payload=body,
    )
    await svc.on_inbound_packet(raw=pkt.encode(), scope="public")

    async with sessionmaker() as db:
        contact = (
            await db.execute(
                select(CompanionContact).where(
                    CompanionContact.identity_id == loaded.id,
                    CompanionContact.peer_pubkey == peer.pub_key,
                )
            )
        ).scalar_one()
    assert contact.last_lat is not None
    assert contact.last_lon is not None
    assert abs(contact.last_lat - lat) < 0.001
    assert abs(contact.last_lon - lon) < 0.001


@pytest.mark.asyncio
async def test_telemetry_response_zero_geo_ignored(service_env) -> None:
    """Lat=0 Lon=0 ist Default-Sentinel — nicht persistieren."""
    import struct

    svc, sessionmaker, user_id, _sent = service_env
    loaded = await svc.add_identity(
        user_id=user_id, name="Antonia", scope="public"
    )
    peer = LocalIdentity.generate()
    async with sessionmaker() as db:
        db.add(
            CompanionContact(
                identity_id=loaded.id,
                peer_pubkey=peer.pub_key,
                peer_name="ZeroGeo",
                last_seen_at=datetime.now(UTC),
            )
        )
        await db.commit()

    voltage = bytes([1, 116]) + struct.pack(">H", 385)
    gps = bytes([1, 136]) + b"\x00" * 9
    plaintext = struct.pack("<I", 1) + voltage + gps
    secret = peer.calc_shared_secret(loaded.pubkey)
    encrypted = encrypt_then_mac(secret, plaintext)
    body = loaded.pubkey[:1] + peer.pub_key[:1] + encrypted
    pkt = Packet(
        route_type=RouteType.FLOOD,
        payload_type=PayloadType.RESPONSE,
        payload=body,
    )
    await svc.on_inbound_packet(raw=pkt.encode(), scope="public")

    async with sessionmaker() as db:
        contact = (
            await db.execute(
                select(CompanionContact).where(
                    CompanionContact.identity_id == loaded.id
                )
            )
        ).scalar_one()
    assert contact.last_lat is None
    assert contact.last_lon is None


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
