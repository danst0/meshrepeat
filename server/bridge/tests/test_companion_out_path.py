"""Tests für das Out-Path-Lernen + DIRECT-DM-Routing.

Verifiziert:
* PATH-Returns vom Peer aktualisieren ``CompanionContact.out_path``.
* Folge-DMs an einen Peer mit gelerntem Path gehen DIRECT statt FLOOD.
* Eingehende ACKs entfernen den Pending-Eintrag, sodass der Timeout-Task
  no-op wird (out_path bleibt erhalten).
* Bei ausbleibendem ACK invalidiert der Timeout-Task den out_path
  (Mesh-Topologie-Änderung simuliert).
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from meshcore_bridge.db import CompanionContact
from meshcore_companion.crypto import LocalIdentity
from meshcore_companion.node import CompanionNode, compute_dm_ack_hash
from meshcore_companion.packet import Packet, PayloadType, RouteType


async def _add_peer_contact(sessionmaker, identity_id, peer_pubkey: bytes) -> None:
    async with sessionmaker() as db:
        db.add(
            CompanionContact(
                identity_id=identity_id,
                peer_pubkey=peer_pubkey,
                peer_name="peer",
                last_seen_at=datetime.now(UTC),
            )
        )
        await db.commit()


async def _get_contact(sessionmaker, identity_id, peer_pubkey: bytes) -> CompanionContact:
    async with sessionmaker() as db:
        return (
            await db.execute(
                select(CompanionContact).where(
                    CompanionContact.identity_id == identity_id,
                    CompanionContact.peer_pubkey == peer_pubkey,
                )
            )
        ).scalar_one()


@pytest.mark.asyncio
async def test_path_return_persists_out_path(service_env) -> None:
    """Peer schickt einen PATH-Return an die Identity → out_path wird im
    Contact gespeichert (firmware-Konvention: 1:1 die Bytes vom Peer)."""
    svc, sessionmaker, user_id, _sent = service_env

    me = await svc.add_identity(user_id=user_id, name="Me", scope="public")
    peer = CompanionNode(LocalIdentity.generate())
    await _add_peer_contact(sessionmaker, me.id, peer.pub_key)

    fake_path = b"\xa1\xa2\xa3"  # 3 Hops, hash_size=1
    rx_path_len_byte = len(fake_path)  # hash_size=1 → high bits 0
    path_pkt = peer.make_path_return(
        peer_pubkey=me.pubkey,
        rx_path_len_byte=rx_path_len_byte,
        rx_path_bytes=fake_path,
        extra_type=int(PayloadType.ACK),
        extra_data=b"\xde\xad\xbe\xef",
    )
    await svc.on_inbound_packet(raw=path_pkt.encode(), scope="public")

    contact = await _get_contact(sessionmaker, me.id, peer.pub_key)
    assert contact.out_path == fake_path
    assert contact.out_path_updated_at is not None


@pytest.mark.asyncio
async def test_send_dm_uses_flood_when_no_out_path(service_env) -> None:
    """Default-Verhalten: ohne gelernten Path → FLOOD."""
    svc, sessionmaker, user_id, sent = service_env

    me = await svc.add_identity(user_id=user_id, name="Me", scope="public")
    peer = CompanionNode(LocalIdentity.generate())
    await _add_peer_contact(sessionmaker, me.id, peer.pub_key)

    sent.clear()
    ok = await svc.send_dm(identity_id=me.id, peer_pubkey=peer.pub_key, text="hi")
    assert ok

    raws = [
        Packet.decode(r)
        for r, _ in sent
        if Packet.decode(r).payload_type == PayloadType.TXT_MSG
    ]
    assert len(raws) == 1
    assert raws[0].route_type == RouteType.FLOOD
    assert raws[0].path == b""


@pytest.mark.asyncio
async def test_send_dm_uses_direct_with_learned_path(service_env) -> None:
    """Nach gelerntem Path: send_dm geht DIRECT mit den gelernten Path-
    Bytes; ACK-Hash ist im Pending-Pool getrackt."""
    svc, sessionmaker, user_id, sent = service_env

    me = await svc.add_identity(user_id=user_id, name="Me", scope="public")
    peer = CompanionNode(LocalIdentity.generate())
    await _add_peer_contact(sessionmaker, me.id, peer.pub_key)

    # Path manuell ins Contact schreiben (Test simuliert vorheriges PATH-RX).
    fake_path = b"\xb1\xb2"
    async with sessionmaker() as db:
        contact = (
            await db.execute(
                select(CompanionContact).where(
                    CompanionContact.identity_id == me.id,
                    CompanionContact.peer_pubkey == peer.pub_key,
                )
            )
        ).scalar_one()
        contact.out_path = fake_path
        contact.out_path_updated_at = datetime.now(UTC)
        await db.commit()

    sent.clear()
    ok = await svc.send_dm(identity_id=me.id, peer_pubkey=peer.pub_key, text="ping")
    assert ok

    txt = [
        Packet.decode(r)
        for r, _ in sent
        if Packet.decode(r).payload_type == PayloadType.TXT_MSG
    ]
    assert len(txt) == 1
    assert txt[0].route_type == RouteType.DIRECT
    assert txt[0].path == fake_path

    # Pending-Pool muss exakt einen Eintrag haben (mit dem erwarteten ack_hash).
    assert len(svc._pending_dms) == 1


@pytest.mark.asyncio
async def test_inbound_ack_clears_pending_dm(service_env) -> None:
    """Inbound ACK-Frame mit passendem Hash entfernt den Pending-Eintrag,
    sodass der Timeout-Task danach no-op ist."""
    svc, sessionmaker, user_id, _sent = service_env

    me = await svc.add_identity(user_id=user_id, name="Me", scope="public")
    peer = CompanionNode(LocalIdentity.generate())
    await _add_peer_contact(sessionmaker, me.id, peer.pub_key)

    fake_path = b"\xc1"
    async with sessionmaker() as db:
        contact = (
            await db.execute(
                select(CompanionContact).where(
                    CompanionContact.identity_id == me.id,
                    CompanionContact.peer_pubkey == peer.pub_key,
                )
            )
        ).scalar_one()
        contact.out_path = fake_path
        await db.commit()

    text = "ack-test"
    ts = int(time.time())
    expected_ack = compute_dm_ack_hash(
        timestamp=ts, flags=0, text_bytes=text.encode("utf-8"), sender_pubkey=me.pubkey
    )

    # send_dm verwendet time.time() — wir frieren es nicht ein, sondern
    # rechnen den ACK-Hash mit dem gleich-fixierten Timestamp aus.
    # Workaround: send_dm direkt mit unserem ts wäre umständlich, also
    # lesen wir den tatsächlich getrackten ack_hash aus _pending_dms.
    await svc.send_dm(identity_id=me.id, peer_pubkey=peer.pub_key, text=text)
    assert len(svc._pending_dms) == 1
    actual_ack = next(iter(svc._pending_dms))
    _ = expected_ack  # nur zur Doku; tatsächlicher Hash hängt vom send_dm-ts ab

    ack_pkt = Packet(
        route_type=RouteType.FLOOD,
        payload_type=PayloadType.ACK,
        payload=actual_ack,
    )
    await svc.on_inbound_packet(raw=ack_pkt.encode(), scope="public")
    assert svc._pending_dms == {}


@pytest.mark.asyncio
async def test_dm_timeout_invalidates_out_path(service_env, monkeypatch) -> None:
    """Wenn kein ACK in ``_DM_DIRECT_TIMEOUT_S`` ankommt, wird out_path
    auf NULL gesetzt → nächstes send_dm geht wieder per FLOOD."""
    svc, sessionmaker, user_id, _sent = service_env

    monkeypatch.setattr(type(svc), "_DM_DIRECT_TIMEOUT_S", 0.05)

    me = await svc.add_identity(user_id=user_id, name="Me", scope="public")
    peer = CompanionNode(LocalIdentity.generate())
    await _add_peer_contact(sessionmaker, me.id, peer.pub_key)

    fake_path = b"\xd1\xd2"
    async with sessionmaker() as db:
        contact = (
            await db.execute(
                select(CompanionContact).where(
                    CompanionContact.identity_id == me.id,
                    CompanionContact.peer_pubkey == peer.pub_key,
                )
            )
        ).scalar_one()
        contact.out_path = fake_path
        await db.commit()

    await svc.send_dm(identity_id=me.id, peer_pubkey=peer.pub_key, text="will-timeout")
    assert len(svc._pending_dms) == 1

    await asyncio.sleep(0.15)  # > Timeout

    contact_after = await _get_contact(sessionmaker, me.id, peer.pub_key)
    assert contact_after.out_path is None
    assert svc._pending_dms == {}
