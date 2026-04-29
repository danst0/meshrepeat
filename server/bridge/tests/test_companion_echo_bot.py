"""Integration: Echo-Bot-Companion antwortet auf eingehende DMs mit
Original-Text plus Mesh-Metadaten (hops/route/age/len)."""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import select

from meshcore_bridge.db import CompanionContact, CompanionIdentity
from meshcore_companion.crypto import Identity, LocalIdentity
from meshcore_companion.node import CompanionNode
from meshcore_companion.packet import Packet, PayloadType


def _make_dm_with_hops(
    sender: CompanionNode,
    *,
    peer_pubkey: bytes,
    text: str,
    timestamp: int,
    hops: int = 0,
) -> Packet:
    """DM-Paket bauen und ``hops`` mal mit Pseudo-Path-Hashes annotieren,
    damit ``pkt.hop_count`` auf der Empfänger-Seite ungleich 0 ist."""
    pkt = sender.make_dm(peer_pubkey=peer_pubkey, text=text, timestamp=timestamp)
    for i in range(hops):
        pkt.add_path_hash(bytes([0xA0 + i]))
    return pkt


async def _add_peer_contact(sessionmaker, identity_id, peer_pubkey: bytes, name: str) -> None:
    async with sessionmaker() as db:
        db.add(
            CompanionContact(
                identity_id=identity_id,
                peer_pubkey=peer_pubkey,
                peer_name=name,
                last_seen_at=datetime.now(UTC),
            )
        )
        await db.commit()


def _decode_outgoing_dm(
    sent: list[tuple[bytes, str]],
    receiver_node: CompanionNode,
    sender_pubkey: bytes,
) -> str | None:
    """Sucht in ``sent`` das erste TXT_MSG-Paket, das wir mit dem
    ``receiver_node`` als Empfänger entschlüsseln können, und gibt den
    Plaintext zurück."""
    for raw, _scope in sent:
        try:
            pkt = Packet.decode(raw)
        except ValueError:
            continue
        if pkt.payload_type != PayloadType.TXT_MSG:
            continue
        decoded = receiver_node.try_decrypt_dm(
            packet=pkt, peer_candidates=[Identity(sender_pubkey)]
        )
        if decoded is not None:
            return decoded.text
    return None


@pytest.mark.asyncio
async def test_echo_bot_replies_with_metadata(service_env) -> None:
    svc, sessionmaker, user_id, sent = service_env

    bot = await svc.add_identity(user_id=user_id, name="Echo", scope="public", is_echo=True)
    sender_local = LocalIdentity.generate()
    sender = CompanionNode(sender_local)
    await _add_peer_contact(sessionmaker, bot.id, sender.pub_key, "tester")

    ts = int(time.time()) - 3
    pkt = _make_dm_with_hops(sender, peer_pubkey=bot.pubkey, text="hallo bot", timestamp=ts, hops=1)

    sent.clear()
    await svc.on_inbound_packet(raw=pkt.encode(), scope="public")

    reply = _decode_outgoing_dm(sent, sender, bot.pubkey)
    assert reply is not None, "expected an outgoing TXT_MSG echo reply"
    assert re.match(r'^echo: "hallo bot" — hops=1 route=FLOOD age=\d+s len=9b$', reply), (
        f"unexpected reply format: {reply!r}"
    )


@pytest.mark.asyncio
async def test_echo_bot_truncates_long_text_and_reports_orig_len(service_env) -> None:
    svc, sessionmaker, user_id, sent = service_env

    bot = await svc.add_identity(user_id=user_id, name="Echo", scope="public", is_echo=True)
    sender = CompanionNode(LocalIdentity.generate())
    await _add_peer_contact(sessionmaker, bot.id, sender.pub_key, "tester")

    # 200 Byte Text bleibt unter dem TXT_MSG-Payload-Limit (~245 Byte
    # Plaintext nach Header/MAC), reißt aber sicher das ~95-Byte-Body-
    # Budget der Echo-Reply.
    long_text = "a" * 200
    ts = int(time.time())
    pkt = _make_dm_with_hops(sender, peer_pubkey=bot.pubkey, text=long_text, timestamp=ts, hops=2)

    sent.clear()
    await svc.on_inbound_packet(raw=pkt.encode(), scope="public")

    reply = _decode_outgoing_dm(sent, sender, bot.pubkey)
    assert reply is not None
    assert len(reply.encode("utf-8")) <= 140
    # Original-Länge bleibt im len=-Feld erhalten, nicht die gestutzte.
    assert "len=200b" in reply
    # Truncation-Marker.
    assert '…"' in reply


@pytest.mark.asyncio
async def test_echo_bot_does_not_loop_on_known_companion(service_env) -> None:
    svc, sessionmaker, user_id, sent = service_env

    bot_a = await svc.add_identity(user_id=user_id, name="EchoA", scope="public", is_echo=True)
    bot_b = await svc.add_identity(user_id=user_id, name="EchoB", scope="public", is_echo=True)
    # B als Contact von A registrieren, damit try_decrypt_dm die DM
    # zuordnen kann — sonst würde der Loop-Schutz nie auch nur evaluiert.
    await _add_peer_contact(sessionmaker, bot_a.id, bot_b.pubkey, "EchoB")

    ts = int(time.time())
    pkt = _make_dm_with_hops(
        bot_b.node, peer_pubkey=bot_a.pubkey, text="ping", timestamp=ts, hops=1
    )

    sent.clear()
    await svc.on_inbound_packet(raw=pkt.encode(), scope="public")

    # Es darf KEINE TXT_MSG ausgehend gewesen sein (ACK-Frames sind ok).
    txt_outgoing = [
        raw for raw, _ in sent if Packet.decode(raw).payload_type == PayloadType.TXT_MSG
    ]
    assert txt_outgoing == [], "echo bot must not reply to another known companion"


@pytest.mark.asyncio
async def test_echo_bot_replies_to_non_echo_companion(service_env) -> None:
    """Andere eigene Identity ohne is_echo darf den Bot ganz normal pingen —
    es entsteht kein Loop, weil der Sender nicht selbst echoed."""
    svc, sessionmaker, user_id, sent = service_env

    bot = await svc.add_identity(user_id=user_id, name="Echo", scope="public", is_echo=True)
    other = await svc.add_identity(user_id=user_id, name="Antonia", scope="public", is_echo=False)
    await _add_peer_contact(sessionmaker, bot.id, other.pubkey, "Antonia")

    ts = int(time.time())
    pkt = _make_dm_with_hops(other.node, peer_pubkey=bot.pubkey, text="hi", timestamp=ts, hops=1)

    sent.clear()
    await svc.on_inbound_packet(raw=pkt.encode(), scope="public")

    reply = _decode_outgoing_dm(sent, other.node, bot.pubkey)
    assert reply is not None, "echo bot should reply to a non-echo companion identity"
    assert reply.startswith('echo: "hi"')


@pytest.mark.asyncio
async def test_echo_bot_does_not_reply_on_dedup_replay(service_env) -> None:
    svc, sessionmaker, user_id, sent = service_env

    bot = await svc.add_identity(user_id=user_id, name="Echo", scope="public", is_echo=True)
    sender = CompanionNode(LocalIdentity.generate())
    await _add_peer_contact(sessionmaker, bot.id, sender.pub_key, "tester")

    ts = int(time.time())
    pkt = _make_dm_with_hops(sender, peer_pubkey=bot.pubkey, text="zwei mal", timestamp=ts, hops=1)
    raw = pkt.encode()

    sent.clear()
    await svc.on_inbound_packet(raw=raw, scope="public")
    # zweites Mal: derselbe Frame kommt vom zweiten Repeater rein —
    # der inbound-Dedup im Service muss greifen.
    await svc.on_inbound_packet(raw=raw, scope="public")

    txt_outgoing = [
        raw_b for raw_b, _ in sent if Packet.decode(raw_b).payload_type == PayloadType.TXT_MSG
    ]
    assert len(txt_outgoing) == 1, f"expected exactly one echo reply, got {len(txt_outgoing)}"


@pytest.mark.asyncio
async def test_echo_bot_disabled_identity_no_reply(service_env) -> None:
    svc, sessionmaker, user_id, sent = service_env

    plain = await svc.add_identity(user_id=user_id, name="NoEcho", scope="public", is_echo=False)
    sender = CompanionNode(LocalIdentity.generate())
    await _add_peer_contact(sessionmaker, plain.id, sender.pub_key, "tester")

    ts = int(time.time())
    pkt = _make_dm_with_hops(sender, peer_pubkey=plain.pubkey, text="hi", timestamp=ts, hops=0)

    sent.clear()
    await svc.on_inbound_packet(raw=pkt.encode(), scope="public")

    txt_outgoing = [
        raw for raw, _ in sent if Packet.decode(raw).payload_type == PayloadType.TXT_MSG
    ]
    assert txt_outgoing == []


@pytest.mark.asyncio
async def test_echo_rate_limit_skips_burst(service_env, monkeypatch) -> None:
    """Drei DMs in schneller Folge: nur die erste bekommt eine Reply,
    weil die Streak-1-Cooldown (5 s) noch greift."""
    svc, sessionmaker, user_id, sent = service_env

    bot = await svc.add_identity(user_id=user_id, name="Echo", scope="public", is_echo=True)
    sender = CompanionNode(LocalIdentity.generate())
    await _add_peer_contact(sessionmaker, bot.id, sender.pub_key, "tester")

    # Monotonic-Clock einfrieren — alle drei DMs liegen virtuell auf dem
    # gleichen Zeitpunkt, der Cooldown muss greifen.
    fake_now = [1000.0]
    monkeypatch.setattr("meshcore_companion.service.time.monotonic", lambda: fake_now[0])

    sent.clear()
    for i, ts_offset in enumerate((0, 1, 2)):
        # Jede DM braucht eine eigene wall-clock-ts, sonst dedupt der
        # CompanionMessage-existing-Lookup die zweite Reply weg und der
        # Test prüft den falschen Pfad.
        pkt = _make_dm_with_hops(
            sender,
            peer_pubkey=bot.pubkey,
            text=f"msg {i}",
            timestamp=int(time.time()) + ts_offset,
            hops=1,
        )
        await svc.on_inbound_packet(raw=pkt.encode(), scope="public")

    txt_outgoing = [
        raw for raw, _ in sent if Packet.decode(raw).payload_type == PayloadType.TXT_MSG
    ]
    assert len(txt_outgoing) == 1, f"expected 1 echo within burst, got {len(txt_outgoing)}"


def test_echo_rate_limit_doubles_cooldown_per_streak() -> None:
    """Helper direkt treiben: Cooldown 5 → 10 → 20 → 40 → ... → cap 300."""
    from meshcore_companion.service import CompanionService

    svc = CompanionService.__new__(CompanionService)
    svc._echo_rl = {}
    pk = b"\x01" * 32

    # Streak 1: bei now=0 erlauben → next_allowed_at = 5
    assert svc._echo_rate_allow(pk, 0.0) is True
    assert svc._echo_rl[pk].next_allowed_at == pytest.approx(5.0)
    # Direkt nochmal bei now=4 → blockiert (4 < 5)
    assert svc._echo_rate_allow(pk, 4.0) is False
    # Streak 2 bei now=5: cooldown 10 → next 15
    assert svc._echo_rate_allow(pk, 5.0) is True
    assert svc._echo_rl[pk].streak == 2
    assert svc._echo_rl[pk].next_allowed_at == pytest.approx(15.0)
    # Streak 3: cooldown 20
    assert svc._echo_rate_allow(pk, 15.0) is True
    assert svc._echo_rl[pk].next_allowed_at == pytest.approx(35.0)
    # Cap-Test: künstlich hohe Streak
    svc._echo_rl[pk].streak = 10
    svc._echo_rl[pk].next_allowed_at = 100.0
    svc._echo_rl[pk].last_reply_at = 100.0
    assert svc._echo_rate_allow(pk, 100.0) is True
    # Streak wäre 11 → 5*2^10=5120 s, gedeckelt bei 300 s
    assert svc._echo_rl[pk].next_allowed_at == pytest.approx(400.0)


def test_echo_rate_limit_independent_per_sender() -> None:
    from meshcore_companion.service import CompanionService

    svc = CompanionService.__new__(CompanionService)
    svc._echo_rl = {}
    pk_a = b"\x01" * 32
    pk_b = b"\x02" * 32

    assert svc._echo_rate_allow(pk_a, 0.0) is True
    # B bei demselben now muss unabhängig erlauben
    assert svc._echo_rate_allow(pk_b, 0.0) is True
    # A noch geblockt
    assert svc._echo_rate_allow(pk_a, 1.0) is False


def test_echo_rate_limit_resets_after_idle() -> None:
    """Nach _ECHO_RL_STREAK_RESET_S ohne Reply startet die Streak neu bei 1."""
    from meshcore_companion.service import CompanionService

    svc = CompanionService.__new__(CompanionService)
    svc._echo_rl = {}
    pk = b"\x01" * 32

    # Streak hochziehen.
    svc._echo_rate_allow(pk, 0.0)  # streak=1, cooldown 5
    svc._echo_rate_allow(pk, 5.0)  # streak=2, cooldown 10
    svc._echo_rate_allow(pk, 15.0)  # streak=3, cooldown 20
    assert svc._echo_rl[pk].streak == 3

    # Lange Pause — > 600 s seit last_reply (15.0).
    assert svc._echo_rate_allow(pk, 15.0 + 601.0) is True
    assert svc._echo_rl[pk].streak == 1


@pytest.mark.asyncio
async def test_set_echo_toggles_db_and_memory(service_env) -> None:
    svc, sessionmaker, user_id, _sent = service_env

    loaded = await svc.add_identity(
        user_id=user_id, name="Toggleable", scope="public", is_echo=False
    )
    assert loaded.is_echo is False

    ok = await svc.set_echo(loaded.id, True)
    assert ok is True
    assert svc.get(loaded.id).is_echo is True

    async with sessionmaker() as db:
        row = (
            await db.execute(select(CompanionIdentity).where(CompanionIdentity.id == loaded.id))
        ).scalar_one()
    assert row.is_echo is True

    # Zurückschalten.
    assert await svc.set_echo(loaded.id, False) is True
    assert svc.get(loaded.id).is_echo is False

    # Unbekannte ID liefert False.
    assert await svc.set_echo(uuid4(), True) is False
