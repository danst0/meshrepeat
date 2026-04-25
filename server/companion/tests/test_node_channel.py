"""Tests für GRP_TXT-Channel-Encoding (CompanionNode.make_channel_message).

Decoding/Empfang ist in Phase 5 noch nicht implementiert, daher
verifizieren wir hier wire-Format und Roundtrip-Decrypt manuell.
"""

from __future__ import annotations

import hashlib

from meshcore_companion.crypto import (
    PATH_HASH_SIZE,
    LocalIdentity,
    derive_channel_secret,
    mac_then_decrypt,
)
from meshcore_companion.node import CompanionNode
from meshcore_companion.packet import PayloadType, RouteType


def _channel_hash(secret: bytes) -> bytes:
    return hashlib.sha256(secret).digest()[:PATH_HASH_SIZE]


def test_make_channel_message_wire_format() -> None:
    secret = derive_channel_secret("public", "public")
    chash = _channel_hash(secret)

    alice = CompanionNode(LocalIdentity.generate())
    pkt = alice.make_channel_message(
        channel_secret=secret,
        channel_hash=chash,
        text="hello world",
        sender_name="alice",
        timestamp=0xDEADBEEF,
    )

    assert pkt.route_type == RouteType.FLOOD
    assert pkt.payload_type == PayloadType.GRP_TXT
    # Payload startet mit 1-Byte-Channel-Hash
    assert pkt.payload[:1] == chash
    # Rest ist mac(2) || ciphertext (16-byte-aligned)
    rest = pkt.payload[1:]
    assert len(rest) >= 2
    assert (len(rest) - 2) % 16 == 0


def test_channel_message_roundtrip_decrypt() -> None:
    secret = derive_channel_secret("alpha", "secret")
    chash = _channel_hash(secret)

    alice = CompanionNode(LocalIdentity.generate())
    pkt = alice.make_channel_message(
        channel_secret=secret,
        channel_hash=chash,
        text="hi channel",
        sender_name="alice",
        timestamp=12345,
    )

    encrypted = pkt.payload[PATH_HASH_SIZE:]
    plain = mac_then_decrypt(secret, encrypted)
    assert plain is not None

    # Wire-Format: ts(4LE) || txt_type(1) || "<sender>: " || text
    ts = int.from_bytes(plain[:4], "little", signed=False)
    assert ts == 12345
    assert plain[4] == 0  # TXT_TYPE_PLAIN
    body = plain[5:].rstrip(b"\x00").decode("utf-8")
    assert body == "alice: hi channel"


def test_channel_message_wrong_secret_rejects_mac() -> None:
    secret_ok = derive_channel_secret("a", "p1")
    secret_bad = derive_channel_secret("a", "p2")

    alice = CompanionNode(LocalIdentity.generate())
    pkt = alice.make_channel_message(
        channel_secret=secret_ok,
        channel_hash=_channel_hash(secret_ok),
        text="hi",
        sender_name="alice",
        timestamp=1,
    )
    plain = mac_then_decrypt(secret_bad, pkt.payload[PATH_HASH_SIZE:])
    assert plain is None


def test_channel_message_empty_sender_name() -> None:
    secret = derive_channel_secret("c", "p")
    chash = _channel_hash(secret)
    alice = CompanionNode(LocalIdentity.generate())
    pkt = alice.make_channel_message(
        channel_secret=secret,
        channel_hash=chash,
        text="anon",
        sender_name=None,
        timestamp=7,
    )
    plain = mac_then_decrypt(secret, pkt.payload[PATH_HASH_SIZE:])
    assert plain is not None
    body = plain[5:].rstrip(b"\x00").decode("utf-8")
    assert body == ": anon"
