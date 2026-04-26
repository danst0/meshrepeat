"""Tests für GRP_TXT-Channel-Encoding (CompanionNode.make_channel_message)
und -Decoding (try_decrypt_grp_txt).
"""

from __future__ import annotations

import hashlib

from meshcore_companion.crypto import (
    PATH_HASH_SIZE,
    LocalIdentity,
    derive_channel_secret,
    encrypt_then_mac,
    mac_then_decrypt,
)
from meshcore_companion.node import CompanionNode, try_decrypt_grp_txt
from meshcore_companion.packet import Packet, PayloadType, RouteType


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


# ---------- try_decrypt_grp_txt ----------


def test_decrypt_grp_txt_roundtrip() -> None:
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
    decoded = try_decrypt_grp_txt(packet=pkt, channels=[(chash, secret)])
    assert decoded is not None
    assert decoded.timestamp == 12345
    assert decoded.sender_name == "alice"
    assert decoded.text == "hi channel"
    assert decoded.channel_secret == secret


def test_decrypt_grp_txt_picks_matching_channel() -> None:
    s1 = derive_channel_secret("a", "p1")
    s2 = derive_channel_secret("b", "p2")
    h1, h2 = _channel_hash(s1), _channel_hash(s2)
    alice = CompanionNode(LocalIdentity.generate())
    pkt = alice.make_channel_message(
        channel_secret=s2, channel_hash=h2, text="x", sender_name="a", timestamp=1
    )
    decoded = try_decrypt_grp_txt(packet=pkt, channels=[(h1, s1), (h2, s2)])
    assert decoded is not None
    assert decoded.channel_secret == s2


def test_decrypt_grp_txt_no_hash_match_returns_none() -> None:
    s1 = derive_channel_secret("a", "p1")
    s2 = derive_channel_secret("b", "p2")
    h1, h2 = _channel_hash(s1), _channel_hash(s2)
    if h1 == h2:  # 1-byte hashes können kollidieren — Test ist dann moot
        return
    alice = CompanionNode(LocalIdentity.generate())
    pkt = alice.make_channel_message(
        channel_secret=s2, channel_hash=h2, text="x", sender_name="a", timestamp=1
    )
    assert try_decrypt_grp_txt(packet=pkt, channels=[(h1, s1)]) is None


def test_decrypt_grp_txt_wrong_secret_returns_none() -> None:
    """Ein Channel mit gleichem 1-Byte-Hash aber falschem Secret schlägt am
    MAC fehl. Wir simulieren den Hash-Match, indem wir denselben Hash
    angeben aber falsches Secret verwenden."""
    s1 = derive_channel_secret("a", "p1")
    s_bad = derive_channel_secret("a", "different")
    chash = _channel_hash(s1)
    alice = CompanionNode(LocalIdentity.generate())
    pkt = alice.make_channel_message(
        channel_secret=s1, channel_hash=chash, text="x", sender_name="a", timestamp=1
    )
    assert try_decrypt_grp_txt(packet=pkt, channels=[(chash, s_bad)]) is None


def test_decrypt_grp_txt_too_short_body() -> None:
    pkt = Packet(
        route_type=RouteType.FLOOD,
        payload_type=PayloadType.GRP_TXT,
        payload=b"\x00",  # nur Hash, kein MAC + Body
    )
    assert try_decrypt_grp_txt(packet=pkt, channels=[(b"\x00", b"\x00" * 32)]) is None


def test_decrypt_grp_txt_rejects_high_txt_type_bits() -> None:
    secret = derive_channel_secret("c", "p")
    chash = _channel_hash(secret)
    # synthetisch: txt_type-Byte mit gesetztem high bit → muss verworfen werden
    plain = (1234).to_bytes(4, "little") + bytes([0x80]) + b"alice: hi"
    encrypted = encrypt_then_mac(secret, plain)
    pkt = Packet(
        route_type=RouteType.FLOOD,
        payload_type=PayloadType.GRP_TXT,
        payload=chash + encrypted,
    )
    assert try_decrypt_grp_txt(packet=pkt, channels=[(chash, secret)]) is None


def test_decrypt_grp_txt_wrong_payload_type() -> None:
    # ein TXT_MSG-Paket darf den Channel-Decoder nicht triggern
    pkt = Packet(
        route_type=RouteType.FLOOD,
        payload_type=PayloadType.TXT_MSG,
        payload=b"\x00" * 32,
    )
    assert try_decrypt_grp_txt(packet=pkt, channels=[(b"\x00", b"\x00" * 32)]) is None
