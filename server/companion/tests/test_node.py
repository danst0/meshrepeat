from __future__ import annotations

from meshcore_companion.crypto import Identity, LocalIdentity
from meshcore_companion.node import CompanionNode
from meshcore_companion.packet import PayloadType, RouteType


def test_make_advert_signs_correctly() -> None:
    li = LocalIdentity.generate()
    node = CompanionNode(li)
    pkt = node.make_advert(timestamp=42, app_data=b"alice", flood=True)
    assert pkt.route_type == RouteType.FLOOD
    assert pkt.payload_type == PayloadType.ADVERT
    # Wenn wir ihn zurück-parsen und verifizieren, klappt's.
    parsed = node.parse_inbound_advert(pkt)
    assert parsed is not None
    assert parsed.pubkey == li.pub_key
    assert parsed.timestamp == 42
    assert parsed.app_data == b"alice"


def test_dm_encrypt_decrypt_roundtrip() -> None:
    alice = CompanionNode(LocalIdentity.generate())
    bob = CompanionNode(LocalIdentity.generate())
    pkt = alice.make_dm(peer_pubkey=bob.pub_key, text="hi bob", timestamp=12345)
    assert pkt.payload_type == PayloadType.TXT_MSG
    decoded = bob.try_decrypt_dm(packet=pkt, peer_candidates=[Identity(alice.pub_key)])
    assert decoded is not None
    assert decoded.sender_pubkey == alice.pub_key
    assert decoded.timestamp == 12345
    assert decoded.text == "hi bob"


def test_dm_for_other_recipient_returns_none() -> None:
    alice = CompanionNode(LocalIdentity.generate())
    bob = CompanionNode(LocalIdentity.generate())
    eve = CompanionNode(LocalIdentity.generate())
    pkt = alice.make_dm(peer_pubkey=bob.pub_key, text="secret")
    decoded = eve.try_decrypt_dm(packet=pkt, peer_candidates=[Identity(alice.pub_key)])
    # eve's pub_hash matchet vermutlich nicht mit dem dest_hash → schon hier raus
    assert decoded is None


def test_dm_with_unknown_sender_pubkey_returns_none() -> None:
    alice = CompanionNode(LocalIdentity.generate())
    bob = CompanionNode(LocalIdentity.generate())
    pkt = alice.make_dm(peer_pubkey=bob.pub_key, text="hi")
    # Bob hat alice nicht in candidates
    decoded = bob.try_decrypt_dm(packet=pkt, peer_candidates=[])
    assert decoded is None


def test_advert_with_tampered_signature_rejected() -> None:
    li = LocalIdentity.generate()
    node = CompanionNode(li)
    pkt = node.make_advert(timestamp=1, app_data=b"x")
    # Flip ein Sig-Byte (offset 32+4 = 36 in Advert-Payload)
    payload = bytearray(pkt.payload)
    payload[36] ^= 0x01
    pkt.payload = bytes(payload)
    assert node.parse_inbound_advert(pkt) is None
