from __future__ import annotations

import struct

from meshcore_companion.crypto import Identity, LocalIdentity, encrypt_then_mac
from meshcore_companion.node import CompanionNode, parse_lpp_gps
from meshcore_companion.packet import Packet, PayloadType, RouteType


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


# ---------- Telemetry REQ / RESPONSE ----------


def _build_lpp_gps_buffer(lat: float, lon: float, alt: float) -> bytes:
    """Synthetisiert einen LPP-Buffer mit Voltage + GPS, wie ihn die
    Firmware in einer Telemetry-Response sendet."""
    # voltage: chan=1, type=116, 2 byte BE *100
    voltage = bytes([1, 116]) + struct.pack(">H", int(3.85 * 100))
    # gps: chan=1, type=136, 3+3+3 BE signed *10000/100
    lat_i = int(lat * 10000)
    lon_i = int(lon * 10000)
    alt_i = int(alt * 100)
    gps_data = bytearray()
    for v in (lat_i, lon_i, alt_i):
        # 3-byte big-endian signed
        u = v + (1 << 24) if v < 0 else v
        gps_data += bytes([(u >> 16) & 0xFF, (u >> 8) & 0xFF, u & 0xFF])
    gps = bytes([1, 136]) + bytes(gps_data)
    return voltage + gps


def test_telemetry_req_encrypts_to_peer() -> None:
    alice = CompanionNode(LocalIdentity.generate())
    bob = CompanionNode(LocalIdentity.generate())
    pkt, tag = alice.make_telemetry_req(peer_pubkey=bob.pub_key, tag=12345)
    assert pkt.payload_type == PayloadType.REQ
    assert pkt.route_type == RouteType.FLOOD
    assert tag == 12345
    # Bob soll mit alice als sender_candidate die RESPONSE-Decrypt-Richtung
    # NICHT direkt nutzen (REQ ist nicht response). Aber wir können den
    # plaintext per ECDH manuell verifizieren.
    body = pkt.payload
    dest_hash = body[:1]
    assert dest_hash == bob.pub_key[:1]


def test_response_decrypt_roundtrip() -> None:
    """Alice schickt simulierten RESPONSE (manuell konstruiert) an Bob;
    Bob entschlüsselt und extrahiert tag + reply_data."""
    alice = CompanionNode(LocalIdentity.generate())
    bob = CompanionNode(LocalIdentity.generate())

    secret = alice.local.calc_shared_secret(bob.pub_key)
    reply_data = b"\xff" * 8
    plaintext = struct.pack("<I", 0xABCD1234) + reply_data
    encrypted = encrypt_then_mac(secret, plaintext)
    body = bob.pub_key[:1] + alice.pub_key[:1] + encrypted
    pkt = Packet(
        route_type=RouteType.FLOOD,
        payload_type=PayloadType.RESPONSE,
        payload=body,
    )
    decoded = bob.try_decrypt_response(
        packet=pkt, peer_candidates=[Identity(alice.pub_key)]
    )
    assert decoded is not None
    assert decoded.tag == 0xABCD1234
    assert decoded.sender_pubkey == alice.pub_key
    # ciphertext-AES-Padding: encrypted plaintext-Length (12) wird auf 16
    # aufgepadded mit Nullen — beim Decrypt sehen wir die zero-padded Form.
    assert decoded.reply_data.startswith(reply_data)


def test_response_decrypt_wrong_peer_returns_none() -> None:
    alice = CompanionNode(LocalIdentity.generate())
    bob = CompanionNode(LocalIdentity.generate())
    eve = CompanionNode(LocalIdentity.generate())

    secret = alice.local.calc_shared_secret(bob.pub_key)
    plaintext = struct.pack("<I", 1) + b"x"
    encrypted = encrypt_then_mac(secret, plaintext)
    body = bob.pub_key[:1] + alice.pub_key[:1] + encrypted
    pkt = Packet(
        route_type=RouteType.FLOOD,
        payload_type=PayloadType.RESPONSE,
        payload=body,
    )
    # Bob versucht mit Eve als Kandidat — passt nicht, src_hash matched
    # vielleicht zufällig, MAC schlägt aber fehl
    res = bob.try_decrypt_response(
        packet=pkt, peer_candidates=[Identity(eve.pub_key)]
    )
    # entweder src_hash mismatch oder MAC mismatch
    if res is not None:
        # Bei zufälliger Kollision der Hash-Prefixes (1/256) → MAC sollte greifen
        # Wir akzeptieren nur, wenn MAC-Decrypt fehlschlägt (Result None)
        assert res is None  # provoziert Fehler


def test_parse_lpp_gps_extracts_geo() -> None:
    buf = _build_lpp_gps_buffer(lat=51.1907, lon=6.5722, alt=42.0)
    gps = parse_lpp_gps(buf)
    assert gps is not None
    assert gps.lat == round(int(51.1907 * 10000) / 10000.0, 4)
    assert gps.lon == round(int(6.5722 * 10000) / 10000.0, 4)
    assert gps.alt == round(int(42.0 * 100) / 100.0, 2)


def test_parse_lpp_gps_negative_coords() -> None:
    buf = _build_lpp_gps_buffer(lat=-33.8688, lon=151.2093, alt=58.0)
    gps = parse_lpp_gps(buf)
    assert gps is not None
    assert gps.lat < 0
    assert abs(gps.lat - (-33.8688)) < 0.001
    assert abs(gps.lon - 151.2093) < 0.001


def test_parse_lpp_gps_no_gps_returns_none() -> None:
    # nur voltage, kein GPS
    voltage = bytes([1, 116]) + struct.pack(">H", 385)
    assert parse_lpp_gps(voltage) is None


def test_parse_lpp_gps_unknown_type_aborts() -> None:
    # type 99 ist nicht in der size-map → abort
    buf = bytes([1, 99, 0xFF])
    assert parse_lpp_gps(buf) is None
