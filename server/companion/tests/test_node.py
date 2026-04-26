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


# ---------- DM flags-Byte + ACK-Hash + PATH-Return ----------


def test_dm_includes_flags_byte_in_plaintext() -> None:
    """make_dm muss flags=0 zwischen ts und text einfügen, sonst lehnt
    die MeshCore-Firmware (BaseChatMesh.cpp:217) das Paket ab."""
    from meshcore_companion.crypto import mac_then_decrypt

    alice = CompanionNode(LocalIdentity.generate())
    bob = CompanionNode(LocalIdentity.generate())
    pkt = alice.make_dm(peer_pubkey=bob.pub_key, text="hi", timestamp=42)
    body = pkt.payload
    encrypted = body[2:]
    secret = bob.local.calc_shared_secret(alice.pub_key)
    plain = mac_then_decrypt(secret, encrypted)
    assert plain is not None
    # ts(4) + flags(1) + "hi" = 7 byte real, AES-padded auf 16
    assert plain[:4] == struct.pack("<I", 42)
    assert plain[4] == 0  # flags = TXT_TYPE_PLAIN, attempt=0
    assert plain[5:7] == b"hi"


def test_dm_decoder_skips_flags_byte() -> None:
    """try_decrypt_dm muss flags-Byte überspringen, sonst landet \\x00
    am Anfang des Texts."""
    alice = CompanionNode(LocalIdentity.generate())
    bob = CompanionNode(LocalIdentity.generate())
    pkt = alice.make_dm(peer_pubkey=bob.pub_key, text="Test", timestamp=99)
    decoded = bob.try_decrypt_dm(packet=pkt, peer_candidates=[Identity(alice.pub_key)])
    assert decoded is not None
    assert decoded.text == "Test"  # NICHT "\x00Test"
    assert decoded.flags == 0


def test_dm_decoder_rejects_non_plain_txt_type() -> None:
    """txt_type != 0 (z.B. CLI_DATA) muss verworfen werden."""
    from meshcore_companion.crypto import encrypt_then_mac

    alice = CompanionNode(LocalIdentity.generate())
    bob = CompanionNode(LocalIdentity.generate())
    secret = alice.local.calc_shared_secret(bob.pub_key)
    # txt_type = 2 (CLI_DATA) → flags-Byte = 2 << 2 = 0x08
    plain = struct.pack("<I", 1) + bytes([0x08]) + b"clidata"
    encrypted = encrypt_then_mac(secret, plain)
    body = bob.pub_key[:1] + alice.pub_key[:1] + encrypted
    pkt = Packet(
        route_type=RouteType.FLOOD,
        payload_type=PayloadType.TXT_MSG,
        payload=body,
    )
    decoded = bob.try_decrypt_dm(packet=pkt, peer_candidates=[Identity(alice.pub_key)])
    assert decoded is None


def test_dm_ack_hash_matches_firmware_formula() -> None:
    """ack_hash = sha256(ts || flags || text || sender_pubkey)[:4]"""
    import hashlib

    from meshcore_companion.node import compute_dm_ack_hash

    sender_pk = bytes(range(32))
    expected = hashlib.sha256(
        struct.pack("<I", 1234) + bytes([0]) + b"hello" + sender_pk
    ).digest()[:4]
    actual = compute_dm_ack_hash(
        timestamp=1234, flags=0, text_bytes=b"hello", sender_pubkey=sender_pk
    )
    assert actual == expected


def test_make_ack_wire_format() -> None:
    """ACK-Frame: payload_type=ACK, payload = 4-Byte-Hash unverschlüsselt
    (firmware Mesh::createAck Mesh.cpp:546)."""
    alice = CompanionNode(LocalIdentity.generate())
    ack_hash = b"\xde\xad\xbe\xef"
    pkt = alice.make_ack(ack_hash)
    assert pkt.payload_type == PayloadType.ACK
    assert pkt.route_type == RouteType.FLOOD
    assert pkt.payload == ack_hash


def test_make_ack_rejects_wrong_length() -> None:
    import pytest

    alice = CompanionNode(LocalIdentity.generate())
    with pytest.raises(ValueError):
        alice.make_ack(b"\x00\x01\x02")  # nur 3 Byte


def test_path_return_wire_format() -> None:
    """PATH-Datagram: payload = dest_hash + src_hash + encrypt_then_mac(
    path_len_byte + path_bytes + extra_type + extra_data)."""
    from meshcore_companion.crypto import mac_then_decrypt

    alice = CompanionNode(LocalIdentity.generate())
    bob = CompanionNode(LocalIdentity.generate())
    rx_path = b"\xaa\xbb"
    rx_path_len_byte = 0x02  # hash_size=1 (top 2 bits=0), hop_count=2
    ack_hash = b"\x01\x02\x03\x04"
    pkt = bob.make_path_return(
        peer_pubkey=alice.pub_key,
        rx_path_len_byte=rx_path_len_byte,
        rx_path_bytes=rx_path,
        extra_type=int(PayloadType.ACK),
        extra_data=ack_hash,
    )
    assert pkt.payload_type == PayloadType.PATH
    assert pkt.payload[:1] == alice.pub_key[:1]
    assert pkt.payload[1:2] == bob.pub_key[:1]
    encrypted = pkt.payload[2:]
    secret = alice.local.calc_shared_secret(bob.pub_key)
    plain = mac_then_decrypt(secret, encrypted)
    assert plain is not None
    assert plain[0] == rx_path_len_byte
    assert plain[1:3] == rx_path
    assert plain[3] == int(PayloadType.ACK)
    assert plain[4:8] == ack_hash
