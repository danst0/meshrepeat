from __future__ import annotations

import pytest

from meshcore_companion.crypto import LocalIdentity
from meshcore_companion.packet import Advert, Packet, PayloadType, RouteType


def test_packet_encode_decode_minimal() -> None:
    p = Packet(
        route_type=RouteType.FLOOD,
        payload_type=PayloadType.ADVERT,
        payload=b"ABCD",
    )
    raw = p.encode()
    decoded = Packet.decode(raw)
    assert decoded.route_type == RouteType.FLOOD
    assert decoded.payload_type == PayloadType.ADVERT
    assert decoded.payload == b"ABCD"
    assert decoded.path == b""
    assert decoded.hop_count == 0


def test_packet_encode_with_path_hashes() -> None:
    p = Packet(
        route_type=RouteType.FLOOD,
        payload_type=PayloadType.TXT_MSG,
        hash_size=1,
        path=bytes([0x11, 0x22, 0x33]),
        payload=b"\xff\xfe",
    )
    raw = p.encode()
    decoded = Packet.decode(raw)
    assert decoded.hop_count == 3
    assert decoded.path == bytes([0x11, 0x22, 0x33])
    assert decoded.payload == b"\xff\xfe"


def test_packet_with_transport_codes_roundtrip() -> None:
    p = Packet(
        route_type=RouteType.TRANSPORT_FLOOD,
        payload_type=PayloadType.ADVERT,
        transport_codes=(0x1234, 0xCAFE),
        payload=b"\x01\x02\x03",
    )
    raw = p.encode()
    assert raw[0] & 0x03 == RouteType.TRANSPORT_FLOOD.value
    # 4 transport-bytes erscheinen direkt nach dem header
    assert raw[1:5] == b"\x34\x12\xfe\xca"
    decoded = Packet.decode(raw)
    assert decoded.transport_codes == (0x1234, 0xCAFE)


def test_packet_decode_rejects_short() -> None:
    with pytest.raises(ValueError):
        Packet.decode(b"")
    with pytest.raises(ValueError):
        Packet.decode(b"\x00")


def test_packet_decode_rejects_reserved_hash_size() -> None:
    # path_len with hash_size=4 (encoded as 0b11 in upper 2 bits)
    raw = bytes([0b01_0000_00, 0b11_000000])
    with pytest.raises(ValueError):
        Packet.decode(raw)


def test_packet_add_path_hash_grows_path() -> None:
    p = Packet(hash_size=1)
    p.add_path_hash(b"\xab")
    p.add_path_hash(b"\xcd")
    assert p.path == b"\xab\xcd"
    assert p.hop_count == 2


def test_advert_signed_message_layout() -> None:
    li = LocalIdentity.generate()
    a = Advert(pubkey=li.pub_key, timestamp=1761379200, app_data=b"name=Alice")
    msg = a.signed_message
    assert msg[:32] == li.pub_key
    assert int.from_bytes(msg[32:36], "little") == 1761379200
    assert msg[36:] == b"name=Alice"


def test_advert_sign_decode_verify_roundtrip() -> None:
    li = LocalIdentity.generate()
    a = Advert(pubkey=li.pub_key, timestamp=1, app_data=b"R")
    a.signature = li.sign(a.signed_message)
    raw = a.encode()
    decoded = Advert.decode(raw)
    assert decoded.pubkey == li.pub_key
    assert decoded.timestamp == 1
    assert decoded.app_data == b"R"
    assert decoded.signature == a.signature
    # Signatur ist gegen pubkey + ts + app_data, nicht gegen sig selbst
    from meshcore_companion.crypto import Identity

    assert Identity(li.pub_key).verify(decoded.signature, decoded.signed_message)


def test_advert_decode_rejects_short_payload() -> None:
    with pytest.raises(ValueError):
        Advert.decode(b"\x00" * 50)
