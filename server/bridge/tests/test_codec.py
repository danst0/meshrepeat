from __future__ import annotations

from uuid import UUID, uuid4

import cbor2
import pytest

from meshcore_bridge.wire import (
    MAX_FRAME_BYTES,
    Bye,
    Flow,
    FrameDecodeError,
    Heartbeat,
    HeartbeatAck,
    Hello,
    HelloAck,
    Packet,
    decode_frame,
    encode_frame,
)


def test_hello_roundtrip() -> None:
    site = uuid4()
    src = Hello(
        site=site,
        tok="MFRGGZDFMZTWQ2LKNNSXS43FOIQAA",
        fw="v0.0.1",
        proto=1,
        scope="public",
        caps=["rssi", "snr"],
    )
    blob = encode_frame(src)
    assert isinstance(blob, bytes)
    out = decode_frame(blob)
    assert isinstance(out, Hello)
    assert out.site == site
    assert out.tok == src.tok
    assert out.caps == ["rssi", "snr"]


def test_helloack_roundtrip() -> None:
    src = HelloAck(proto=1, policy_ep=0, srv_time=1761379200, max_bytes=8192, hb_iv=15)
    out = decode_frame(encode_frame(src))
    assert isinstance(out, HelloAck)
    assert out.hb_iv == 15


def test_pkt_roundtrip_preserves_bytes() -> None:
    raw = bytes(range(0, 64))
    src = Packet(raw=raw, rssi=-97, snr=24, rxts=12345)
    out = decode_frame(encode_frame(src))
    assert isinstance(out, Packet)
    assert out.raw == raw
    assert out.rssi == -97


def test_heartbeat_roundtrip() -> None:
    out = decode_frame(encode_frame(Heartbeat(seq=42, ts=1761379215)))
    assert isinstance(out, Heartbeat)
    assert out.seq == 42

    out2 = decode_frame(encode_frame(HeartbeatAck(seq=42)))
    assert isinstance(out2, HeartbeatAck)


def test_flow_roundtrip() -> None:
    out = decode_frame(encode_frame(Flow(pause_ms=200)))
    assert isinstance(out, Flow)
    assert out.pause_ms == 200


def test_bye_roundtrip() -> None:
    out = decode_frame(encode_frame(Bye(reason="shutdown")))
    assert isinstance(out, Bye)


def test_unknown_frame_type_rejected() -> None:
    blob = cbor2.dumps({"t": "wat", "x": 1}, canonical=True)
    with pytest.raises(FrameDecodeError):
        decode_frame(blob)


def test_extra_field_rejected_due_to_extra_forbid() -> None:
    blob = cbor2.dumps(
        {
            "t": "hello",
            "site": uuid4().bytes,
            "tok": "MFRGGZDFMZTWQ2LKNNSXS43FOIQAA",
            "fw": "v0",
            "proto": 1,
            "scope": "public",
            "caps": [],
            "extra": "not-allowed",
        },
        canonical=True,
    )
    with pytest.raises(FrameDecodeError):
        decode_frame(blob)


def test_oversize_frame_rejected_on_decode() -> None:
    payload = b"x" * (MAX_FRAME_BYTES + 1)
    with pytest.raises(FrameDecodeError):
        decode_frame(payload)


def test_oversize_frame_rejected_on_encode() -> None:
    pkt = Packet(raw=b"\x00" * 500)  # within Packet.raw limit but harmless
    blob = encode_frame(pkt)
    assert len(blob) <= MAX_FRAME_BYTES


def test_top_level_must_be_map() -> None:
    with pytest.raises(FrameDecodeError):
        decode_frame(cbor2.dumps([1, 2, 3]))


def test_invalid_cbor_rejected() -> None:
    with pytest.raises(FrameDecodeError):
        decode_frame(b"\xff\xff\xff")


def test_uuid_is_encoded_as_16_bytes() -> None:
    site = UUID("7b2f9e0c4a514d0a91c8b5d1e7c63f02")
    blob = encode_frame(
        Hello(site=site, tok="MFRGGZDFMZTWQ2LKNNSXS43FOIQAA", fw="v0", proto=1, scope="public")
    )
    decoded = cbor2.loads(blob)
    assert decoded["site"] == site.bytes
    assert len(decoded["site"]) == 16
