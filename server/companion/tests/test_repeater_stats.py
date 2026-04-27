"""Unit-Test für ``parse_repeater_stats`` — packte Layout matchen
firmware ``RepeaterStats``-Struct (56 Byte, native LE, kein Padding)."""

from __future__ import annotations

import struct

from meshcore_companion.crypto import LocalIdentity
from meshcore_companion.node import (
    CompanionNode,
    LoginResponse,
    parse_login_response,
    parse_repeater_stats,
)
from meshcore_companion.packet import PayloadType


def test_parse_repeater_stats_round_trip() -> None:
    # Pack genau in der Reihenfolge der Struct-Definition aus
    # firmware/src/MyMesh.h:47.
    raw = struct.pack(
        "<HHhhIIIIIIIIHhHHII",
        3812,           # batt_milli_volts
        2,              # curr_tx_queue_len
        -118,           # noise_floor
        -85,            # last_rssi
        12345,          # n_packets_recv
        9876,           # n_packets_sent
        420,            # total_air_time_secs
        86400,          # total_up_time_secs (1 Tag)
        100, 200,       # n_sent_flood, n_sent_direct
        300, 400,       # n_recv_flood, n_recv_direct
        7,              # err_events
        24,             # last_snr_q (24 / 4 = 6 dB)
        5, 11,          # n_direct_dups, n_flood_dups
        180,            # total_rx_air_time_secs
        2,              # n_recv_errors
    )
    assert len(raw) == 56

    stats = parse_repeater_stats(raw)
    assert stats is not None
    assert stats.batt_milli_volts == 3812
    assert stats.battery_volts == 3.812
    assert stats.last_rssi == -85
    assert stats.last_snr_q == 24
    assert stats.snr_db == 6.0
    assert stats.total_up_time_secs == 86400
    assert stats.n_packets_recv == 12345
    assert stats.n_packets_sent == 9876
    assert stats.n_sent_flood == 100
    assert stats.n_recv_direct == 400
    assert stats.err_events == 7
    assert stats.n_direct_dups == 5
    assert stats.n_flood_dups == 11


def test_parse_repeater_stats_too_short() -> None:
    assert parse_repeater_stats(b"\x00" * 30) is None


def test_parse_login_response_ok() -> None:
    # reply[0]=0 (RESP_SERVER_LOGIN_OK), reply[1]=0, reply[2]=1 (admin),
    # reply[3]=0xc1 (perms), Rest egal
    buf = bytes([0x00, 0x00, 0x01, 0xC1, 0xDE, 0xAD])
    login = parse_login_response(buf)
    assert isinstance(login, LoginResponse)
    assert login.is_admin is True
    assert login.permissions == 0xC1


def test_parse_login_response_not_login() -> None:
    # buf[0] != 0 → keine Login-Antwort
    assert parse_login_response(bytes([0xFF, 0, 0, 0])) is None


def test_make_anon_login_req_wire_format() -> None:
    """Wire: payload_type=ANON_REQ, body = dest_hash(1) + sender_pub(32) +
    encrypted. Plaintext-Länge = 4 (ts) + len(pw) + 1 (\\0).
    encrypted = plaintext + MAC (encrypt_then_mac fügt MAC an)."""
    sender = LocalIdentity.generate()
    peer_pubkey = LocalIdentity.generate().pub_key
    node = CompanionNode(sender)
    pkt, tag = node.make_anon_login_req(peer_pubkey=peer_pubkey, password="")
    assert pkt.payload_type == PayloadType.ANON_REQ
    # Body-Header: 1B dest_hash + 32B sender_pubkey
    assert pkt.payload[0:1] == peer_pubkey[:1]
    assert pkt.payload[1:33] == sender.pub_key
    # encrypted-Teil hat mind. plaintext_len(=5 für "" + null) + MAC
    assert len(pkt.payload) > 1 + 32 + 5
    assert tag > 0
