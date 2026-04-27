"""Unit-Test für ``parse_repeater_stats`` — packte Layout matchen
firmware ``RepeaterStats``-Struct (56 Byte, native LE, kein Padding)."""

from __future__ import annotations

import struct

from meshcore_companion.node import parse_repeater_stats


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
