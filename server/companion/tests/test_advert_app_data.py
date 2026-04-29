"""Tests für encode_advert_app_data / parse_advert_app_data — spiegelt
``firmware/lib/meshcore/src/helpers/AdvertDataHelpers.{cpp,h}``.
"""

from __future__ import annotations

import struct

from meshcore_companion.node import (
    ADV_LATLON_MASK,
    ADV_NAME_MASK,
    ADV_TYPE_CHAT,
    ADV_TYPE_REPEATER,
    encode_advert_app_data,
    parse_advert_app_data,
)


def test_encode_name_only_sets_name_flag() -> None:
    data = encode_advert_app_data(name="alice")
    # flags = type(1) | NAME_MASK (0x80) = 0x81
    assert data[0] == ADV_TYPE_CHAT | ADV_NAME_MASK
    assert data[1:] == b"alice"


def test_encode_with_latlon() -> None:
    data = encode_advert_app_data(name="repeater", adv_type=ADV_TYPE_REPEATER, lat=52.5, lon=13.4)
    flags = data[0]
    assert flags & ADV_LATLON_MASK
    assert flags & ADV_NAME_MASK
    assert (flags & 0x0F) == ADV_TYPE_REPEATER
    lat_i, lon_i = struct.unpack("<ii", data[1:9])
    assert lat_i == 52_500_000
    assert lon_i == 13_400_000
    assert data[9:] == b"repeater"


def test_roundtrip_name_only() -> None:
    encoded = encode_advert_app_data(name="alice")
    parsed = parse_advert_app_data(encoded)
    assert parsed.name == "alice"
    assert parsed.adv_type == ADV_TYPE_CHAT
    assert parsed.lat is None
    assert parsed.lon is None


def test_roundtrip_with_latlon() -> None:
    encoded = encode_advert_app_data(
        name="repeater-1", adv_type=ADV_TYPE_REPEATER, lat=51.4, lon=7.6
    )
    parsed = parse_advert_app_data(encoded)
    assert parsed.name == "repeater-1"
    assert parsed.adv_type == ADV_TYPE_REPEATER
    assert parsed.lat is not None
    assert parsed.lon is not None
    assert abs(parsed.lat - 51.4) < 1e-5
    assert abs(parsed.lon - 7.6) < 1e-5


def test_parse_real_world_repeater_advert() -> None:
    # flags = REPEATER | LATLON | NAME = 0x02 | 0x10 | 0x80 = 0x92
    flags = ADV_TYPE_REPEATER | ADV_LATLON_MASK | ADV_NAME_MASK
    payload = bytes([flags]) + struct.pack("<ii", 51_400_000, 7_600_000) + b"DE-NW-ME-VBT08"
    parsed = parse_advert_app_data(payload)
    assert parsed.name == "DE-NW-ME-VBT08"
    assert parsed.adv_type == ADV_TYPE_REPEATER


def test_parse_empty() -> None:
    parsed = parse_advert_app_data(b"")
    assert parsed.name == ""
    assert parsed.lat is None


def test_parse_truncated_latlon_returns_empty_name() -> None:
    # LATLON-Bit gesetzt, aber Body kürzer als 8 Byte
    parsed = parse_advert_app_data(bytes([ADV_LATLON_MASK]) + b"\x01\x02")
    assert parsed.name == ""


def test_parse_no_name_flag_ignores_trailing_bytes() -> None:
    # Type-only, kein NAME_MASK → Trailing-Bytes zählen nicht als Name
    parsed = parse_advert_app_data(bytes([ADV_TYPE_CHAT]) + b"junk")
    assert parsed.name == ""
    assert parsed.adv_type == ADV_TYPE_CHAT
