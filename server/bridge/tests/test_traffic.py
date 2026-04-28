from __future__ import annotations

from uuid import uuid4

from meshcore_bridge.bridge.traffic import (
    TrafficLog,
    make_event,
    parse_packet_meta,
)


def test_parse_packet_meta_handles_empty() -> None:
    assert parse_packet_meta(b"") == ("?", "?", [], None)


def test_parse_packet_meta_decodes_route_and_payload() -> None:
    # Header: route=01 (FLOOD), payload=0010 (TXT_MSG=0x02), version=00 -> 0x48
    raw = bytes([0b01_0010_00, 0x00])  # plen=0, no path
    route, payload, hashes, advert = parse_packet_meta(raw)
    assert route == "FLOOD"
    assert payload == "TXT_MSG"
    assert hashes == []
    assert advert is None


def test_parse_packet_meta_extracts_path_hashes() -> None:
    # FLOOD + ADVERT (0x04), 1-byte hashes (size encoded as 0 in upper 2 bits → size=1),
    # 3 hops -> plen byte = 0b00_000011 = 0x03
    header = (0b01 << 6) | (0x04 << 2)
    plen = 0x03
    path = bytes([0x11, 0x22, 0x33])
    pubkey = bytes(32)  # zeros for test
    raw = bytes([header, plen]) + path + pubkey
    route, payload, hashes, advert = parse_packet_meta(raw)
    assert route == "FLOOD"
    assert payload == "ADVERT"
    assert hashes == ["11", "22", "33"]
    assert advert is not None
    assert advert == "00" * 32


def test_traffic_log_records_and_recents() -> None:
    log = TrafficLog(capacity=3)
    site = uuid4()
    for i in range(5):
        log.record(
            make_event(
                site_id=site,
                site_name=f"R{i}",
                scope="public",
                raw=bytes([0x44, 0x00]),
                forwarded_to_pairs=[],
                dropped_reason=None,
            )
        )
    # capacity=3, only last 3 retained
    assert len(log) == 3
    last = log.recent(limit=10)
    assert len(last) == 3
    assert [e.site_name for e in last] == ["R2", "R3", "R4"]


def test_traffic_log_event_serialises_to_dict() -> None:
    site = uuid4()
    other = uuid4()
    e = make_event(
        site_id=site,
        site_name="S1",
        scope="public",
        raw=bytes([(0b10 << 6) | (0x04 << 2), 0x00]),  # DIRECT + ADVERT, no path, no body
        forwarded_to_pairs=[(other, "S2")],
        dropped_reason=None,
    )
    d = e.as_dict()
    assert d["site_name"] == "S1"
    assert d["scope"] == "public"
    assert d["route_type"] == "DIRECT"
    assert d["payload_type"] == "ADVERT"
    assert d["forwarded_to"] == [{"site_id": str(other), "name": "S2"}]
    assert d["dropped_reason"] is None
    # raw_hex muss in der Default-Serialisierung mit drin sein (Inspector liest das)
    assert d["raw_hex"] == "9000"
    assert e.as_dict(include_raw=False).get("raw_hex") is None


def test_traffic_log_hook_fires_on_record() -> None:
    log = TrafficLog(capacity=10)
    seen: list[str] = []
    log.set_hook(lambda ev: seen.append(ev.raw_hex))
    log.record(
        make_event(
            site_id=uuid4(),
            site_name="X",
            scope="public",
            raw=bytes([0x44, 0x00]),
            forwarded_to_pairs=[],
            dropped_reason=None,
        )
    )
    assert seen == ["4400"]
    # Hook-Ausnahmen dürfen record() nicht killen
    log.set_hook(lambda ev: (_ for _ in ()).throw(RuntimeError("boom")))
    log.record(
        make_event(
            site_id=uuid4(),
            site_name="Y",
            scope="public",
            raw=bytes([0x44, 0x00]),
            forwarded_to_pairs=[],
            dropped_reason=None,
        )
    )
    assert len(log) == 2
