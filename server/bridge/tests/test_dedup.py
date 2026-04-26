from __future__ import annotations

from uuid import uuid4

from meshcore_bridge.bridge.dedup import DedupCache, packet_key, payload_dedup_key
from meshcore_companion.packet import Packet as MCPacket
from meshcore_companion.packet import PayloadType, RouteType


class _Clock:
    def __init__(self, t: float = 0.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def test_packet_key_is_deterministic_and_32_bytes() -> None:
    raw = b"\x01\xfe\x00\x42"
    k1 = packet_key(raw)
    k2 = packet_key(raw)
    assert len(k1) == 32
    assert k1 == k2


def test_packet_key_differs_for_different_payload() -> None:
    assert packet_key(b"\x01") != packet_key(b"\x02")


def test_observe_first_returns_true() -> None:
    cache = DedupCache(capacity=100, ttl_s=10)
    site = uuid4()
    assert cache.observe(b"k1", site) is True


def test_observe_same_site_twice_returns_false_second_time() -> None:
    cache = DedupCache(capacity=100, ttl_s=10)
    site = uuid4()
    assert cache.observe(b"k", site) is True
    assert cache.observe(b"k", site) is False


def test_observe_different_sites_each_returns_true() -> None:
    cache = DedupCache(capacity=100, ttl_s=10)
    a, b = uuid4(), uuid4()
    assert cache.observe(b"k", a) is True
    assert cache.observe(b"k", b) is True
    assert cache.has_seen(b"k", a)
    assert cache.has_seen(b"k", b)


def test_ttl_evicts_expired_entries() -> None:
    clock = _Clock(0.0)
    cache = DedupCache(capacity=100, ttl_s=5, time_source=clock)
    site = uuid4()
    cache.observe(b"k", site)
    assert len(cache) == 1

    clock.t = 6.0
    cache.observe(b"new", uuid4())  # triggers _evict_expired
    assert len(cache) == 1
    assert not cache.has_seen(b"k", site)


def test_capacity_evicts_oldest() -> None:
    cache = DedupCache(capacity=3, ttl_s=1000)
    site = uuid4()
    cache.observe(b"a", site)
    cache.observe(b"b", site)
    cache.observe(b"c", site)
    cache.observe(b"d", site)
    assert len(cache) == 3
    assert not cache.has_seen(b"a", site)
    assert cache.has_seen(b"d", site)


def test_observing_existing_key_moves_it_to_end() -> None:
    cache = DedupCache(capacity=3, ttl_s=1000)
    site = uuid4()
    cache.observe(b"a", site)
    cache.observe(b"b", site)
    cache.observe(b"c", site)
    cache.observe(b"a", site)  # touch a
    cache.observe(b"d", site)  # should evict 'b' now, not 'a'
    assert cache.has_seen(b"a", site)
    assert not cache.has_seen(b"b", site)


def test_seen_sites_returns_set_copy() -> None:
    cache = DedupCache(capacity=10, ttl_s=10)
    a, b = uuid4(), uuid4()
    cache.observe(b"k", a)
    cache.observe(b"k", b)
    sites = cache.seen_sites(b"k")
    assert sites == {a, b}
    sites.clear()  # mutating return must not affect cache
    assert cache.seen_sites(b"k") == {a, b}


# ---------- payload_dedup_key (hop-invariant) ----------


def _build_raw(*, route_type: RouteType, payload_type: PayloadType,
               path: bytes, payload: bytes,
               transport_codes: tuple[int, int] = (0, 0)) -> bytes:
    return MCPacket(
        route_type=route_type,
        payload_type=payload_type,
        path=path,
        payload=payload,
        transport_codes=transport_codes,
    ).encode()


def test_payload_dedup_key_ignores_path_changes() -> None:
    body = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    raw1 = _build_raw(
        route_type=RouteType.FLOOD,
        payload_type=PayloadType.GRP_TXT,
        path=b"\xaa",
        payload=body,
    )
    raw2 = _build_raw(
        route_type=RouteType.FLOOD,
        payload_type=PayloadType.GRP_TXT,
        path=b"\xaa\xbb\xcc",
        payload=body,
    )
    assert raw1 != raw2
    assert payload_dedup_key(raw1) == payload_dedup_key(raw2)


def test_payload_dedup_key_distinguishes_payload_types() -> None:
    body = b"hello"
    a = _build_raw(
        route_type=RouteType.FLOOD,
        payload_type=PayloadType.GRP_TXT,
        path=b"",
        payload=body,
    )
    b = _build_raw(
        route_type=RouteType.FLOOD,
        payload_type=PayloadType.TXT_MSG,
        path=b"",
        payload=body,
    )
    assert payload_dedup_key(a) != payload_dedup_key(b)


def test_payload_dedup_key_includes_transport_codes() -> None:
    body = b"x"
    a = _build_raw(
        route_type=RouteType.TRANSPORT_FLOOD,
        payload_type=PayloadType.TXT_MSG,
        path=b"",
        payload=body,
        transport_codes=(1, 2),
    )
    b = _build_raw(
        route_type=RouteType.TRANSPORT_FLOOD,
        payload_type=PayloadType.TXT_MSG,
        path=b"",
        payload=body,
        transport_codes=(9, 9),
    )
    assert payload_dedup_key(a) != payload_dedup_key(b)


def test_payload_dedup_key_falls_back_on_decode_error() -> None:
    # zu kurz für decode
    raw = b"\xff"
    # MUSS keinen Crash werfen und MUSS deterministisch sein
    k1 = payload_dedup_key(raw)
    k2 = payload_dedup_key(raw)
    assert k1 == k2 == packet_key(raw)
