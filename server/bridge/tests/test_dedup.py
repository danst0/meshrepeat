from __future__ import annotations

from uuid import uuid4

from meshcore_bridge.bridge.dedup import DedupCache, packet_key


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
