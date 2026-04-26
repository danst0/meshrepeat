from __future__ import annotations

from uuid import uuid4

import pytest

from meshcore_bridge.bridge.dedup import DedupCache, packet_key
from meshcore_bridge.bridge.registry import ConnectionRegistry, RepeaterConn
from meshcore_bridge.bridge.router import Router
from meshcore_bridge.wire import Frame, Packet


class FakeSink:
    def __init__(self) -> None:
        self.sent: list[Frame] = []

    async def send_frame(self, frame: Frame) -> None:
        self.sent.append(frame)


def _conn(scope: str = "public") -> tuple[RepeaterConn, FakeSink]:
    sink = FakeSink()
    return RepeaterConn(site_id=uuid4(), scope=scope, sink=sink), sink


@pytest.mark.asyncio
async def test_packet_forwarded_to_other_repeaters_in_same_scope() -> None:
    reg = ConnectionRegistry()
    dedup = DedupCache(capacity=100, ttl_s=60)
    router = Router(reg, dedup)
    a, sink_a = _conn()
    b, sink_b = _conn()
    c, sink_c = _conn()
    reg.add(a)
    reg.add(b)
    reg.add(c)

    pkt = Packet(raw=b"\x01\x02\x03")
    result = await router.on_packet(source=a, packet=pkt)

    assert sorted(p.site_id for p in result.forwarded_to) == sorted([b.site_id, c.site_id])
    assert sink_a.sent == []
    assert sink_b.sent == [pkt]
    assert sink_c.sent == [pkt]


@pytest.mark.asyncio
async def test_packet_not_returned_to_origin_on_second_arrival() -> None:
    reg = ConnectionRegistry()
    dedup = DedupCache(capacity=100, ttl_s=60)
    router = Router(reg, dedup)
    a, sink_a = _conn()
    b, sink_b = _conn()
    reg.add(a)
    reg.add(b)

    pkt = Packet(raw=b"\xaa\xbb")
    await router.on_packet(source=a, packet=pkt)
    sink_b.sent.clear()

    # B receives it back from somewhere (e.g. another mesh path) — must not
    # bounce back to A.
    result = await router.on_packet(source=b, packet=pkt)
    assert result.forwarded_to == []
    assert sink_a.sent == []


@pytest.mark.asyncio
async def test_scope_isolation() -> None:
    reg = ConnectionRegistry()
    dedup = DedupCache(capacity=100, ttl_s=60)
    router = Router(reg, dedup)
    pub, sink_pub = _conn(scope="public")
    priv1, _sink_priv1 = _conn(scope="pool:abc")
    priv2, sink_priv2 = _conn(scope="pool:abc")
    other_priv, sink_other = _conn(scope="pool:xyz")
    reg.add(pub)
    reg.add(priv1)
    reg.add(priv2)
    reg.add(other_priv)

    pkt = Packet(raw=b"\x99")
    result = await router.on_packet(source=priv1, packet=pkt)

    assert [p.site_id for p in result.forwarded_to] == [priv2.site_id]
    assert sink_priv2.sent == [pkt]
    assert sink_pub.sent == []
    assert sink_other.sent == []


@pytest.mark.asyncio
async def test_origin_dedup_drops_packet_already_seen_by_origin() -> None:
    reg = ConnectionRegistry()
    dedup = DedupCache(capacity=100, ttl_s=60)
    router = Router(reg, dedup)
    a, _ = _conn()
    b, sink_b = _conn()
    reg.add(a)
    reg.add(b)

    pkt = Packet(raw=b"\xfe")
    # Manually mark this key as seen by `a` already.
    dedup.observe(packet_key(pkt.raw), a.site_id)

    result = await router.on_packet(source=a, packet=pkt)
    assert result.dropped_origin is True
    assert sink_b.sent == []


@pytest.mark.asyncio
async def test_send_failure_is_logged_but_does_not_abort_other_sends() -> None:
    reg = ConnectionRegistry()
    dedup = DedupCache(capacity=100, ttl_s=60)
    router = Router(reg, dedup)
    a, _ = _conn()
    bad, _ = _conn()
    good, sink_good = _conn()

    class _Bad:
        async def send_frame(self, frame: Frame) -> None:
            raise RuntimeError("connection broken")

    bad.sink = _Bad()
    reg.add(a)
    reg.add(bad)
    reg.add(good)

    pkt = Packet(raw=b"\x77")
    result = await router.on_packet(source=a, packet=pkt)
    assert good in result.forwarded_to
    assert bad not in result.forwarded_to
    assert sink_good.sent == [pkt]


@pytest.mark.asyncio
async def test_dedup_across_hops_same_payload_drops_second() -> None:
    """Drusilla forwarded den LoRa-Frame mit 1 Hop, Julia mit 2 Hops —
    raw differiert, payload-Body ist identisch. Der Server muss den
    zweiten Empfang als Duplikat erkennen und nicht erneut weiterleiten."""
    from meshcore_companion.packet import Packet as MCPacket
    from meshcore_companion.packet import PayloadType, RouteType

    reg = ConnectionRegistry()
    dedup = DedupCache(capacity=100, ttl_s=60)
    router = Router(reg, dedup)
    a, _ = _conn()  # Drusilla
    b, sink_b = _conn()  # Julia
    c, sink_c = _conn()  # dritter Knoten
    reg.add(a)
    reg.add(b)
    reg.add(c)

    body = b"\x21\xab\xcd\xef" + b"\x00" * 20
    raw_a = MCPacket(
        route_type=RouteType.FLOOD,
        payload_type=PayloadType.GRP_TXT,
        path=b"\xaa",
        payload=body,
    ).encode()
    raw_b = MCPacket(
        route_type=RouteType.FLOOD,
        payload_type=PayloadType.GRP_TXT,
        path=b"\xaa\xbb",
        payload=body,
    ).encode()
    assert raw_a != raw_b

    # Drusilla schickt zuerst → wird an b und c forwarded
    res1 = await router.on_packet(source=a, packet=Packet(raw=raw_a))
    assert sorted(p.site_id for p in res1.forwarded_to) == sorted([b.site_id, c.site_id])
    sink_b.sent.clear()
    sink_c.sent.clear()

    # Julia schickt dasselbe (mehr Hops) — muss als origin-known gedroppt werden
    res2 = await router.on_packet(source=b, packet=Packet(raw=raw_b))
    assert res2.dropped_origin is True
    assert res2.forwarded_to == []
    assert sink_c.sent == []  # KEIN Re-Forward an c


@pytest.mark.asyncio
async def test_dedup_malformed_packet_falls_back_to_raw() -> None:
    """Pakete, die nicht decodierbar sind, fallen auf packet_key(raw)
    zurück — zweite Empfang derselben raw-Bytes muss trotzdem dedupliziert
    werden."""
    reg = ConnectionRegistry()
    dedup = DedupCache(capacity=100, ttl_s=60)
    router = Router(reg, dedup)
    a, _ = _conn()
    b, sink_b = _conn()
    reg.add(a)
    reg.add(b)

    raw = b"\xff"  # zu kurz für decode
    res1 = await router.on_packet(source=a, packet=Packet(raw=raw))
    assert b in res1.forwarded_to
    sink_b.sent.clear()

    # zweite Übermittlung von a — origin-known
    res2 = await router.on_packet(source=a, packet=Packet(raw=raw))
    assert res2.dropped_origin is True
    assert sink_b.sent == []


def test_registry_replace_returns_old_connection() -> None:
    reg = ConnectionRegistry()
    a, _ = _conn()
    a2 = RepeaterConn(site_id=a.site_id, scope=a.scope, sink=FakeSink())
    assert reg.add(a) is None
    assert reg.add(a2) is a


def test_registry_remove_cleans_up_scope_set() -> None:
    reg = ConnectionRegistry()
    a, _ = _conn(scope="pool:x")
    reg.add(a)
    reg.remove(a.site_id)
    assert list(reg.in_scope("pool:x")) == []
    assert reg.get(a.site_id) is None
