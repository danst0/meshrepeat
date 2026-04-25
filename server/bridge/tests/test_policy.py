from __future__ import annotations

from uuid import uuid4

import pytest

from meshcore_bridge.bridge.dedup import DedupCache
from meshcore_bridge.bridge.policy import PolicyEngine, PolicyState
from meshcore_bridge.bridge.registry import ConnectionRegistry, RepeaterConn
from meshcore_bridge.bridge.router import Router
from meshcore_bridge.config import PolicyConfig
from meshcore_bridge.wire import Frame, Packet


class _Clock:
    def __init__(self, t: float = 0.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class _Sink:
    def __init__(self) -> None:
        self.sent: list[Frame] = []

    async def send_frame(self, frame: Frame) -> None:
        self.sent.append(frame)


def test_default_allow_passes_packet() -> None:
    p = PolicyEngine(
        PolicyConfig(default="allow", rate_limit_pkts_per_s=1000, rate_limit_burst=1000)
    )
    assert p.evaluate(source_site=uuid4()).allow is True


def test_default_deny_blocks_packet() -> None:
    p = PolicyEngine(PolicyConfig(default="deny"))
    decision = p.evaluate(source_site=uuid4())
    assert decision.allow is False
    assert decision.reason == "default-deny"


def test_rate_limit_burst_then_throttle() -> None:
    clock = _Clock(0.0)
    p = PolicyEngine(
        PolicyConfig(default="allow", rate_limit_pkts_per_s=1, rate_limit_burst=3),
        time_source=clock,
    )
    site = uuid4()
    # initial bucket = burst=3 → drei Pakete erlaubt
    assert p.evaluate(source_site=site).allow
    assert p.evaluate(source_site=site).allow
    assert p.evaluate(source_site=site).allow
    # vierter wird gedroppt (Bucket leer, refill=0)
    fourth = p.evaluate(source_site=site)
    assert fourth.allow is False
    assert fourth.reason == "rate-limit"
    # nach 1s wieder 1 Token
    clock.t = 1.0
    assert p.evaluate(source_site=site).allow
    assert p.evaluate(source_site=site).allow is False


def test_rate_limit_independent_per_site() -> None:
    p = PolicyEngine(PolicyConfig(default="allow", rate_limit_pkts_per_s=0, rate_limit_burst=1))
    a, b = uuid4(), uuid4()
    assert p.evaluate(source_site=a).allow
    assert p.evaluate(source_site=b).allow
    # both buckets empty now
    assert not p.evaluate(source_site=a).allow
    assert not p.evaluate(source_site=b).allow


def test_update_swaps_config_atomic() -> None:
    p = PolicyEngine(PolicyConfig(default="deny"))
    assert not p.evaluate(source_site=uuid4()).allow
    p.update(PolicyConfig(default="allow", rate_limit_pkts_per_s=10, rate_limit_burst=10))
    assert p.evaluate(source_site=uuid4()).allow


def test_state_snapshot_reports_stats() -> None:
    p = PolicyEngine(PolicyConfig(default="allow", rate_limit_pkts_per_s=0, rate_limit_burst=1))
    site = uuid4()
    p.evaluate(source_site=site)  # allowed
    p.evaluate(source_site=site)  # denied (rate-limit)
    state = PolicyState.of(p)
    assert state.stats.allowed == 1
    assert state.stats.denied_rate_limit == 1
    assert state.sites_tracked == 1


@pytest.mark.asyncio
async def test_router_drops_when_policy_denies() -> None:
    reg = ConnectionRegistry()
    dedup = DedupCache(capacity=100, ttl_s=60)
    policy = PolicyEngine(PolicyConfig(default="deny"))
    router = Router(reg, dedup, policy)
    a = RepeaterConn(site_id=uuid4(), scope="public", sink=_Sink())
    b = RepeaterConn(site_id=uuid4(), scope="public", sink=_Sink())
    reg.add(a)
    reg.add(b)
    result = await router.on_packet(source=a, packet=Packet(raw=b"\x01\x02"))
    assert result.dropped_policy == "default-deny"
    assert result.forwarded_to == []


@pytest.mark.asyncio
async def test_router_forwards_when_policy_allows() -> None:
    reg = ConnectionRegistry()
    dedup = DedupCache(capacity=100, ttl_s=60)
    policy = PolicyEngine(
        PolicyConfig(default="allow", rate_limit_pkts_per_s=1000, rate_limit_burst=1000)
    )
    router = Router(reg, dedup, policy)
    a = RepeaterConn(site_id=uuid4(), scope="public", sink=_Sink())
    b_sink = _Sink()
    b = RepeaterConn(site_id=uuid4(), scope="public", sink=b_sink)
    reg.add(a)
    reg.add(b)
    result = await router.on_packet(source=a, packet=Packet(raw=b"\x01"))
    assert result.dropped_policy is None
    assert b in result.forwarded_to
