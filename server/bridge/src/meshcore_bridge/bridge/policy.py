"""Policy-Engine: Drop-Entscheidungen vor Paket-Forwarding.

Aktuelle Regeln (Phase 3):
- ``default``: ``allow`` oder ``deny`` für ungelistete Pakete.
- Pro Quell-Site: Token-Bucket-Rate-Limit (Pakete/s + Burst).

Spätere Erweiterungen:
- Per-Channel allow/deny (basierend auf erkennbarem MeshCore-Channel-Hash).
- Path-Hash-Filter, um bestimmte Routen zu blocken.
- Zeitfenster-basierte Filter.

Die Engine ist hot-reloadbar — ``update()`` wechselt die ``PolicyConfig``
atomar und resettet Rate-Limit-Buckets nicht (nur Parameter).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import RLock
from uuid import UUID

from meshcore_bridge.config import PolicyConfig
from meshcore_bridge.log import get_logger


@dataclass
class _Bucket:
    tokens: float = 0.0
    last_refill: float = 0.0


@dataclass
class PolicyDecision:
    allow: bool
    reason: str | None = None


@dataclass
class PolicyStats:
    allowed: int = 0
    denied_default: int = 0
    denied_rate_limit: int = 0


class PolicyEngine:
    def __init__(
        self,
        cfg: PolicyConfig,
        *,
        time_source: callable | None = None,  # type: ignore[type-arg]
    ) -> None:
        self._cfg = cfg
        self._buckets: dict[UUID, _Bucket] = {}
        self._lock = RLock()
        self._now = time_source or time.monotonic
        self._stats = PolicyStats()
        self._log = get_logger("policy")

    @property
    def config(self) -> PolicyConfig:
        return self._cfg

    @property
    def stats(self) -> PolicyStats:
        with self._lock:
            return PolicyStats(
                allowed=self._stats.allowed,
                denied_default=self._stats.denied_default,
                denied_rate_limit=self._stats.denied_rate_limit,
            )

    def update(self, cfg: PolicyConfig) -> None:
        """Hot-Reload: tauscht die Config atomar, behält Bucket-Zustände."""
        with self._lock:
            old = self._cfg
            self._cfg = cfg
            # Burst-Cap an neuen Burst anpassen, falls runter.
            for b in self._buckets.values():
                if b.tokens > cfg.rate_limit_burst:
                    b.tokens = float(cfg.rate_limit_burst)
        self._log.info(
            "policy_reloaded",
            default_old=old.default,
            default_new=cfg.default,
            rate_old=old.rate_limit_pkts_per_s,
            rate_new=cfg.rate_limit_pkts_per_s,
        )

    def evaluate(self, *, source_site: UUID) -> PolicyDecision:
        """Entscheidet, ob ein Paket akzeptiert wird."""
        with self._lock:
            cfg = self._cfg
            if cfg.default == "deny":
                self._stats.denied_default += 1
                return PolicyDecision(allow=False, reason="default-deny")

            now = self._now()
            bucket = self._buckets.get(source_site)
            if bucket is None:
                bucket = _Bucket(
                    tokens=float(cfg.rate_limit_burst),
                    last_refill=now,
                )
                self._buckets[source_site] = bucket
            else:
                elapsed = now - bucket.last_refill
                bucket.tokens = min(
                    cfg.rate_limit_burst,
                    bucket.tokens + elapsed * cfg.rate_limit_pkts_per_s,
                )
                bucket.last_refill = now

            if bucket.tokens < 1.0:
                self._stats.denied_rate_limit += 1
                return PolicyDecision(allow=False, reason="rate-limit")

            bucket.tokens -= 1.0
            self._stats.allowed += 1
            return PolicyDecision(allow=True)

    def reset_buckets(self) -> None:
        with self._lock:
            self._buckets.clear()


@dataclass
class PolicyState:
    """Snapshot for ctl-Tool / status endpoints."""
    default: str
    rate_limit_pkts_per_s: int
    rate_limit_burst: int
    sites_tracked: int
    stats: PolicyStats = field(default_factory=PolicyStats)

    @classmethod
    def of(cls, engine: PolicyEngine) -> PolicyState:
        with engine._lock:
            return cls(
                default=engine._cfg.default,
                rate_limit_pkts_per_s=engine._cfg.rate_limit_pkts_per_s,
                rate_limit_burst=engine._cfg.rate_limit_burst,
                sites_tracked=len(engine._buckets),
                stats=engine.stats,
            )
