"""Aggregierte Wichtigkeits-Bewertung pro Repeater-Pubkey.

Quelle: ``RawPacket`` (7-Tage-Spool, ``path_hashes`` als CSV von
1-3-Byte-Pubkey-Präfixen) + ``CompanionContact`` mit ``node_type=2``
(Repeater) für Pubkey/Name/Geo/last_seen.

Vier Sub-Scores, jeweils 0..1, kombiniert per gewichtetem Mittel:

* **Forwarding** — wie oft taucht der Repeater in ``path_hashes`` aller
  Pakete auf (gewichtet 1/N bei Mehrdeutigkeit, weil 1-Byte-Hashes
  ~1/256-Kollisionen haben).
* **Bottleneck** — für wieviele beobachtete *Origins* (advert_pubkey)
  liegt der Repeater in **jedem** distinkten Pfad? Origins mit nur
  einem beobachteten Pfad zählen nicht.
* **Reach** — wieviele unterschiedliche Origins (advert_pubkey aus
  ADVERT-Paketen) sind über diesen Repeater bereits geflossen.
* **Liveness** — Exponential-Decay über ``last_seen_at`` aus
  CompanionContact (24-h Halbwertszeit-Größenordnung).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from meshcore_bridge.db import CompanionContact, RawPacket

# Sub-Score-Gewichte. Forwarding dominiert (häufigster Hop = wichtigster
# Vermittler), die anderen drei tragen je ~20%.
DEFAULT_WEIGHTS: dict[str, float] = {
    "forwarding": 0.4,
    "bottleneck": 0.2,
    "reach": 0.2,
    "liveness": 0.2,
}

# Halbwertszeit der Liveness-Decay-Funktion (in Stunden). exp(-Δh/τ).
_LIVENESS_TAU_H: float = 24.0

# Ein Origin braucht mindestens so viele *distinkte* Pfade, bevor er für
# Bottleneck-Wertung in Frage kommt — sonst würde jede Einzelbeobachtung
# alle Repeater im Pfad als "obligatorisch" markieren.
_BOTTLENECK_MIN_PATHS: int = 2

# CompanionContact.node_type == _ADV_TYPE_REPEATER, MeshCore-ADV_TYPE-Konstante.
_ADV_TYPE_REPEATER: int = 2

WINDOW_PRESETS: dict[str, timedelta] = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}


@dataclass(frozen=True, slots=True)
class RepeaterMetric:
    pubkey_hex: str
    name: str
    last_lat: float | None
    last_lon: float | None
    last_seen_at: datetime | None
    forward_count: float
    forward_share: float
    unique_paths: int
    reach_endpoints: int
    bottleneck_origins: int
    advert_count: int
    forwarding_score: float
    bottleneck_score: float
    reach_score: float
    liveness_score: float
    total_score: float


@dataclass(frozen=True, slots=True)
class RepeaterMetricsResult:
    window: str
    cutoff: datetime
    total_packets: int
    repeater_count: int
    metrics: list[RepeaterMetric]
    forward_truncated_to_7d: bool
    """True, wenn das Fenster größer ist als die RawPacket-Retention (7d).
    Forward/Reach/Bottleneck sind dann auf 7d gekappt; nur Liveness und
    Advert-Counts beziehen sich auf das volle Fenster."""


def liveness_decay(last_seen_at: datetime | None, now: datetime) -> float:
    """exp(-Δh/τ), Δh in Stunden, τ=24h. None → 0.0, Zukunft → 1.0."""
    if last_seen_at is None:
        return 0.0
    seen = last_seen_at if last_seen_at.tzinfo is not None else last_seen_at.replace(tzinfo=UTC)
    delta_s = (now - seen).total_seconds()
    if delta_s <= 0:
        return 1.0
    return math.exp(-(delta_s / 3600.0) / _LIVENESS_TAU_H)


def _normalize(value: float, max_value: float) -> float:
    if max_value <= 0:
        return 0.0
    return min(1.0, max(0.0, value / max_value))


@dataclass
class _RepeaterCandidate:
    pubkey_hex: str
    pubkey_bytes: bytes
    name: str
    last_lat: float | None
    last_lon: float | None
    last_seen_at: datetime | None


@dataclass
class _Acc:
    forward_count: float = 0.0
    unique_paths: set[tuple[str, ...]] = field(default_factory=set)
    reach: set[str] = field(default_factory=set)
    advert_count: int = 0
    bottleneck_origins: set[str] = field(default_factory=set)


async def _load_repeater_inventory(db: AsyncSession) -> list[_RepeaterCandidate]:
    """Lädt alle bekannten Repeater (CompanionContact mit node_type=2),
    deduplizert pro pubkey: pro Pubkey nur eine Karte mit dem jüngsten
    last_seen_at und einem nicht-leeren Namen, falls verfügbar."""
    rows = (
        (
            await db.execute(
                select(CompanionContact).where(CompanionContact.node_type == _ADV_TYPE_REPEATER)
            )
        )
        .scalars()
        .all()
    )

    by_pubkey: dict[bytes, _RepeaterCandidate] = {}
    for c in rows:
        cand = by_pubkey.get(c.peer_pubkey)
        seen = c.last_seen_at
        if seen is not None and seen.tzinfo is None:
            seen = seen.replace(tzinfo=UTC)
        if cand is None:
            by_pubkey[c.peer_pubkey] = _RepeaterCandidate(
                pubkey_hex=c.peer_pubkey.hex(),
                pubkey_bytes=bytes(c.peer_pubkey),
                name=c.peer_name or "?",
                last_lat=c.last_lat,
                last_lon=c.last_lon,
                last_seen_at=seen,
            )
            continue
        # Merge: behalte aktuellsten last_seen_at, fülle Geo/Name auf.
        if seen is not None and (cand.last_seen_at is None or seen > cand.last_seen_at):
            cand.last_seen_at = seen
        if cand.name == "?" and c.peer_name:
            cand.name = c.peer_name
        if cand.last_lat is None and c.last_lat is not None:
            cand.last_lat = c.last_lat
        if cand.last_lon is None and c.last_lon is not None:
            cand.last_lon = c.last_lon
    return list(by_pubkey.values())


def _build_prefix_index(
    repeaters: list[_RepeaterCandidate],
) -> dict[bytes, list[str]]:
    """prefix_bytes (1..3) → [pubkey_hex, …]."""
    idx: dict[bytes, list[str]] = {}
    for r in repeaters:
        for n in (1, 2, 3):
            idx.setdefault(r.pubkey_bytes[:n], []).append(r.pubkey_hex)
    return idx


def _resolve_path(path_hashes_csv: str, prefix_idx: dict[bytes, list[str]]) -> list[list[str]]:
    """Für jeden Hash im CSV → Liste der Repeater-Kandidaten (pubkey_hex).
    Hashes, die zu keinem bekannten Repeater passen, ergeben eine leere
    Kandidatenliste und werden später ignoriert."""
    if not path_hashes_csv:
        return []
    out: list[list[str]] = []
    for hop_hex in path_hashes_csv.split(","):
        if not hop_hex:
            continue
        try:
            prefix = bytes.fromhex(hop_hex)
        except ValueError:
            out.append([])
            continue
        out.append(prefix_idx.get(prefix, []))
    return out


def _process_packet(
    accs: dict[str, _Acc],
    origin_paths: dict[str, set[frozenset[str]]],
    *,
    hops: list[list[str]],
    advert_pubkey_hex: str | None,
    payload_type: str,
) -> None:
    """Aktualisiert Akkumulatoren für ein einzelnes Paket.

    Forwarding/unique_paths immer; Reach/Bottleneck nur für ADVERT-Pakete
    mit bekanntem Origin und nicht-leerem aufgelöstem Pfad. Self-Adverts
    (Origin == Repeater im Pfad) zählen nicht zu Reach."""
    if payload_type == "ADVERT" and advert_pubkey_hex:
        acc = accs.get(advert_pubkey_hex)
        if acc is not None:
            acc.advert_count += 1

    path_repeaters: set[str] = set()
    path_tuple_keys: list[str] = []
    for cands in hops:
        if not cands:
            path_tuple_keys.append("")
            continue
        weight = 1.0 / len(cands)
        path_tuple_keys.append("|".join(sorted(cands)))
        for pub in cands:
            accs[pub].forward_count += weight
            path_repeaters.add(pub)
    path_tuple = tuple(path_tuple_keys)
    for pub in path_repeaters:
        accs[pub].unique_paths.add(path_tuple)

    if (
        payload_type == "ADVERT"
        and advert_pubkey_hex
        and path_repeaters
        and advert_pubkey_hex not in path_repeaters
    ):
        for pub in path_repeaters:
            accs[pub].reach.add(advert_pubkey_hex)
        origin_paths.setdefault(advert_pubkey_hex, set()).add(frozenset(path_repeaters))


async def compute_repeater_metrics(
    db: AsyncSession,
    window: timedelta,
    *,
    weights: dict[str, float] | None = None,
    now: datetime | None = None,
    window_label: str = "",
) -> RepeaterMetricsResult:
    """Aggregiert alle ``RawPacket`` im Fenster und berechnet pro
    Repeater-Pubkey die vier Sub-Scores und einen Gesamt-Score.

    Args:
        db: aktive Session.
        window: Zeitfenster ab ``now`` rückwärts.
        weights: Override für Sub-Score-Gewichtung (sonst DEFAULT_WEIGHTS).
        now: Override für Test-Reproduzierbarkeit.
        window_label: optionales Label fürs UI ("24h", "7d", "30d").
    """
    w = weights or DEFAULT_WEIGHTS
    cur = now or datetime.now(UTC)
    cutoff = cur - window

    repeaters = await _load_repeater_inventory(db)
    if not repeaters:
        return RepeaterMetricsResult(
            window=window_label,
            cutoff=cutoff,
            total_packets=0,
            repeater_count=0,
            metrics=[],
            forward_truncated_to_7d=window > timedelta(days=7),
        )

    prefix_idx = _build_prefix_index(repeaters)
    pubkey_to_cand = {r.pubkey_hex: r for r in repeaters}
    accs: dict[str, _Acc] = {r.pubkey_hex: _Acc() for r in repeaters}

    # Pakete laden — wir brauchen nur die paar Spalten, kein full ORM-Row.
    rows = (
        await db.execute(
            select(
                RawPacket.path_hashes,
                RawPacket.advert_pubkey,
                RawPacket.payload_type,
            ).where(RawPacket.ts >= cutoff)
        )
    ).all()
    total_packets = len(rows)

    # Pro Origin (advert_pubkey aus ADVERT-Paketen) sammeln wir die
    # distinkten Pfad-Repeater-Sets — daraus folgt Reach + Bottleneck.
    origin_paths: dict[str, set[frozenset[str]]] = {}

    for path_csv, advert_pubkey_hex, payload_type in rows:
        hops = _resolve_path(path_csv, prefix_idx)
        _process_packet(
            accs,
            origin_paths,
            hops=hops,
            advert_pubkey_hex=advert_pubkey_hex,
            payload_type=payload_type,
        )

    # Bottleneck-Auswertung: pro Origin Schnittmenge der Pfad-Repeater-Sets.
    for origin, sets in origin_paths.items():
        if len(sets) < _BOTTLENECK_MIN_PATHS:
            continue
        intersection: set[str] = set(next(iter(sets)))
        for s in sets:
            intersection &= s
        for pub in intersection:
            accs[pub].bottleneck_origins.add(origin)

    # Sub-Score-Maxima für Rank-Normalisierung.
    max_forward = max((a.forward_count for a in accs.values()), default=0.0)
    max_reach = max((len(a.reach) for a in accs.values()), default=0)
    max_bottle = max((len(a.bottleneck_origins) for a in accs.values()), default=0)

    metrics: list[RepeaterMetric] = []
    for pub_hex, acc in accs.items():
        cand = pubkey_to_cand[pub_hex]
        forwarding = _normalize(acc.forward_count, max_forward)
        reach = _normalize(float(len(acc.reach)), float(max_reach))
        bottle = _normalize(float(len(acc.bottleneck_origins)), float(max_bottle))
        liveness = liveness_decay(cand.last_seen_at, cur)
        total = (
            w["forwarding"] * forwarding
            + w["bottleneck"] * bottle
            + w["reach"] * reach
            + w["liveness"] * liveness
        )
        share = acc.forward_count / float(total_packets) if total_packets > 0 else 0.0
        metrics.append(
            RepeaterMetric(
                pubkey_hex=pub_hex,
                name=cand.name,
                last_lat=cand.last_lat,
                last_lon=cand.last_lon,
                last_seen_at=cand.last_seen_at,
                forward_count=acc.forward_count,
                forward_share=share,
                unique_paths=len(acc.unique_paths),
                reach_endpoints=len(acc.reach),
                bottleneck_origins=len(acc.bottleneck_origins),
                advert_count=acc.advert_count,
                forwarding_score=forwarding,
                bottleneck_score=bottle,
                reach_score=reach,
                liveness_score=liveness,
                total_score=total,
            )
        )

    metrics.sort(key=lambda m: m.total_score, reverse=True)

    return RepeaterMetricsResult(
        window=window_label,
        cutoff=cutoff,
        total_packets=total_packets,
        repeater_count=len(metrics),
        metrics=metrics,
        forward_truncated_to_7d=window > timedelta(days=7),
    )
