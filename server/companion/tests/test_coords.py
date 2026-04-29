"""Tests für coords.is_valid_coord / haversine_km / cluster_outlier_mask."""

from __future__ import annotations

import math

import pytest

from meshcore_companion.coords import (
    cluster_outlier_mask,
    haversine_km,
    is_valid_coord,
)

# ---------- is_valid_coord ----------


@pytest.mark.parametrize(
    ("lat", "lon"),
    [
        (52.5, 13.4),  # Berlin
        (-33.86, 151.21),  # Sydney
        (90.0, 180.0),  # Eckwert
        (-90.0, -180.0),  # Eckwert
        (1.5, 0.5),  # knapp außerhalb Null-Insel-Toleranz
    ],
)
def test_valid_coords_pass(lat: float, lon: float) -> None:
    assert is_valid_coord(lat, lon) is True


@pytest.mark.parametrize(
    ("lat", "lon"),
    [
        (None, 13.4),
        (52.5, None),
        (None, None),
        (float("nan"), 13.4),
        (52.5, float("inf")),
        (91.0, 0.0),  # über 90°
        (-90.1, 0.0),
        (0.0, 181.0),
        (0.0, -181.0),
        (0.0, 0.0),  # exakte Null-Insel
        (0.5, -0.5),  # Null-Insel-Toleranzkreis
        (1.0, 1.0),  # Rand der Toleranz (≤)
    ],
)
def test_invalid_coords_rejected(lat: float | None, lon: float | None) -> None:
    assert is_valid_coord(lat, lon) is False


def test_null_island_tolerance_configurable() -> None:
    # Mit kleinerer Toleranz wird (0.5, 0.5) wieder gültig.
    assert is_valid_coord(0.5, 0.5, null_island_deg=0.1) is True
    assert is_valid_coord(0.05, 0.05, null_island_deg=0.1) is False


# ---------- haversine_km ----------


def test_haversine_zero_distance() -> None:
    assert haversine_km(52.5, 13.4, 52.5, 13.4) == pytest.approx(0.0)


def test_haversine_berlin_paris_about_880km() -> None:
    # Berlin (52.5200, 13.4050) ↔ Paris (48.8566, 2.3522) ≈ 878 km
    d = haversine_km(52.5200, 13.4050, 48.8566, 2.3522)
    assert 870.0 < d < 890.0


def test_haversine_antipodes_about_half_earth() -> None:
    d = haversine_km(0.0, 0.0, 0.0, 180.0)
    # halber Erdumfang ≈ π·R ≈ 20015 km
    assert d == pytest.approx(math.pi * 6371.0, rel=1e-6)


# ---------- cluster_outlier_mask ----------


def test_cluster_too_few_points_no_outliers() -> None:
    pts = [(52.5, 13.4), (48.8, 2.3), (51.5, -0.1)]  # nur 3 Punkte
    assert cluster_outlier_mask(pts) == [False, False, False]


def test_cluster_outlier_far_from_median() -> None:
    # 11 Punkte um Berlin + 1 weit weg in Australien — der Australien-
    # Punkt liegt mehr als 5000 km vom Median entfernt und muss True
    # werden, alle anderen False.
    cluster = [
        (52.5 + i * 0.01, 13.4 + i * 0.01) for i in range(-5, 6)
    ]  # 11 Punkte
    pts = [*cluster, (-33.86, 151.21)]
    mask = cluster_outlier_mask(pts)
    assert mask[:-1] == [False] * len(cluster)
    assert mask[-1] is True


def test_cluster_tight_group_no_false_positives() -> None:
    # 12 Punkte innerhalb ~1 km — keiner darf als Ausreißer gelten,
    # weil min_threshold_km = 500 km die MAD nach unten begrenzt.
    pts = [(52.5 + i * 0.001, 13.4 + i * 0.001) for i in range(12)]
    assert cluster_outlier_mask(pts) == [False] * len(pts)


def test_cluster_max_threshold_caps() -> None:
    # Stark gestreute Punkte: MAD wäre groß, aber max_threshold_km=500
    # zwingt einen klaren Ausreißer als True.
    pts = [
        (52.5, 13.4),
        (48.8, 2.3),
        (51.5, -0.1),
        (50.1, 8.7),
        (53.5, 9.9),
        (47.4, 8.5),
        (45.4, 12.3),
        (40.4, -3.7),
        (41.9, 12.5),
        (55.7, 12.6),
        (-33.86, 151.21),  # offensichtlicher Ausreißer
    ]
    mask = cluster_outlier_mask(pts, max_threshold_km=500.0)
    assert mask[-1] is True
