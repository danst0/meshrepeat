"""Plausibilitäts-Filter für Geo-Koordinaten der Companion-Karte.

Reines Helper-Modul ohne Async-/DB-Abhängigkeiten, damit es sowohl beim
Ingestion-Pfad (``service.py``) als auch beim Display-Pfad
(``companion_routes.py``) verwendet werden kann.
"""

from __future__ import annotations

import math
from collections.abc import Sequence

EARTH_RADIUS_KM = 6371.0
LAT_MAX = 90.0
LON_MAX = 180.0


def is_valid_coord(
    lat: float | None,
    lon: float | None,
    *,
    null_island_deg: float = 1.0,
) -> bool:
    """Hard-Filter: Wertebereich, finite, Null-Insel-Toleranz.

    Liefert ``False`` für ``None``, ``NaN``/``Inf``, Werte außerhalb
    [-90, 90] / [-180, 180] sowie für die Null-Insel (|lat| und |lon|
    jeweils ≤ ``null_island_deg``).
    """
    if lat is None or lon is None:
        return False
    if not (math.isfinite(lat) and math.isfinite(lon)):
        return False
    if not (-LAT_MAX <= lat <= LAT_MAX):
        return False
    if not (-LON_MAX <= lon <= LON_MAX):
        return False
    return not (abs(lat) <= null_island_deg and abs(lon) <= null_island_deg)


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Großkreisdistanz auf der Kugel in Kilometern (R = 6371 km)."""
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(
        dlambda / 2.0
    ) ** 2
    return 2.0 * EARTH_RADIUS_KM * math.asin(math.sqrt(a))


def _median(values: Sequence[float]) -> float:
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2 == 1:
        return s[mid]
    return 0.5 * (s[mid - 1] + s[mid])


def cluster_outlier_mask(
    points: Sequence[tuple[float, float]],
    *,
    min_points: int = 10,
    mad_factor: float = 3.5,
    min_threshold_km: float = 500.0,
    max_threshold_km: float = 5000.0,
) -> list[bool]:
    """Markiert Punkte als Ausreißer relativ zum Median-Zentrum.

    Vorgehen: Median(lat) und Median(lon) bilden ein robustes Cluster-
    Zentrum. Pro Punkt wird die Haversine-Distanz dazu berechnet. Die
    MAD (median absolute deviation) der Distanzen liefert eine robuste
    Streuung; die Schwelle ist ``mad_factor · MAD``, hart gefenstert
    auf ``[min_threshold_km, max_threshold_km]``. Punkte mit Distanz >
    Schwelle gelten als Ausreißer.

    Bei ``len(points) < min_points`` ist die Statistik zu dünn — dann
    gibt es keine Ausreißerentscheidung (alles ``False``).
    """
    n = len(points)
    if n < min_points:
        return [False] * n

    lat_med = _median([p[0] for p in points])
    lon_med = _median([p[1] for p in points])
    distances = [haversine_km(lat_med, lon_med, lat, lon) for lat, lon in points]

    mad = _median([abs(d - _median(distances)) for d in distances])
    threshold = mad_factor * mad
    threshold = max(threshold, min_threshold_km)
    threshold = min(threshold, max_threshold_km)

    return [d > threshold for d in distances]
