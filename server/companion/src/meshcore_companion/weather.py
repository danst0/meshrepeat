"""Format-Builder für Wetter-Posts aus Home-Assistant-States.

Pure-Function-Modul ohne I/O — :func:`format_weather_line` nimmt einen
:class:`HAState`, eine optionale Ortsbezeichnung, und liefert die fertige
Mesh-Channel-Zeile zurück (kompakt, mit Emoji).

Designziele:
- LoRa-Bytecount klein halten (Zielzeile ≤ ~120 Bytes nach UTF-8-Encoding).
- Deterministisch: gleiches HAState → gleiche Zeile.
- Robust gegen fehlende Attribute: Felder, die HA nicht liefert, werden
  einfach weggelassen statt eine Exception zu werfen.
- Erst-Konsument ist der ``_weather_loop`` im CompanionService; Tests
  prüfen das Modul isoliert ohne DB/HTTP.
"""

from __future__ import annotations

from .homeassistant import HAState

# Mapping von HA-``weather.*``-State auf (Emoji, deutscher Klartext).
# HA liefert die Conditions als snake_case; siehe
# https://developers.home-assistant.io/docs/core/entity/weather/#recommended-values-for-state-and-condition
_CONDITION_MAP: dict[str, tuple[str, str]] = {
    "clear-night": ("🌙", "klar"),
    "cloudy": ("☁", "bewölkt"),
    "exceptional": ("⚠", "extrem"),
    "fog": ("🌫", "Nebel"),
    "hail": ("🌨", "Hagel"),
    "lightning": ("⚡", "Gewitter"),
    "lightning-rainy": ("⛈", "Gewitter mit Regen"),
    "partlycloudy": ("🌤", "teils bewölkt"),
    "pouring": ("🌧", "Starkregen"),
    "rainy": ("🌧", "Regen"),
    "snowy": ("❄", "Schnee"),
    "snowy-rainy": ("🌨", "Schneeregen"),
    "sunny": ("☀", "sonnig"),
    "windy": ("💨", "windig"),
    "windy-variant": ("💨", "windig"),
}


def _fmt_num(value: object, decimals: int = 0) -> str | None:
    """``18.4`` → ``"18"`` (decimals=0) bzw. ``"18.4"`` (decimals=1).
    Liefert ``None`` wenn sich kein Float draus machen lässt — Caller
    überspringt die Komponente dann."""
    try:
        f = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if decimals <= 0:
        return f"{round(f)}"
    return f"{f:.{decimals}f}"


def format_weather_line(state: HAState, location: str | None = None) -> str:
    """Baue eine kompakte Wetter-Zeile für einen Mesh-Channel.

    Beispiele (Location = ``"Bonn"``)::

        weather.home  state="sunny"  attrs={temperature: 18.4, wind_speed: 12, humidity: 62}
            → "☀ Bonn: 18°C, sonnig, Wind 12 km/h, 62% RH"

        weather.home  state="rainy"  attrs={temperature: 9, humidity: 88}
            → "🌧 Bonn: 9°C, Regen, 88% RH"

        sensor.outdoor_temp  state="18.4"  (kein bekannter Condition-State)
            → "Bonn: 18.4°C"   (Fallback)

    Format ohne ``location`` ist analog, nur ohne den ``"<Ort>: "``-Prefix.
    """
    emoji, condition_label = _CONDITION_MAP.get(state.state.lower(), ("", ""))

    parts: list[str] = []

    # 1) Temperatur — bei weather.*-Entities in ``attributes['temperature']``,
    # bei sensor.*-Entities oft direkt im ``state``.
    temp_raw = state.attributes.get("temperature")
    if temp_raw is None and _fmt_num(state.state, decimals=1) is not None:
        temp_raw = state.state
    temp_str = _fmt_num(temp_raw, decimals=0)
    if temp_str is not None:
        parts.append(f"{temp_str}°C")

    # 2) Klartext-Condition (falls bekannt). Wenn der State numerisch war,
    # gibt's keine Condition — dann fällt diese Komponente weg.
    if condition_label:
        parts.append(condition_label)

    # 3) Wind. ``wind_speed`` ist in HA standardisiert km/h.
    wind_raw = state.attributes.get("wind_speed")
    wind_str = _fmt_num(wind_raw, decimals=0)
    if wind_str is not None:
        parts.append(f"Wind {wind_str} km/h")

    # 4) Luftfeuchte (% relative humidity).
    humid_raw = state.attributes.get("humidity")
    humid_str = _fmt_num(humid_raw, decimals=0)
    if humid_str is not None:
        parts.append(f"{humid_str}% RH")

    body = ", ".join(parts) if parts else state.state

    prefix_parts: list[str] = []
    if emoji:
        prefix_parts.append(emoji)
    if location:
        prefix_parts.append(f"{location}:")
    prefix = " ".join(prefix_parts)
    if prefix:
        return f"{prefix} {body}"
    return body
