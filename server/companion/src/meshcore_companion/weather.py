"""Format-Builder für Wetter-Posts aus Home-Assistant-States.

Pure-Function-Modul ohne I/O. Zwei Eintrittspunkte:

* :func:`format_weather_line` — ein einzelner :class:`HAState`. Für
  ``weather.*``-Entities mit Standardattributen (temperature, humidity,
  wind_speed) zieht der Builder das Maximum an Information raus.
* :func:`format_weather_line_multi` — Liste von Sensor-States (z.B.
  einzelne Wetterstations-Sensoren). Pro State wird ``state +
  unit_of_measurement`` ausgegeben; die Reihenfolge bleibt erhalten.

Designziele:
- LoRa-Bytecount klein halten (Zielzeile ≤ ~120 Bytes nach UTF-8-Encoding).
- Deterministisch: gleiche Inputs → gleiche Zeile.
- Robust gegen fehlende Attribute: Felder, die HA nicht liefert, werden
  einfach weggelassen statt eine Exception zu werfen.
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


# Pro-Sensor-Emoji nach entity_id-Substring. Schmückt die Multi-Variante,
# damit "18.4 °C, 62 %, 12 km/h" als "🌡18.4°C · 💧62% · 💨12 km/h"
# lesbarer wird. Reihenfolge der Patterns ist relevant: erstes Treffer-Pattern
# gewinnt.
_SENSOR_EMOJI: tuple[tuple[str, str], ...] = (
    ("temperature", "🌡"),
    ("temp", "🌡"),
    ("humidity", "💧"),
    ("rain", "🌧"),
    ("wind_speed", "💨"),
    ("windspeed", "💨"),
    ("wind", "💨"),
    ("pressure", "📈"),
    ("uv", "☀"),
    ("illuminance", "💡"),
    ("lux", "💡"),
)


def _emoji_for_entity(entity_id: str) -> str:
    lowered = entity_id.lower()
    for substr, emoji in _SENSOR_EMOJI:
        if substr in lowered:
            return emoji
    return ""


def fmt_sensor_value(state: HAState) -> str | None:
    """``HAState`` → ``"18.4 °C"`` o.ä. Liefert ``None``, wenn der State
    keinen darstellbaren Wert hat (z.B. ``"unavailable"``).

    Zahlen werden konservativ formatiert: enthält der Roh-String einen
    Punkt, eine Nachkommastelle; sonst ganzzahlig. So vermeiden wir den
    häufigen Fall, dass HA ``"62"`` liefert und wir daraus ``"62.0 %"``
    machen würden.
    """
    raw = state.state
    if not raw or raw.lower() in ("unavailable", "unknown", "none"):
        return None
    unit_raw = state.attributes.get("unit_of_measurement")
    unit = unit_raw if isinstance(unit_raw, str) and unit_raw else ""
    try:
        f = float(raw)
    except (TypeError, ValueError):
        val = raw
    else:
        val = f"{f:.1f}" if "." in raw else f"{int(f)}"
    if unit:
        # %-Einheiten ohne Leerzeichen — HA-Konvention.
        if unit == "%":
            return f"{val}%"
        return f"{val} {unit}"
    return val


def format_weather_line_multi(
    states: list[HAState], location: str | None = None
) -> str:
    """Baue eine Wetter-Zeile aus mehreren HA-Sensor-States.

    Beispiel (location = ``"Bonn"``)::

        states = [
            HAState("sensor.wetterstation_actual_temperature", "18.4",
                    {"unit_of_measurement": "°C"}),
            HAState("sensor.wetterstation_actual_humidity", "62",
                    {"unit_of_measurement": "%"}),
            HAState("sensor.wetterstation_wind_speed", "12",
                    {"unit_of_measurement": "km/h"}),
        ]
        → "Bonn: 🌡18.4 °C · 💧62% · 💨12 km/h"

    Sensoren mit ``state="unavailable"`` werden übersprungen; ist nach
    dem Filter nichts mehr übrig, ist die Zeile leer (Caller-Loop
    skippt den Post dann).
    """
    parts: list[str] = []
    for s in states:
        value = fmt_sensor_value(s)
        if value is None:
            continue
        emoji = _emoji_for_entity(s.entity_id)
        parts.append(f"{emoji}{value}" if emoji else value)
    body = " · ".join(parts)
    if location and body:
        return f"{location}: {body}"
    return body
