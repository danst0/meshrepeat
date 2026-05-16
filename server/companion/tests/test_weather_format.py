"""Format-Builder für Wetter-Channel-Posts: deterministisch, kein I/O."""

from __future__ import annotations

from meshcore_companion.homeassistant import HAState
from meshcore_companion.weather import format_weather_line, format_weather_line_multi


def _state(state: str = "sunny", **attrs: object) -> HAState:
    return HAState(entity_id="weather.home", state=state, attributes=dict(attrs))


def _sensor(entity_id: str, state: str, unit: str | None = None) -> HAState:
    attrs: dict[str, object] = {}
    if unit is not None:
        attrs["unit_of_measurement"] = unit
    return HAState(entity_id=entity_id, state=state, attributes=attrs)


def test_format_full_weather_entity() -> None:
    state = _state(
        state="sunny",
        temperature=18.4,
        wind_speed=12,
        humidity=62,
    )
    line = format_weather_line(state, location="Bonn")
    assert line == "☀ Bonn: 18°C, sonnig, Wind 12 km/h, 62% RH"


def test_format_without_location() -> None:
    state = _state(state="rainy", temperature=9, humidity=88)
    line = format_weather_line(state)
    assert line == "🌧 9°C, Regen, 88% RH"


def test_format_missing_attributes_skips_silently() -> None:
    state = _state(state="cloudy", temperature=12)
    line = format_weather_line(state, location="Bonn")
    # Kein Wind, keine Humidity → Komponenten werden ausgelassen.
    assert line == "☁ Bonn: 12°C, bewölkt"


def test_format_unknown_condition_falls_back_to_raw_state() -> None:
    """sensor.* ohne Condition-Mapping: keine Emoji, kein Klartext."""
    state = HAState(entity_id="sensor.outdoor_temp", state="18.4", attributes={})
    line = format_weather_line(state, location="Bonn")
    assert line == "Bonn: 18°C"


def test_format_no_data_at_all_returns_raw_state() -> None:
    """Entity ohne Temperatur und ohne bekannte Condition: raw state."""
    state = HAState(entity_id="sensor.foo", state="unavailable", attributes={})
    assert format_weather_line(state) == "unavailable"


def test_format_partlycloudy_lightning_emojis() -> None:
    assert format_weather_line(_state("partlycloudy", temperature=15)).startswith("🌤")
    assert format_weather_line(_state("lightning-rainy", temperature=15)).startswith("⛈")
    assert format_weather_line(_state("snowy", temperature=-2)).startswith("❄")


def test_format_multi_wetterstation_with_units() -> None:
    states = [
        _sensor("sensor.wetterstation_actual_temperature", "18.4", unit="°C"),
        _sensor("sensor.wetterstation_actual_humidity", "62", unit="%"),
        _sensor("sensor.wetterstation_wind_speed", "12", unit="km/h"),
    ]
    line = format_weather_line_multi(states, location="Bonn")
    assert line == "Bonn: 🌡18.4 °C · 💧62% · 💨12 km/h"


def test_format_multi_skips_unavailable() -> None:
    states = [
        _sensor("sensor.wetterstation_temperature", "unavailable", unit="°C"),
        _sensor("sensor.wetterstation_humidity", "62", unit="%"),
    ]
    line = format_weather_line_multi(states)
    assert line == "💧62%"


def test_format_multi_without_unit() -> None:
    states = [_sensor("sensor.foo", "42", unit=None)]
    line = format_weather_line_multi(states, location="X")
    assert line == "X: 42"


def test_format_multi_all_unavailable_returns_empty() -> None:
    states = [_sensor("sensor.t", "unavailable", unit="°C")]
    assert format_weather_line_multi(states, location="Bonn") == ""
