"""Format-Builder für Wetter-Channel-Posts: deterministisch, kein I/O."""

from __future__ import annotations

from meshcore_companion.homeassistant import HAState
from meshcore_companion.weather import format_weather_line


def _state(state: str = "sunny", **attrs: object) -> HAState:
    return HAState(entity_id="weather.home", state=state, attributes=dict(attrs))


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
