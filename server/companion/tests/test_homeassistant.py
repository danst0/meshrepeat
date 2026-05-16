"""HA-Lese-Adapter: HTTP-Schicht via ``httpx.MockTransport``.

Kein Netzwerk, kein echter HA — wir injizieren einen MockTransport in den
Client-Konstruktor und prüfen Header, Pfad und Fehlerübersetzung.
"""

from __future__ import annotations

import httpx
import pytest

from meshcore_companion.homeassistant import (
    HomeAssistantAuthError,
    HomeAssistantClient,
    HomeAssistantConfig,
    HomeAssistantError,
    HomeAssistantNotFound,
)


def _client(handler) -> HomeAssistantClient:  # type: ignore[no-untyped-def]
    cfg = HomeAssistantConfig(
        base_url="https://lu.dumke.me",
        token="test-token-123",
        timeout_s=5.0,
    )
    return HomeAssistantClient(cfg, transport=httpx.MockTransport(handler))


async def test_get_state_ok() -> None:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(
            200,
            json={
                "entity_id": "weather.home",
                "state": "sunny",
                "attributes": {
                    "temperature": 18.4,
                    "humidity": 62,
                    "wind_speed": 12.0,
                },
                "last_changed": "2026-05-16T10:00:00+00:00",
                "last_updated": "2026-05-16T10:05:30+00:00",
            },
        )

    client = _client(handler)
    try:
        state = await client.get_state("weather.home")
    finally:
        await client.aclose()

    assert state.entity_id == "weather.home"
    assert state.state == "sunny"
    assert state.attributes["temperature"] == 18.4
    assert state.last_changed is not None
    assert state.last_changed.tzinfo is not None
    assert state.last_changed.utcoffset().total_seconds() == 0  # type: ignore[union-attr]
    assert state.last_updated is not None

    # Header + Pfad-Konstruktion prüfen.
    assert len(seen) == 1
    req = seen[0]
    assert req.url.path == "/api/states/weather.home"
    assert req.headers["authorization"] == "Bearer test-token-123"
    assert req.headers["accept"] == "application/json"


async def test_get_state_not_found() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "Entity not found."})

    client = _client(handler)
    try:
        with pytest.raises(HomeAssistantNotFound):
            await client.get_state("sensor.does_not_exist")
    finally:
        await client.aclose()


async def test_get_state_auth_error() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "Unauthorized"})

    client = _client(handler)
    try:
        with pytest.raises(HomeAssistantAuthError):
            await client.get_state("weather.home")
    finally:
        await client.aclose()


async def test_get_state_missing_state_field() -> None:
    """Defensiv: HA-Antwort ohne ``state``-Feld → HomeAssistantError."""

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"entity_id": "weather.home", "attributes": {}})

    client = _client(handler)
    try:
        with pytest.raises(HomeAssistantError):
            await client.get_state("weather.home")
    finally:
        await client.aclose()
