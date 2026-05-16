"""Lese-Adapter für Home-Assistant-REST-API.

Dünner async-Wrapper um ``GET /api/states/<entity_id>`` mit Bearer-Token.
Konsumenten (z.B. ein zukünftiger Wetter-Poster) injizieren sich eine
``HomeAssistantClient``-Instanz, rufen :meth:`get_state` und verarbeiten
den ``HAState``-Datensatz weiter.

Design:
- Ein langlebiger ``httpx.AsyncClient`` pro Instanz — kein Setup pro Call.
- Keine Retries auf dieser Ebene; der Konsument entscheidet, ob ein Skip
  oder ein Re-Try nach Backoff sinnvoll ist (ein Wetter-Ticker pausiert
  einfach bis zum nächsten Intervall).
- HTTP-Status wird in eine schlanke Exception-Hierarchie übersetzt, damit
  Konsumenten ``HomeAssistantAuthError`` / ``HomeAssistantNotFound``
  gezielt fangen können, ohne `httpx` zu importieren.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Any

import httpx
import structlog

_log = structlog.get_logger("companion.ha")


@dataclass(frozen=True, slots=True)
class HomeAssistantConfig:
    """Konfiguration für einen :class:`HomeAssistantClient`."""

    base_url: str
    """Externe HA-URL inkl. Schema, ohne trailing ``/`` nötig (wird gestripped)."""

    token: str
    """Long-Lived Access Token, der in HA unter Profil → Sicherheit erzeugt wird."""

    timeout_s: float = 10.0
    verify_ssl: bool = True


@dataclass(frozen=True, slots=True)
class HAState:
    """Snapshot eines HA-Entities zum Abruf-Zeitpunkt."""

    entity_id: str
    state: str
    attributes: dict[str, Any] = field(default_factory=dict)
    last_changed: datetime | None = None  # UTC
    last_updated: datetime | None = None  # UTC


class HomeAssistantError(Exception):
    """Basisklasse für alle HA-Fehler — Netzwerk, Timeout, Decode."""


class HomeAssistantAuthError(HomeAssistantError):
    """HTTP 401: Token fehlt, abgelaufen, oder ungültig."""


class HomeAssistantNotFound(HomeAssistantError):
    """HTTP 404: Entity-ID existiert nicht (mehr)."""


def _parse_dt(value: object) -> datetime | None:
    """HA liefert ISO-8601 mit ``+00:00`` — wir normalisieren auf UTC.

    Bei kaputtem/fehlendem Wert lieber ``None`` zurückgeben als die ganze
    Antwort zu verwerfen — die Caller-Logik braucht meist nur ``state``
    bzw. ``attributes``.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


class HomeAssistantClient:
    """Async-Client gegen die HA-REST-API.

    Beispiel::

        cfg = HomeAssistantConfig(base_url="https://lu.dumke.me", token="...")
        client = HomeAssistantClient(cfg)
        state = await client.get_state("weather.home")
        print(state.state, state.attributes.get("temperature"))
        await client.aclose()
    """

    def __init__(
        self,
        cfg: HomeAssistantConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._cfg = cfg
        # ``transport`` ist nur für Tests gedacht (httpx.MockTransport).
        self._client = httpx.AsyncClient(
            base_url=cfg.base_url.rstrip("/"),
            timeout=cfg.timeout_s,
            verify=cfg.verify_ssl,
            headers={
                "Authorization": f"Bearer {cfg.token}",
                "Accept": "application/json",
            },
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get_state(self, entity_id: str) -> HAState:
        """Lade den aktuellen Zustand eines HA-Entities.

        Raises:
            HomeAssistantAuthError: Token ungültig (401).
            HomeAssistantNotFound: Entity unbekannt (404).
            HomeAssistantError: Sonstige Netzwerk-/Decode-Probleme.
        """
        path = f"/api/states/{entity_id}"
        try:
            resp = await self._client.get(path)
        except httpx.TimeoutException as exc:
            _log.warning("ha_timeout", entity_id=entity_id, timeout_s=self._cfg.timeout_s)
            raise HomeAssistantError(f"timeout calling {path}") from exc
        except httpx.HTTPError as exc:
            _log.warning("ha_http_error", entity_id=entity_id, error=str(exc))
            raise HomeAssistantError(f"http error calling {path}: {exc}") from exc

        if resp.status_code == HTTPStatus.UNAUTHORIZED:
            _log.warning("ha_auth_error", entity_id=entity_id)
            raise HomeAssistantAuthError("HA token invalid or missing")
        if resp.status_code == HTTPStatus.NOT_FOUND:
            _log.info("ha_entity_not_found", entity_id=entity_id)
            raise HomeAssistantNotFound(f"entity {entity_id!r} not found")
        if resp.status_code >= HTTPStatus.BAD_REQUEST:
            _log.warning("ha_unexpected_status", entity_id=entity_id, status=resp.status_code)
            raise HomeAssistantError(f"unexpected status {resp.status_code} for {path}")

        try:
            data = resp.json()
        except ValueError as exc:
            _log.warning("ha_bad_json", entity_id=entity_id, error=str(exc))
            raise HomeAssistantError(f"invalid JSON from {path}") from exc

        if not isinstance(data, dict):
            raise HomeAssistantError(f"expected JSON object, got {type(data).__name__}")

        state = data.get("state")
        if not isinstance(state, str):
            raise HomeAssistantError(f"missing/invalid 'state' for {entity_id!r}")
        attrs = data.get("attributes")
        if not isinstance(attrs, dict):
            attrs = {}
        return HAState(
            entity_id=entity_id,
            state=state,
            attributes=attrs,
            last_changed=_parse_dt(data.get("last_changed")),
            last_updated=_parse_dt(data.get("last_updated")),
        )
