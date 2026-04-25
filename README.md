# MeshCore Internet-Spiegel + Software-Companion

Internet-Spiegel zwischen mehreren MeshCore-LoRa-Mesh-Inseln plus
serverseitiger Software-Companion (vollwertiger MeshCore-Teilnehmer mit
eigener Identität, ohne eigene LoRa-Hardware, der die Bridge-Infrastruktur
als Funk-Uplink nutzt).

## Architektur

```
Standort 1..N
  ┌──────────┐   LoRa   ┌──────────────────┐
  │ Phone /  │◄────────►│ T-Beam Repeater  │
  │ Companion│          │ Custom MeshCore  │
  └──────────┘          │ FW (Bridge ext.) │
                        └──────────┬───────┘
                                   │ wss://meshcore.dumke.me/api/v1/bridge
                                   │ Bearer-Token + Let's Encrypt TLS
                                   ▼
              ┌─────────────────────────────────────┐
              │ cassius — Docker Compose            │
              │                                     │
              │  Traefik2 (existing stack)          │
              │   • IONOS DNS-Challenge LE         │
              │   • routes meshcore.dumke.me ──┐    │
              │                                │    │
              │  ┌─────────────────────────────▼─┐  │
              │  │ app (FastAPI + asyncio)       │  │
              │  │  • REST + Admin/Client UI     │  │
              │  │  • WebSocket /api/v1/bridge   │  │
              │  │  ┌─────────────────────────┐  │  │
              │  │  │ Bridge-Daemon           │  │  │
              │  │  │  • Dedup, Policy, Route │  │  │
              │  │  │  • Hybrid-Scope         │  │  │
              │  │  └────────────┬────────────┘  │  │
              │  │               │ in-process    │  │
              │  │  ┌────────────▼────────────┐  │  │
              │  │  │ Software-Companion      │  │  │
              │  │  │  • N Identitäten / User │  │  │
              │  │  └─────────────────────────┘  │  │
              │  └───────────────────────────────┘  │
              └─────────────────────────────────────┘
```

Repeater bleiben auch ohne Server vollwertige lokale Repeater. Server-Ausfall
pausiert nur die Inter-Site-Bridge.

## Repo-Layout

| Pfad                       | Inhalt                                              |
|----------------------------|-----------------------------------------------------|
| `docs/`                    | Architektur, Threat-Model, ADRs                     |
| `protocol/WIRE.md`         | Wire-Protokoll-Spec Repeater↔Server                 |
| `firmware/`                | PlatformIO-Projekt mit `WifiTcpBridge` + MeshCore   |
| `server/bridge/`           | Python-Daemon, asyncio, WebSocket-Server            |
| `server/companion/`        | Software-Companion (Crypto, Identität, Storage)     |
| `ops/`                     | Docker-Compose, Caddyfile, systemd, Config-Beispiele|
| `tools/meshcore-spiegel-ctl` | Admin-CLI                                         |

## Tech-Stack

- **Firmware**: C++/PlatformIO, MeshCore als Submodul, neue
  `WifiTcpBridge`-Subclass von `BridgeBase`. Zielhardware: LilyGO T-Beam
  V1.1 (ESP32, SX1276, EU868).
- **Server**: Python 3.12, asyncio, strict Type Hints, ruff + mypy --strict.
- **Wire-Protokoll**: WebSocket mit length-bounded CBOR-Frames, Bearer-Token-
  Auth über TLS (Let's Encrypt via Caddy).
- **Persistenz**: SQLite.
- **Konfiguration**: YAML pro Komponente.
- **Deployment**: Docker Compose unter `/home/danst/dockers/meshcore/` auf
  `cassius` (10.0.2.71). Reverse-Proxy: existierender Traefik2-Stack auf
  cassius (`/home/danst/dockers/traefik2/`), wir hängen uns über das
  externe Netz `traefik_proxy` per Labels ein. TLS via IONOS-DNS-Challenge.

## Auth-Modell (Kurzfassung)

Repeater werden per Web-UI registriert (eigener User-Account, Self-Signup
mit E-Mail-Verifikation). Admin-User haben Rolle `admin`, Repeater-Owner
haben Rolle `owner`. Pro Repeater wird ein Bearer-Token erzeugt, der per
**erweitertem MeshCore-Admin-CLI über LoRa-DM** auf den Repeater geschrieben
wird (`set bridge.host`, `set bridge.token`, `set bridge.scope`,
`bridge enable`). Repeater verbindet sich dann mit
`wss://meshcore.dumke.me/api/v1/bridge` und übergibt den Token im
`hello`-Frame. Details: `docs/auth.md`.

## Mesh-Modell (Hybrid)

Jeder Repeater hat einen Scope:
- `public` — Teil eines gemeinsamen, öffentlichen Internet-Spiegels.
- `pool:<uuid>` — Teil eines isolierten Private-Pools des Owners.

Der Server routet Pakete nur innerhalb des Scopes ihres Quell-Repeaters.

## Identitäts-Modell

Ein User (Web-Account) kann **mehrere** Companion-Identitäten anlegen
(1:N). Jede Identität ist ein eigenständiger MeshCore-Teilnehmer mit
eigenem Ed25519-Keypair, eigenem Display-Namen und einer Scope-Bindung
(`public` oder `pool:<uuid>`). Eine Identität kann z.B. nur in einem
privaten Pool existieren oder öffentlich auftauchen. Privat-Keys liegen
nur im Server, niemals im Repeater.

## Phasen

| Phase | Inhalt                                                        | Status |
|-------|---------------------------------------------------------------|--------|
| 0     | Design, Wire-Spec, Repo-Skelett, Docker-Compose-Skelett       | aktiv  |
| 1     | Bridge-Daemon (minimal), Web-Backend (Auth + Token-Mgmt)      | offen  |
| 2     | Custom Repeater-FW (`WifiTcpBridge`, Admin-CLI-Erweiterungen) | offen  |
| 3     | Multi-Site-Tests, Policy-Engine, Hot-Reload, ctl-Tool         | offen  |
| 4     | Software-Companion (Subset MeshCore-Protokoll, REST + CLI)    | offen  |
| 5     | Ops: Prometheus, Backups, Ansible                             | offen  |

## Quickstart (Phase 0 — Stand jetzt)

Es ist noch nichts lauffähig. Phase 0 produziert nur Specs und Skelett.

```bash
# Repo-Layout inspizieren
tree -L 2

# Wire-Protokoll lesen
$EDITOR protocol/WIRE.md

# ADRs lesen
ls docs/adr/
```

Phase 1 wird dann ein erstes lauffähiges Compose-Setup liefern.

## Out of Scope

- Mobile-App-Anpassungen (existierende MeshCore-App reicht für Konfig)
- Andere Hardware als T-Beam V1.1
- LoRaWAN / TTN-Integration

## Lizenz

Noch nicht gewählt. Vorerst privat.
