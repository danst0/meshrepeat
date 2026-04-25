# Repeater-Firmware (PlatformIO)

Custom MeshCore-Repeater-Firmware mit zusätzlicher
`WifiTcpBridge`-Subclass von `BridgeBase`. MeshCore wird als Git-Submodul
unter `lib/meshcore` eingebunden.

## Phase 0 — Stand jetzt

Es gibt nur Skelett-Files. Build noch nicht eingerichtet, MeshCore-
Submodul noch nicht hinzugefügt.

## Geplante Struktur (Phase 2)

```
firmware/
├── platformio.ini
├── meshcore-pin.txt           # gepinnter MeshCore-Commit/Tag
├── partitions.csv             # ESP32-Flash-Layout
├── src/
│   ├── main.cpp               # Repeater-Bootstrap
│   ├── WifiTcpBridge.h        # neue BridgeBase-Subclass
│   ├── WifiTcpBridge.cpp
│   ├── cli/
│   │   └── BridgeCommands.cpp # set bridge.host / .token / .scope etc.
│   └── certs/
│       └── isrg_root_x1.h     # einkompilierte Let's-Encrypt-Root-CA
└── lib/
    └── meshcore/              # git submodule
```

## Setup (sobald Phase 2 startet)

```bash
cd firmware
git submodule add https://github.com/meshcore-dev/MeshCore lib/meshcore
git -C lib/meshcore checkout "$(cat meshcore-pin.txt)"
pio run -e tbeam-eu868
pio run -e tbeam-eu868 -t upload
```

## Zielhardware

- LilyGO T-Beam V1.1 (ESP32, SX1276, EU868)

Andere Boards sind explizit out-of-scope für v1.

## Bridge-CLI (Phase 2)

Erweiterte Admin-Befehle, signiert mit Admin-Pubkey wie alle anderen
`set`-Befehle. Übertragung per LoRa-DM aus der existierenden
MeshCore-Phone-App. Liste in `/docs/auth.md`.
