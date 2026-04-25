# ADR 001: WebSocket statt Raw-TCP für Bridge-Transport

Datum: 2026-04-25
Status: accepted

## Kontext

Das Briefing schlug ursprünglich length-prefixed CBOR über TLS auf
einem dedizierten Port (z.B. 8765) vor. Mit der Entscheidung, alles
über `meshcore.dumke.me:443` hinter dem existierenden Traefik2-
Reverse-Proxy auf cassius zu fahren (Q10), ist ein eigener TLS-Port
nicht mehr verfügbar — der Reverse-Proxy multiplexed auf HTTP/
WebSocket-Ebene.

## Entscheidung

Bridge-Verbindung läuft als **WebSocket** (`wss://...`) über Caddy.
Frame-Body bleibt CBOR; statt eigenem `uint16_be`-Length-Prefix
nutzen wir die WS-Frame-Grenzen direkt (1 WS-Binary-Frame =
1 Wire-Frame).

## Folgen

### Vorteile

- Traefik macht TLS, ACME (DNS-Challenge IONOS), Hostname-Routing automatisch.
- Heartbeat optional via WS-Ping/Pong (ergänzend zu App-Layer-`hb`).
- Reconnect-Semantik in WS-Libraries (auch ESP32-seitig) sauber gelöst.
- Single-Port-Deployment vereinfacht Firewall-Konfiguration auf cassius.

### Nachteile

- Geringer Overhead pro Frame (~6 Byte WS-Header). Akzeptabel für
  unsere Bandbreitenklasse (LoRa < 1 kbit/s pro Repeater).
- Ein zusätzlicher Layer (HTTP-Upgrade) im Verbindungsaufbau.

## Verworfen

- **Raw TLS auf Port 8765**: Zweite Cert-Toolchain (separates ACME oder
  selbst-signiert), Firewall-Regel zusätzlich, kein Reverse-Proxy-Schutz.
- **HTTP-Long-Polling**: Latenz unakzeptabel.
- **gRPC**: ESP32-Toolchain ist mau, Protobuf-Generator-Pipeline für
  Firmware unverhältnismäßig.
