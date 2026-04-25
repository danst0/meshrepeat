# ADR 006: Token-Auslieferung per MeshCore-Admin-LoRa-DM

Datum: 2026-04-25
Status: accepted

## Kontext

Repeater müssen einen Bridge-Endpoint und einen Bearer-Token
zugewiesen bekommen. Out-of-band-Mechanismen: USB-Serial,
Web-Captive-Portal, BLE, oder LoRa-DM via MeshCore-Admin-CLI.

User hat Q8=A entschieden — MeshCore-Admin-CLI erweitern.

## Entscheidung

Repeater-Konfiguration erfolgt über die existierende, von MeshCore
abgesicherte Admin-CLI per LoRa-DM. Wir patchen das CLI im
Custom-FW, um neue `set bridge.*`-Befehle zu unterstützen
(Liste in `docs/auth.md`). Owner nutzt seine reguläre MeshCore-
Phone-App, um die Admin-DMs zu senden.

Die Admin-CLI ist authentifiziert: jeder Repeater hat einen
Admin-Pubkey, nur Nachrichten signiert mit dem zugehörigen Privkey
werden akzeptiert. Initial-Pairing (Erst-Setzen des Admin-Pubkeys)
erfolgt **out-of-band** über USB-Serial-CLI bei Erst-Inbetriebnahme
(MeshCore-Standard).

Token werden in NVS unter Namespace `mcbridge` abgelegt. Beim Lesen
zurück wird nur ein SHA-256-Prefix exposiert, nicht der Klartext-Token.

## Folgen

### Vorteile

- Keine zusätzliche Hardware (kein BLE-Pairing-UI nötig).
- Existierende MeshCore-Phone-App reicht.
- Admin-DMs sind verschlüsselt (AES-128) und signiert (HMAC-SHA256
  und Ed25519-Sig); Token ist on-air nicht im Klartext.
- Token-Rotation: einfach erneut Admin-DM mit neuem Token.

### Nachteile

- Initial-Setup erfordert physischen USB-Zugang einmalig (für
  Admin-Pubkey-Pairing). Akzeptiert — Standard-MeshCore-Workflow.
- Token in einer LoRa-DM ist auf Payload-Größe begrenzt. 32 ASCII-
  Zeichen passen in einen Datagram-Payload.
- Wer den Repeater physisch hat, kann NVS dumpen → Token-Leak.
  Owner muss bei Verlust rotieren.

## Verworfen

- **Captive-Portal**: zusätzliche Web-UI auf dem ESP32, Konfigurations-
  PSK-Frage, schlechter UX bei Multi-Repeater-Owner.
- **USB-Only**: Owner muss bei jeder Token-Rotation an die Hardware
  ran — schlechter UX bei vielen Repeatern.
- **BLE**: zusätzliche Stack-Konfiguration, App-Pairing-Flow.
