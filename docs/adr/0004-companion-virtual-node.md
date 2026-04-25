# ADR 004: Software-Companion als virtueller Mesh-Node in Python

Datum: 2026-04-25
Status: accepted

## Kontext

Der MeshCore-"Companion-Mode" (siehe Recherche) ist **kein**
On-Air-Pakettyp, sondern ein API-Layer (Serial/BLE/WiFi-TCP) zwischen
einem lokalen Frontend (Phone-App) und einem LoRa-Node, der die
On-Air-Pakete erzeugt.

Für unseren Server-Companion gab es zwei Wege:

- A) **Virtueller Mesh-Node**: Python implementiert das MeshCore-
     Paketformat und die Crypto direkt. Der Bridge-Daemon injiziert
     die erzeugten Pakete in **alle** Repeater des relevanten Scopes.
- B) **Companion-API-Client**: Python redet das Companion-API-Protokoll
     mit einem ausgewählten Bridge-Repeater, der Repeater erzeugt
     die On-Air-Pakete.

User hat A entschieden.

## Entscheidung

Server-Companion ist eine vollständige Python-Implementierung der
benötigten MeshCore-Pakettypen (Advert, DM, Channel-Broadcast, ACK).
Crypto: Ed25519-Identitäten, X25519-ECDH (über Ed25519→X25519-Transposition),
AES-128 + HMAC-SHA256 für DM, symmetrische Channel-Keys für
Channel-Broadcasts.

Der Bridge-Daemon stellt eine schmale **In-Process-API** bereit, über
die Companion-Pakete als wären sie von "allen" Repeatern in einem Scope
empfangen worden, in den Routing-Pfad eingespeist werden — und
umgekehrt eingehende Pakete (Adverts, DMs an Companion-Pubkeys) an die
Companion-Logik durchgereicht.

## Folgen

### Vorteile

- Companion ist nicht an einen einzelnen Repeater gebunden — Repeater-
  Ausfall hat keinen Companion-Impact.
- Repeater-FW bleibt schlank (kein API-Reimplement).
- Saubere Trennung: Companion ist Library + Service, Bridge ist Daemon.
- Tests in Python deutlich einfacher als auf der Firmware.

### Nachteile

- MeshCore-Paketformat und -Crypto müssen in Python nachgebaut werden
  (Aufwand Phase 4). Quellcode-Referenz: MeshCore-Submodul liegt im
  Repo, kann als Spezifikation gelesen werden.
- Pakete des Companions werden über alle Repeater eines Scopes
  gleichzeitig gesendet → gleiches Paket potenziell mehrfach on-air,
  Empfänger-Dedup fängt es ab. Mehrkosten an Funkzeit; akzeptiert.
- Update-Zwang bei MeshCore-Protokoll-Änderungen: wir müssen Python-
  Implementation nachziehen, sonst Inkompatibilität. Pin-Strategie für
  MeshCore-Submodul (siehe `firmware/meshcore-pin.txt`) hilft.

## Verworfen

- B) Companion-API-Client: bindet Companion an einzelnen Repeater,
  kompliziert Failover.
