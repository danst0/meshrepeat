# ADR 006: Repeater-Onboarding über MeshCore-Standard-Login per LoRa

Datum: 2026-04-25 (revised)
Status: accepted

## Kontext

Repeater müssen einen Bridge-Endpoint und einen Bearer-Token zugewiesen
bekommen. Erstkontakt-Pairing-Optionen:

- USB-Serial-CLI (Henne-Ei-frei, aber Kabel nötig)
- BLE-Pairing (zusätzliche Stack-Komplexität)
- Eigenes LoRa-Pairing-Protokoll (Time-Window, Pairing-Code, …)
- **MeshCore-Standard-Login per Admin-Passwort über LoRa**

Beim Pin-Wechsel auf MeshCore `repeater-v1.15.0` zeigte sich, dass das
existierende `CommonCLI` bereits ein vollständiges passwort-basiertes
Admin-Login hat (`_prefs.password`, CLI-Befehl `password <new>`,
App-Seite `BaseChatMesh::sendLogin`). Der User hat sich für diesen Weg
entschieden.

## Entscheidung

Onboarding erfolgt **ohne eigenes Pairing-Protokoll**:

1. Owner flasht Repeater. FW kommt mit dem MeshCore-Default-Admin-Passwort
   `password`.
2. Owner öffnet die offizielle MeshCore-Phone-App, fügt den neu gestarteten
   Repeater per Advert als Contact hinzu, loggt sich mit `password` ein.
3. **Pflicht**: Owner ändert das Admin-Passwort sofort:
   `password <neues_passwort>`. Solange das Default-Passwort aktiv ist,
   blockt das CLI alle `set bridge.*`-Befehle (Schutz vor Funk-Übernahme
   im Pairing-Window).
4. Owner setzt die Bridge-Konfiguration im selben Admin-Channel:
   `set bridge.host meshcore.dumke.me`, `set bridge.token <T>`,
   `set bridge.site <UUID>`, `set bridge.scope <s>`, `bridge enable`.

Die zusätzlichen `set bridge.*`-Befehle ergänzen wir in einer Subclass
von `CommonCLI` oder via Hook im `simple_repeater`-Bootstrap (siehe
firmware-Code, Phase 2).

## Folgen

### Vorteile

- Kein eigenes Pairing-Protokoll nötig — wir nutzen einen etablierten,
  in der App bereits implementierten Mechanismus.
- Keine Kabel, keine Captive-Portals, keine BLE-Stacks.
- Repeater-Übernahme = Passwort kennen. Recovery = Factory-Reset
  (NVS-Erase) oder neuer Flash.
- Token + Endpoint kommen über denselben Admin-Channel wie alle anderen
  Konfig-Settings.

### Nachteile

- Default-Passwort `password` ist ab Power-on bekannt; wer in
  Funkreichweite ist, kann sich vor dem rechtmäßigen Owner einloggen.
  → Mitigation: Default-Passwort-Lock auf `set bridge.*` (Repeater
  weigert sich, einen Bridge-Endpoint zu setzen, solange das Default-
  Passwort aktiv ist). Der schlimmste Pre-Pairing-Schaden ist, dass
  jemand das Passwort ändert; der Owner merkt das beim eigenen Login
  und macht einen Factory-Reset.
- 16-Zeichen-Limit für das Passwort (`_prefs.password[16]`, Upstream-
  Konstante). Ausreichend, wenn der Owner ein zufälliges Passwort wählt.
- Bei Verlust des Passworts: NVS-Erase (Owner verliert seine Identität;
  Repeater muss neu in der Web-UI angelegt werden).

### Pflicht-Erweiterungen in unserer Custom-FW

- Subclass / Hook in `CommonCLI`:
  - Neue Befehle: `bridge enable`, `bridge disable`, `bridge status`,
    `set bridge.host`, `set bridge.token`, `set bridge.scope`,
    `set bridge.site`, `set bridge.path`.
  - Default-Passwort-Lock: alle `set bridge.*` und `bridge enable`
    werfen `ERROR: change default password first`, wenn
    `strcmp(_prefs.password, "password") == 0`.
- NVS-Persistenz für die neuen Felder unter Namespace `mcbridge`
  (separat von MeshCore-Prefs, damit Submodul-Updates nicht kollidieren).

## Verworfen

- **USB-only-Pairing**: schlechter UX, alte Annahme aus ADR-Erstfassung.
- **Eigenes LoRa-Pairing-Protokoll**: redundant zum existierenden
  MeshCore-Login.
- **Captive-Portal**: zusätzliche WebUI auf dem ESP32, schlechter UX
  bei Multi-Repeater-Owner.
