# T-Beam V1.1 Erst-Inbetriebnahme

Schritt-für-Schritt-Anleitung vom geflashten Repeater bis zur ersten
Bridge-Verbindung. Voraussetzung: `pio run -e tbeam_sx1276_wifitcp -t upload`
ist durchgelaufen, der T-Beam ist gebootet, das OLED zeigt etwas an.

## 1) MeshCore-Phone-App vorbereiten

App-Seite: <https://meshcore.co.uk/> → Android oder iOS.

- App öffnen. Eigene Identität anlegen, falls noch nicht geschehen.
- Repeater erscheint nach kurzer Zeit als Advert mit Name `MeshCore-Spiegel`.
  Falls nicht: am T-Beam Reset-Knopf drücken, der Erstadvert erfolgt
  innerhalb der ersten 60 Sekunden.

## 2) Repeater als Contact einlagen + Login

- In der App: Repeater-Eintrag → "Add Contact".
- Aus dem Repeater-Detail: "Send Login" → Passwort `password` (Default).
- Erfolg sichtbar als Login-Notification + freigeschaltetes Admin-CLI.

## 3) Pflicht: Default-Passwort ändern

Im Admin-CLI des Repeaters (in der App):

```
password meinneuesgeheim
```

Antwort: `password now: meinneuesgeheim`. Notiere es — ohne dieses
Passwort kommt niemand mehr ins Admin-CLI.

> Solange das Default-Passwort aktiv ist, gibt der Repeater bei jedem
> `set bridge.*` und `bridge enable` die Antwort
> `ERROR: change default password first` — Schutz gegen Funk-Übernahme im
> Pairing-Window.

## 4) WLAN-Zugang konfigurieren

```
set bridge.wifi.ssid <SSID>
set bridge.wifi.psk <Passphrase>
```

Antwort jeweils: `OK`.

## 5) Repeater im Web-UI registrieren

- Browser öffnen: <https://meshcore.dumke.me/signup>
- Account anlegen, E-Mail bestätigen, einloggen.
- Dashboard → "+ Neuen Repeater anlegen".
- Name vergeben, Scope `public` oder `pool:new` wählen.
- Submit → der Server zeigt einmalig:
  - `<TOKEN>` (32 Zeichen base32)
  - `<SITE-UUID>`
  - die exakten `set bridge.*`-Befehle in einem `<pre>`-Block.

## 6) Bridge-Konfig in den Repeater spielen

Aus der Web-UI direkt in die App-CLI kopieren:

```
set bridge.host meshcore.dumke.me
set bridge.token <TOKEN>
set bridge.site <SITE-UUID>
set bridge.scope public
bridge enable
```

Jeder Befehl bekommt `OK` zurück.

## 7) Verbindungsstatus checken

```
bridge status
```

Erwartete Antwort: `state=2 rec=0 err=-` (state 2 = CONNECTED).

Auf der Web-UI sieht man unter dem Repeater "letzte Verbindung: vor X Sek."

## Fehlerbilder

| Symptom                                                           | Ursache + Fix                                                  |
|-------------------------------------------------------------------|---------------------------------------------------------------|
| `bridge status` zeigt `state=3 rec=N err=ws closed`              | TLS-Cert oder DNS — Hostname checken; ISRG-X1 nur LE-Certs     |
| `state=1 rec=N err=wifi timeout`                                  | SSID/PSK falsch; in Funkreichweite eines AP?                   |
| `state=4 rec=N err=heartbeat timeout`                             | Server lebt nicht, oder Token wurde widerrufen                  |
| `ERROR: change default password first`                            | Passwort wurde nicht gewechselt (Schritt 3 nachholen)           |
| Repeater zeigt sich gar nicht im Mesh                             | Erstadvert zu lang her — `reboot` oder Reset-Knopf              |

## Factory-Reset

Falls Owner-Passwort verloren oder Repeater "verloren":

- Über USB-Serial: `pio device monitor` → `password password` (wenn
  Login noch geht), oder
- Komplett-Erase: `pio run -e tbeam_sx1276_wifitcp -t erase` → re-flash

NVS-Volumes inklusive Bridge-Token werden dabei gelöscht.

## Logs live mitlesen

```bash
pio device monitor -e tbeam_sx1276_wifitcp -p /dev/ttyACM0 -b 115200
```

Mit `Ctrl-T h` Hilfe; `Ctrl-C` zum Verlassen.
