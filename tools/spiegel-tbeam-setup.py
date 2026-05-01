#!/usr/bin/env python3
"""Interaktives Setup-Tool: schreibt Bridge- und WLAN-Konfig per USB-Serial
auf einen geflashten T-Beam.

Voraussetzungen:
- T-Beam mit der MeshCore-Spiegel-FW (WITH_WIFITCP_BRIDGE) per USB.
- pyserial (`pip install pyserial`).
- Repeater im Web-UI (https://meshcore.dumke.me) angelegt — Token + Site-UUID
  werden zum Setup gebraucht.

Aufruf:
    tools/spiegel-tbeam-setup.py [--port /dev/ttyACM0]

Das Skript fragt:
- WLAN-SSID und Passwort
- Bridge-Host (Default meshcore.dumke.me)
- Bridge-Token (aus Web-UI)
- Site-UUID (aus Web-UI)
- Scope (public oder pool:<uuid>)
- (Optional) neues Admin-Passwort für die LoRa-Phone-App-Verbindung

… schickt die `set bridge.*` und `bridge enable`-Befehle der Reihe nach
und zeigt die Antworten.
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
import sys
import time
from dataclasses import dataclass

try:
    import serial  # pyserial
except ImportError:  # pragma: no cover
    sys.stderr.write("pyserial fehlt — bitte `pip install pyserial`\n")
    sys.exit(2)


DEFAULT_PORT = "/dev/ttyACM0"
DEFAULT_BAUD = 115200
DEFAULT_HOST = "meshcore.dumke.me"
COMMAND_TIMEOUT_S = 4.0

_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")


@dataclass
class Setup:
    wifi_ssid: str
    wifi_psk: str
    host: str
    token: str
    site: str
    scope: str
    new_password: str | None
    wifi_mac: str | None = None  # "aa:bb:cc:dd:ee:ff" or None for factory default


def prompt(label: str, default: str | None = None, *, secret: bool = False) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        if secret:
            value = getpass.getpass(f"{label}{suffix}: ")
        else:
            value = input(f"{label}{suffix}: ").strip()
        if not value and default is not None:
            return default
        if value:
            return value


def gather_setup() -> Setup:
    print("=== T-Beam-Setup ===")
    wifi_ssid = prompt("WLAN-SSID")
    wifi_psk = prompt("WLAN-Passwort (leer für offenes WLAN)", default="", secret=True)
    host = prompt("Bridge-Host", DEFAULT_HOST)
    token = prompt("Bridge-Token (32 Zeichen, base32)")
    site = prompt("Site-UUID (z.B. 7b2f9e0c-4a51-4d0a-91c8-b5d1e7c63f02)")
    scope = prompt("Scope", "public")
    mac_in = prompt(
        "MAC-Spoof (für Captive-Portal-WLANs; aa:bb:cc:dd:ee:ff oder leer)",
        "",
    )
    wifi_mac = mac_in.strip() or None
    if wifi_mac and not _MAC_RE.match(wifi_mac):
        print("Ungültiges MAC-Format — abgebrochen.", file=sys.stderr)
        sys.exit(1)
    change_pw = prompt("Admin-Passwort jetzt ändern? (y/N)", "n").lower().startswith("y")
    new_password = None
    if change_pw:
        new_password = prompt("Neues Admin-Passwort", secret=True)
        confirm = prompt("Bestätigen", secret=True)
        if confirm != new_password:
            print("Passwörter unterschiedlich — abgebrochen.", file=sys.stderr)
            sys.exit(1)
    return Setup(
        wifi_ssid=wifi_ssid,
        wifi_psk=wifi_psk,
        host=host,
        token=token,
        site=site,
        scope=scope,
        new_password=new_password,
        wifi_mac=wifi_mac,
    )


def run_command(s: serial.Serial, cmd: str, *, hide_value: bool = False) -> str:
    """Schickt eine Zeile, sammelt Antwort bis Timeout. Antwort = was der
    Repeater nach dem Echo zurückgibt (`-> <text>`-Format aus simple_repeater
    main.cpp). Wir geben einfach alles aus, was bis zum Timeout kommt.
    """
    display = cmd if not hide_value else cmd.partition(" ")[0] + " <hidden>"
    print(f"\n>>> {display}")
    s.reset_input_buffer()
    s.write((cmd + "\r").encode("ascii"))
    s.flush()

    deadline = time.monotonic() + COMMAND_TIMEOUT_S
    response_lines: list[str] = []
    while time.monotonic() < deadline:
        line = s.readline()
        if not line:
            continue
        decoded = line.decode("utf-8", errors="replace").rstrip()
        if not decoded:
            continue
        # Echo der eigenen Eingabe schlucken (FW echo'd char-by-char).
        if decoded.strip() == cmd.strip():
            continue
        response_lines.append(decoded)
        # Heuristik: Antwort beginnt mit "  -> " (siehe main.cpp:129).
        # Wenn so eine Zeile da ist, nochmal ein bisschen warten und Schluss.
        if decoded.lstrip().startswith("->"):
            time.sleep(0.2)
            break
    out = "\n".join(response_lines).strip()
    if out:
        print(out)
    else:
        print(f"(keine Antwort innerhalb {COMMAND_TIMEOUT_S:.0f}s)")
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--port", default=DEFAULT_PORT, help=f"Serial-Port (Default {DEFAULT_PORT})")
    p.add_argument("--baud", type=int, default=DEFAULT_BAUD)
    p.add_argument(
        "--no-prompt",
        action="store_true",
        help="Erwartet alle Werte als ENV (MESHCORE_SETUP_*) — für Skripten",
    )
    p.add_argument(
        "--no-reset",
        action="store_true",
        help=(
            "Kein DTR/RTS-Reset triggern (Pflicht für ESP32-S3 native USB-CDC, "
            "z.B. Heltec V4 — der Reset-Pulse würde sonst Download-Mode auslösen)"
        ),
    )
    args = p.parse_args()

    if args.no_prompt:
        try:
            cfg = Setup(
                wifi_ssid=os.environ["MESHCORE_SETUP_WIFI_SSID"],
                wifi_psk=os.environ.get("MESHCORE_SETUP_WIFI_PSK", ""),
                host=os.environ.get("MESHCORE_SETUP_HOST", DEFAULT_HOST),
                token=os.environ["MESHCORE_SETUP_TOKEN"],
                site=os.environ["MESHCORE_SETUP_SITE"],
                scope=os.environ.get("MESHCORE_SETUP_SCOPE", "public"),
                new_password=os.environ.get("MESHCORE_SETUP_NEW_PW"),
                wifi_mac=os.environ.get("MESHCORE_SETUP_WIFI_MAC") or None,
            )
        except KeyError as e:
            print(f"Fehlende ENV-Var: {e}", file=sys.stderr)
            return 1
    else:
        cfg = gather_setup()

    print(f"\nVerbinde zu {args.port} @ {args.baud} …")
    try:
        s = serial.Serial(args.port, args.baud, timeout=0.4)
    except serial.SerialException as e:
        print(f"Serial-Fehler: {e}", file=sys.stderr)
        return 1

    if args.no_reset:
        print("Kein Reset; verbinde direkt zur laufenden FW …")
        time.sleep(0.5)
    else:
        # Reset für klassische USB-Serial-Bridges (CH9102/CP210x). Bei
        # ESP32-S3 native USB-CDC stattdessen --no-reset verwenden.
        s.setDTR(False)
        s.setRTS(True)
        time.sleep(0.1)
        s.setRTS(False)
        print("Reset getriggert; warte 4s auf Boot …")
        time.sleep(4.0)
    s.reset_input_buffer()

    sequence: list[tuple[str, bool]] = []
    if cfg.wifi_mac:
        sequence.append((f"set bridge.wifi.mac {cfg.wifi_mac}", False))
    sequence.extend(
        [
            (f"set bridge.wifi.ssid {cfg.wifi_ssid}", False),
            (f"set bridge.wifi.psk {cfg.wifi_psk}", True),
            (f"set bridge.host {cfg.host}", False),
            (f"set bridge.token {cfg.token}", True),
            (f"set bridge.site {cfg.site}", False),
            (f"set bridge.scope {cfg.scope}", False),
        ]
    )
    if cfg.new_password:
        sequence.append((f"password {cfg.new_password}", True))
    sequence.extend(
        [
            ("bridge enable", False),
            ("bridge status", False),
        ]
    )

    failures = []
    for cmd, hide in sequence:
        try:
            resp = run_command(s, cmd, hide_value=hide)
        except serial.SerialException as e:
            print(f"Serial-Abbruch: {e}", file=sys.stderr)
            return 2
        ok_signals = ("OK", "password now", "state=")
        if not any(sig in resp for sig in ok_signals) and ("ERROR" in resp or resp == ""):
            failures.append((cmd if not hide else cmd.partition(" ")[0], resp))

    s.close()
    print()
    if failures:
        print("Setup mit Warnungen abgeschlossen:")
        for cmd, resp in failures:
            print(f"  - {cmd}: {resp or '(no response)'}")
        return 1
    print("Setup abgeschlossen. `bridge status` sollte state=2 (CONNECTED) zeigen,")
    print("sobald WLAN aufkommt und der Server erreichbar ist.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
