#!/usr/bin/env python3
"""Status-Check für einen per USB-Serial angeschlossenen Spiegel-Repeater.

Schickt eine Reihe read-only Befehle an die laufende FW und gibt die
Antworten formatiert aus. Defaultmäßig **kein** Reset — wir docken an die
laufende FW an, damit nicht jedes Mal 4s auf Boot gewartet werden muss
(und damit Captive-Portal-/WLAN-Sessions nicht abreißen).

Voraussetzungen:
- Spiegel-FW (WITH_WIFITCP_BRIDGE) per USB.
- pyserial (`pip install pyserial`).

Aufruf:
    tools/spiegel-tbeam-status.py [--port /dev/ttyACM0] [--json]

Mit `--reset` wird die FW vor dem Status-Check kurz resettet (klassische
USB-Serial-Bridges, *nicht* ESP32-S3 native USB-CDC).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, field

try:
    import serial  # pyserial
except ImportError:  # pragma: no cover
    sys.stderr.write("pyserial fehlt — bitte `pip install pyserial`\n")
    sys.exit(2)


DEFAULT_PORT = "/dev/ttyACM0"
DEFAULT_BAUD = 115200
COMMAND_TIMEOUT_S = 3.0

# Aus firmware/src/WifiTcpBridge.h:52
_BRIDGE_STATE_CONNECTED = 2
BRIDGE_STATES = {
    0: "IDLE",
    1: "CONNECT_W (WiFi joining)",
    _BRIDGE_STATE_CONNECTED: "CONNECTED",
    3: "BACKOFF (reconnect pending)",
}

# Read-only Status-Befehle (Label, Command). Reihenfolge = Ausgabe-Reihenfolge.
STATUS_COMMANDS: list[tuple[str, str]] = [
    ("firmware", "ver"),
    ("board", "board"),
    ("clock", "clock"),
    ("bridge.status", "bridge status"),
    ("bridge.host", "get bridge.host"),
    ("bridge.port", "get bridge.port"),
    ("bridge.path", "get bridge.path"),
    ("bridge.scope", "get bridge.scope"),
    ("bridge.site", "get bridge.site"),
    ("bridge.wifi.ssid", "get bridge.wifi.ssid"),
    ("bridge.wifi.mac", "get bridge.wifi.mac"),
    ("neighbors", "neighbors"),
    ("stats.core", "stats-core"),
    ("stats.radio", "stats-radio"),
    ("stats.packets", "stats-packets"),
]

_BRIDGE_STATUS_RE = re.compile(r"state=(\d+)\s+rec=(\d+)\s+err=(.+)")


@dataclass
class CommandResult:
    label: str
    command: str
    response: str
    elapsed_s: float = 0.0
    raw: list[str] = field(default_factory=list)


def run_command(s: serial.Serial, cmd: str) -> CommandResult:
    """Sendet eine Zeile, sammelt Antwort bis Timeout (oder bis Zeile mit
    `->`-Präfix, siehe simple_repeater main.cpp).
    """
    s.reset_input_buffer()
    t0 = time.monotonic()
    s.write((cmd + "\r").encode("ascii"))
    s.flush()

    deadline = t0 + COMMAND_TIMEOUT_S
    raw_lines: list[str] = []
    response_lines: list[str] = []
    while time.monotonic() < deadline:
        line = s.readline()
        if not line:
            continue
        decoded = line.decode("utf-8", errors="replace").rstrip()
        raw_lines.append(decoded)
        if not decoded:
            continue
        if decoded.strip() == cmd.strip():
            continue  # Echo der eigenen Eingabe
        response_lines.append(decoded)
        if decoded.lstrip().startswith("->"):
            time.sleep(0.15)
            break

    return CommandResult(
        label="",
        command=cmd,
        response="\n".join(response_lines).strip(),
        elapsed_s=time.monotonic() - t0,
        raw=raw_lines,
    )


def strip_arrow(text: str) -> str:
    """Entfernt einen führenden `  -> `-Präfix und leading whitespace."""
    out = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("->"):
            stripped = stripped[2:].lstrip()
        out.append(stripped)
    return "\n".join(out).strip()


def parse_bridge_status(text: str) -> dict[str, str | int] | None:
    """`state=2 rec=0 err=-` → dict."""
    for line in text.splitlines():
        m = _BRIDGE_STATUS_RE.search(line)
        if m:
            state_num = int(m.group(1))
            return {
                "state": state_num,
                "state_name": BRIDGE_STATES.get(state_num, f"UNKNOWN({state_num})"),
                "reconnects": int(m.group(2)),
                "last_error": m.group(3).strip(),
            }
    return None


def render_human(results: list[CommandResult]) -> int:
    """Pretty-print + Exit-Code (0 = bridge CONNECTED, 1 = nicht CONNECTED, 2 = keine Antwort)."""
    print("\n=== Spiegel-Repeater Status ===\n")
    bridge_state: int | None = None
    saw_any_response = False

    label_w = max(len(label) for label, _ in STATUS_COMMANDS)
    for r in results:
        value = strip_arrow(r.response) if r.response else "(keine Antwort)"
        if r.response:
            saw_any_response = True
        if r.label == "bridge.status":
            parsed = parse_bridge_status(r.response)
            if parsed is not None:
                bridge_state = int(parsed["state"])
                value = (
                    f"{parsed['state_name']}  "
                    f"(state={parsed['state']}, reconnects={parsed['reconnects']}, "
                    f"last_error={parsed['last_error']})"
                )
        # Mehrzeilige Antworten eingerückt unter dem Label.
        lines = value.splitlines() or [""]
        print(f"  {r.label:<{label_w}} : {lines[0]}")
        for extra in lines[1:]:
            print(f"  {' ' * label_w}   {extra}")

    print()
    if not saw_any_response:
        print("Keine einzige Antwort — falscher Port? FW läuft nicht? "
              "Mit --reset versuchen oder Baudrate prüfen.", file=sys.stderr)
        return 2
    if bridge_state is None:
        print("Bridge-Status konnte nicht gelesen werden (FW ohne "
              "WITH_WIFITCP_BRIDGE?).", file=sys.stderr)
        return 1
    if bridge_state == _BRIDGE_STATE_CONNECTED:
        print("→ Bridge ist verbunden (state=CONNECTED).")
        return 0
    print(f"→ Bridge nicht verbunden (state={bridge_state} "
          f"{BRIDGE_STATES.get(bridge_state, '?')}).", file=sys.stderr)
    return 1


def render_json(results: list[CommandResult]) -> int:
    payload: dict[str, object] = {}
    bridge_state: int | None = None
    for r in results:
        clean = strip_arrow(r.response)
        entry: dict[str, object] = {
            "command": r.command,
            "response": clean,
            "elapsed_s": round(r.elapsed_s, 3),
        }
        if r.label == "bridge.status":
            parsed = parse_bridge_status(r.response)
            if parsed is not None:
                entry["parsed"] = parsed
                bridge_state = int(parsed["state"])
        payload[r.label] = entry
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    if bridge_state == _BRIDGE_STATE_CONNECTED:
        return 0
    if bridge_state is None:
        return 2
    return 1


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--port", default=DEFAULT_PORT, help=f"Serial-Port (Default {DEFAULT_PORT})")
    p.add_argument("--baud", type=int, default=DEFAULT_BAUD)
    p.add_argument(
        "--reset",
        action="store_true",
        help=(
            "DTR/RTS-Reset triggern (4s Boot-Wartezeit). Default: kein Reset, "
            "Aufschalten auf laufende FW. Für ESP32-S3 native USB-CDC NICHT "
            "verwenden — der Reset würde Download-Mode auslösen."
        ),
    )
    p.add_argument("--json", action="store_true", help="Maschinenlesbares JSON-Output")
    p.add_argument(
        "--cmd",
        action="append",
        default=[],
        metavar="LABEL=COMMAND",
        help="Zusätzlichen Befehl ausführen (mehrfach möglich), z.B. "
        "--cmd 'acl=get acl'",
    )
    args = p.parse_args()

    extra: list[tuple[str, str]] = []
    for entry in args.cmd:
        if "=" not in entry:
            print(f"--cmd erwartet LABEL=COMMAND, bekam: {entry!r}", file=sys.stderr)
            return 2
        label, _, command = entry.partition("=")
        extra.append((label.strip(), command.strip()))

    sequence = STATUS_COMMANDS + extra

    if not args.json:
        print(f"Verbinde zu {args.port} @ {args.baud} …", file=sys.stderr)
    try:
        s = serial.Serial(args.port, args.baud, timeout=0.4)
    except serial.SerialException as e:
        print(f"Serial-Fehler: {e}", file=sys.stderr)
        return 2

    try:
        if args.reset:
            s.setDTR(False)
            s.setRTS(True)
            time.sleep(0.1)
            s.setRTS(False)
            if not args.json:
                print("Reset getriggert; warte 4s auf Boot …", file=sys.stderr)
            time.sleep(4.0)
        else:
            time.sleep(0.3)
        s.reset_input_buffer()

        # Eine harmlose Leerzeile, damit eine evtl. halbe Eingabezeile
        # in der FW abgeschlossen wird, bevor wir starten.
        s.write(b"\r")
        time.sleep(0.1)
        s.reset_input_buffer()

        results: list[CommandResult] = []
        for label, cmd in sequence:
            try:
                r = run_command(s, cmd)
            except serial.SerialException as e:
                print(f"Serial-Abbruch: {e}", file=sys.stderr)
                return 2
            r.label = label
            results.append(r)
    finally:
        s.close()

    if args.json:
        return render_json(results)
    return render_human(results)


if __name__ == "__main__":
    sys.exit(main())
