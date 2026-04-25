"""Entry-Point für `python -m meshcore_bridge`.

Phase 0: Platzhalter. Phase 1 implementiert hier den asyncio-Loop
mit WebSocket-Server, FastAPI-App und (per In-Process-API) dem
Companion-Service.
"""

from __future__ import annotations

import sys


def main() -> int:
    print("meshcore_bridge: Phase 0 skeleton — not yet implemented", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
