"""Entry-Point für ``python -m meshcore_bridge``."""

from __future__ import annotations

import sys

import uvicorn

from meshcore_bridge.config import AppConfig
from meshcore_bridge.log import configure as configure_logging
from meshcore_bridge.web import build_app


def main() -> int:
    cfg = AppConfig.load()
    configure_logging(level=cfg.logging.level, fmt=cfg.logging.format)
    app = build_app(cfg)
    uvicorn.run(
        app,
        host=cfg.server.host,
        port=cfg.server.port,
        log_config=None,
        access_log=False,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
