"""Fixtures für Playwright-basierte UI-Tests.

Nicht im Default-pytest-Lauf — nur via ``pytest -m ui tests/ui/``.
Voraussetzung: ``pip install -e ".[ui-test]" && playwright install
--with-deps chromium``.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from secrets import token_hex
from urllib.request import urlopen

import pytest

# pytest-playwright Plugin ist optional — wenn fehlend, skipt das Modul.
playwright = pytest.importorskip("playwright.sync_api")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def live_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """Startet uvicorn in einem Subprozess gegen eine isolierte SQLite-DB.
    Yields die Base-URL."""
    work = tmp_path_factory.mktemp("uitest")
    db_path = work / "ui.sqlite"
    db_key = work / "db_key"
    db_key.write_text(token_hex(32))

    port = _free_port()
    url = f"http://127.0.0.1:{port}"

    env = os.environ.copy()
    env.update(
        {
            "MESHCORE_DB_PATH": str(db_path),
            "MESHCORE_DB_KEY_FILE": str(db_key),
            "MESHCORE_LOG_LEVEL": "WARNING",
            "MESHCORE_WEB__BASE_URL": url,
            "MESHCORE_WEB__SIGNUP__REQUIRE_EMAIL_VERIFICATION": "false",
        }
    )

    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "meshcore_bridge.web:build_app",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        env=env,
        cwd=Path(__file__).resolve().parents[3],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                if urlopen(f"{url}/healthz", timeout=1).status == 200:
                    break
            except OSError:
                time.sleep(0.25)
        else:
            proc.terminate()
            raise RuntimeError("live_server did not become healthy")
        yield url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
