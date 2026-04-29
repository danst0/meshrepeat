"""Auto-Migration beim ``init_engine``-Start.

Drei DB-Zustände werden hier abgesichert:
* frisch (leer)
* Legacy (ohne ``alembic_version``, evtl. ohne neuere Spalten)
* Alembic-verwaltet (an alter Revision)
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from meshcore_bridge.db.session import close_engine, init_engine


@pytest.mark.asyncio
async def test_fresh_db_creates_tables_and_stamps_head(tmp_path: Path) -> None:
    db = tmp_path / "fresh.sqlite"
    await init_engine(db)
    await close_engine()
    with sqlite3.connect(db) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "companion_contacts" in tables
        assert "companion_messages" in tables
        assert "alembic_version" in tables
        head = conn.execute("SELECT version_num FROM alembic_version").fetchone()[0]
        assert head == "f1a2b3c4d5e6"
        cols = {r[1] for r in conn.execute("PRAGMA table_info(companion_contacts)")}
        assert "node_type" in cols
        msg_cols = {r[1] for r in conn.execute("PRAGMA table_info(companion_messages)")}
        assert "room_sender_pubkey" in msg_cols


@pytest.mark.asyncio
async def test_legacy_db_gets_patched_and_stamped(tmp_path: Path) -> None:
    """DB ist auf einer früheren Schemastufe (vor unserer Room-Migration),
    aber ohne ``alembic_version``-Tabelle — so wie Prod-DBs vor v0.2.0
    aussehen, weil die App bislang per ``create_all`` aufgewachsen ist.

    Reproduziert über alembic upgrade bis vor head, dann ``alembic_version``
    droppen — so haben wir eine realistische Schemastruktur mit FTS5 etc.,
    nur eben nicht die neue ``node_type``/``room_sender_pubkey``-Spalte."""
    from alembic import command

    from meshcore_bridge.db.session import _alembic_config

    db = tmp_path / "legacy.sqlite"
    cfg = _alembic_config(db)
    command.upgrade(cfg, "d7e2a9c1f4b8")  # Revision direkt vor head
    # Verwaltung wegnehmen → sieht aus wie eine ungemanagte Legacy-DB.
    with sqlite3.connect(db) as conn:
        conn.execute("DROP TABLE alembic_version")
        cols = {r[1] for r in conn.execute("PRAGMA table_info(companion_contacts)")}
        assert "node_type" not in cols  # Vorbedingung

    await init_engine(db)
    await close_engine()

    with sqlite3.connect(db) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(companion_contacts)")}
        assert "node_type" in cols  # via _apply_column_patches nachgezogen
        assert "favorite" in cols
        msg_cols = {r[1] for r in conn.execute("PRAGMA table_info(companion_messages)")}
        assert "room_sender_pubkey" in msg_cols
        head = conn.execute("SELECT version_num FROM alembic_version").fetchone()[0]
        assert head == "f1a2b3c4d5e6"


@pytest.mark.asyncio
async def test_alembic_managed_db_runs_upgrade(tmp_path: Path) -> None:
    """DB an älterer Revision (vor unserer Room-Migration) — init_engine
    soll auf head upgraden, ohne create_all-Konflikt."""
    from alembic import command

    from meshcore_bridge.db.session import _alembic_config

    db = tmp_path / "managed.sqlite"
    # Wir erzeugen die DB sauber per alembic upgrade bis zur
    # vor-letzten Revision.
    cfg = _alembic_config(db)
    command.upgrade(cfg, "d7e2a9c1f4b8")  # eine Revision vor head
    with sqlite3.connect(db) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(companion_contacts)")}
        assert "node_type" not in cols  # Vorbedingung: noch nicht da

    await init_engine(db)
    await close_engine()

    with sqlite3.connect(db) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(companion_contacts)")}
        assert "node_type" in cols  # nach upgrade: da
        head = conn.execute("SELECT version_num FROM alembic_version").fetchone()[0]
        assert head == "f1a2b3c4d5e6"
