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
        assert head == "e4b8d5c2f1a9"
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
        assert head == "e4b8d5c2f1a9"


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
        assert head == "e4b8d5c2f1a9"


@pytest.mark.asyncio
async def test_sigil_strip_migration_renames_existing_channels(tmp_path: Path) -> None:
    """e4b8d5c2f1a9 normalisiert in v0.4.6 angelegte ``#bonn``-Einträge zu
    ``bonn`` (Channel-Tabelle und Message-Refs)."""
    import uuid

    from alembic import command

    from meshcore_bridge.db.session import _alembic_config

    db = tmp_path / "presigil.sqlite"
    cfg = _alembic_config(db)
    command.upgrade(cfg, "d3a8c4b1e9f5")  # Stand v0.4.6, vor Sigil-Strip

    user_id = uuid.uuid4().bytes
    ident_id = uuid.uuid4().bytes
    ch_id = uuid.uuid4().bytes
    msg_id = uuid.uuid4().bytes
    with sqlite3.connect(db) as conn:
        conn.execute(
            "INSERT INTO users (id, email, password_hash, role, created_at) "
            "VALUES (?, 'u@u', 'x', 'owner', '2026-05-10 00:00:00')",
            (user_id,),
        )
        conn.execute(
            "INSERT INTO companion_identities (id, user_id, name, pubkey, "
            "privkey_enc, scope, created_at) VALUES (?, ?, 'A', X'00', "
            "X'00', 'public', '2026-05-10 00:00:00')",
            (ident_id, user_id),
        )
        conn.execute(
            "INSERT INTO companion_channels (id, identity_id, name, secret, "
            "channel_hash, favorite, created_at) VALUES (?, ?, '#bonn', "
            "X'00', X'00', 0, '2026-05-10 00:00:00')",
            (ch_id, ident_id),
        )
        conn.execute(
            "INSERT INTO companion_messages (id, identity_id, ts, direction, "
            "payload_type, raw, channel_name, text) VALUES (?, ?, "
            "'2026-05-10 00:00:00', 'in', 2, X'00', '#bonn', 'hi')",
            (msg_id, ident_id),
        )
        conn.commit()

    await init_engine(db)
    await close_engine()

    with sqlite3.connect(db) as conn:
        ch_name = conn.execute(
            "SELECT name FROM companion_channels WHERE id = ?", (ch_id,)
        ).fetchone()[0]
        msg_name = conn.execute(
            "SELECT channel_name FROM companion_messages WHERE id = ?", (msg_id,)
        ).fetchone()[0]
        head = conn.execute("SELECT version_num FROM alembic_version").fetchone()[0]
    assert ch_name == "bonn"
    assert msg_name == "bonn"
    assert head == "e4b8d5c2f1a9"


@pytest.mark.asyncio
async def test_sigil_strip_migration_handles_collision(tmp_path: Path) -> None:
    """Wenn neben ``#bonn`` (auto-seed) bereits ein User-Channel ``bonn``
    existiert, würde das blinde Rename den UNIQUE-Constraint sprengen.
    Die Migration löscht dann den auto-seed-Eintrag."""
    import uuid

    from alembic import command

    from meshcore_bridge.db.session import _alembic_config

    db = tmp_path / "collide.sqlite"
    cfg = _alembic_config(db)
    command.upgrade(cfg, "d3a8c4b1e9f5")

    user_id = uuid.uuid4().bytes
    ident_id = uuid.uuid4().bytes
    auto_id = uuid.uuid4().bytes
    user_ch_id = uuid.uuid4().bytes
    with sqlite3.connect(db) as conn:
        conn.execute(
            "INSERT INTO users (id, email, password_hash, role, created_at) "
            "VALUES (?, 'u@u', 'x', 'owner', '2026-05-10 00:00:00')",
            (user_id,),
        )
        conn.execute(
            "INSERT INTO companion_identities (id, user_id, name, pubkey, "
            "privkey_enc, scope, created_at) VALUES (?, ?, 'A', X'00', "
            "X'00', 'public', '2026-05-10 00:00:00')",
            (ident_id, user_id),
        )
        conn.execute(
            "INSERT INTO companion_channels (id, identity_id, name, secret, "
            "channel_hash, favorite, created_at) VALUES (?, ?, '#bonn', "
            "X'00', X'00', 0, '2026-05-10 00:00:00')",
            (auto_id, ident_id),
        )
        conn.execute(
            "INSERT INTO companion_channels (id, identity_id, name, secret, "
            "channel_hash, favorite, created_at) VALUES (?, ?, 'bonn', "
            "X'01', X'01', 1, '2026-05-10 00:00:00')",
            (user_ch_id, ident_id),
        )
        conn.commit()

    await init_engine(db)
    await close_engine()

    with sqlite3.connect(db) as conn:
        rows = conn.execute(
            "SELECT id, name FROM companion_channels WHERE identity_id = ? "
            "ORDER BY name",
            (ident_id,),
        ).fetchall()
    # Auto-Seed-Eintrag entfernt, User-Channel bleibt unverändert.
    assert len(rows) == 1
    assert rows[0][0] == user_ch_id
    assert rows[0][1] == "bonn"
