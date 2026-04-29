"""Async SQLAlchemy engine + session management."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from meshcore_bridge.db.models import Base

_log = structlog.get_logger("db")
_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None

# Idempotente Spalten-Patches für Bestands-DBs, die mit ``create_all``
# vor der jeweiligen Spalte erstellt wurden. Reihenfolge: (Tabelle,
# Spalte, DDL-Snippet). Greift nur, wenn ``alembic_version`` fehlt
# (Legacy-DB) — sonst ist Alembic zuständig.
_COLUMN_PATCHES: tuple[tuple[str, str, str], ...] = (
    ("companion_contacts", "favorite", "BOOLEAN NOT NULL DEFAULT 0"),
    ("companion_contacts", "last_lat", "FLOAT NULL"),
    ("companion_contacts", "last_lon", "FLOAT NULL"),
    ("companion_contacts", "node_type", "INTEGER NULL"),
    ("companion_messages", "room_sender_pubkey", "BLOB NULL"),
)


async def init_engine(sqlite_path: Path) -> AsyncEngine:
    """Create the async engine, ensure parent dir exists, then bring the
    schema up to date.

    Drei DB-Zustände werden unterschieden:
    1. *frisch* (keine Tabellen)            → ``create_all`` + ``stamp head``
    2. *Legacy* (Tabellen, aber kein
       ``alembic_version``)                  → ``create_all`` + Spalten-Patches +
                                              ``ensure_fts5`` + ``stamp head``
    3. *Alembic-verwaltet* (``alembic_version``
       existiert)                            → ``upgrade head``

    Reihenfolge wichtig: bei Legacy-DBs müssen die Patches **vor** dem Stamp
    laufen, weil das Stamp die DB als „auf head" markiert — eine fehlende
    Spalte würde danach nicht mehr nachgepflegt.
    """
    global _engine, _sessionmaker

    sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    url = f"sqlite+aiosqlite:///{sqlite_path}"
    _engine = create_async_engine(url, echo=False, future=True)
    _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)

    # Phase 1: Schemastruktur in einer Transaktion bringen. Alembic
    # **darf nicht** innerhalb dieser Transaktion laufen — es öffnet
    # eine eigene Connection und SQLite würde dann „database is locked"
    # werfen. Daher merken wir uns hier nur die nötige Folge-Aktion.
    async with _engine.begin() as conn:
        action = await conn.run_sync(_phase1_apply_ddl)
    # Phase 2: Alembic in eigener (sync) Connection. Synchron ausführen
    # ist ok, weil der Server in diesem Punkt noch nicht hochgefahren ist.
    if action == "stamp":
        _alembic_stamp_head(sqlite_path)
    elif action == "upgrade":
        _alembic_upgrade_head(sqlite_path)
    return _engine


def _phase1_apply_ddl(sync_conn) -> str:  # type: ignore[no-untyped-def]
    """Idempotente DDL-Anwendung. Liefert die nötige Alembic-Folgeaktion
    zurück (``"stamp"`` für frisch/legacy, ``"upgrade"`` für bereits
    verwaltete DBs)."""
    insp = inspect(sync_conn)
    table_names = set(insp.get_table_names())
    has_alembic = "alembic_version" in table_names
    if has_alembic:
        # Alembic-verwaltete DB — kein create_all, keine DDL-Patches,
        # sonst Konflikt mit ausstehenden Migrations.
        return "upgrade"
    is_fresh = not table_names
    Base.metadata.create_all(sync_conn)
    if not is_fresh:
        _apply_column_patches(sync_conn)
    # FTS5-Virtual-Table wird von ``Base.metadata.create_all`` nicht
    # angelegt (FTS5 ist eine Migration in d7e2a9c1f4b8); idempotent.
    _ensure_fts5(sync_conn)
    return "stamp"


def _alembic_config(sqlite_path: Path):  # type: ignore[no-untyped-def]
    """Programmatic Alembic-Config — vermeidet die Suche nach alembic.ini.

    ``script_location`` muss aufs ``alembic/``-Verzeichnis mit ``env.py +
    versions/`` zeigen. Im Container liegt das unter
    ``/app/server/bridge/alembic`` (per ``COPY`` aus dem Repo); lokal beim
    Dev nutzen wir cwd-Heuristik. Override via ``MESHCORE_ALEMBIC_DIR``.
    """
    candidates: list[Path] = []
    env_override = os.environ.get("MESHCORE_ALEMBIC_DIR")
    if env_override:
        candidates.append(Path(env_override))
    candidates.extend(
        [
            Path("/app/server/bridge/alembic"),  # Image-Default
            Path.cwd() / "alembic",
            Path.cwd() / "server" / "bridge" / "alembic",
        ]
    )
    script_location: Path | None = None
    for c in candidates:
        if (c / "env.py").is_file():
            script_location = c
            break
    if script_location is None:
        raise FileNotFoundError(
            "alembic env.py not found in any candidate location: "
            f"{[str(c) for c in candidates]} — set MESHCORE_ALEMBIC_DIR"
        )
    cfg = Config()
    cfg.set_main_option("script_location", str(script_location))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{sqlite_path}")
    return cfg


def _alembic_stamp_head(sqlite_path: Path) -> None:
    try:
        cfg = _alembic_config(sqlite_path)
    except FileNotFoundError as e:
        _log.warning("alembic_stamp_skipped", reason=str(e))
        return
    _log.info("alembic_stamp_head")
    command.stamp(cfg, "head")


def _alembic_upgrade_head(sqlite_path: Path) -> None:
    try:
        cfg = _alembic_config(sqlite_path)
    except FileNotFoundError as e:
        _log.warning("alembic_upgrade_skipped", reason=str(e))
        return
    _log.info("alembic_upgrade_head")
    command.upgrade(cfg, "head")


def _apply_column_patches(sync_conn) -> None:  # type: ignore[no-untyped-def]
    insp = inspect(sync_conn)
    existing_tables = set(insp.get_table_names())
    for table, column, ddl in _COLUMN_PATCHES:
        if table not in existing_tables:
            continue
        cols = {c["name"] for c in insp.get_columns(table)}
        if column in cols:
            continue
        _log.info("db_column_patch", table=table, column=column)
        sync_conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))


_FTS5_TABLE = "companion_messages_fts"


def _ensure_fts5(sync_conn) -> None:  # type: ignore[no-untyped-def]
    """Idempotent: legt die FTS5-Virtual-Tabelle + Sync-Trigger an, wenn
    sie noch nicht existiert. Wird auch bei alten DBs aufgerufen, die
    create_all/Migration-frei aufgewachsen sind. Backfill befüllt aus
    companion_messages."""
    existing = sync_conn.execute(
        text("SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name = :n"),
        {"n": _FTS5_TABLE},
    ).scalar_one_or_none()
    if existing:
        return
    _log.info("db_fts5_init", table=_FTS5_TABLE)
    sync_conn.execute(
        text(
            f"""
            CREATE VIRTUAL TABLE {_FTS5_TABLE} USING fts5(
              text,
              msg_id UNINDEXED,
              identity_id UNINDEXED,
              peer_pubkey UNINDEXED,
              peer_name UNINDEXED,
              channel_name UNINDEXED,
              ts UNINDEXED,
              direction UNINDEXED,
              tokenize='unicode61 remove_diacritics 2'
            )
            """
        )
    )
    sync_conn.execute(
        text(
            f"""
            INSERT INTO {_FTS5_TABLE}(
              text, msg_id, identity_id, peer_pubkey, peer_name,
              channel_name, ts, direction
            )
            SELECT COALESCE(text, ''), id, identity_id, peer_pubkey, peer_name,
                   channel_name, ts, direction
            FROM companion_messages
            """
        )
    )
    sync_conn.execute(
        text(
            f"""
            CREATE TRIGGER companion_messages_ai AFTER INSERT ON companion_messages BEGIN
              INSERT INTO {_FTS5_TABLE}(
                text, msg_id, identity_id, peer_pubkey, peer_name,
                channel_name, ts, direction
              ) VALUES (
                COALESCE(new.text, ''), new.id, new.identity_id, new.peer_pubkey,
                new.peer_name, new.channel_name, new.ts, new.direction
              );
            END
            """
        )
    )
    sync_conn.execute(
        text(
            f"""
            CREATE TRIGGER companion_messages_ad AFTER DELETE ON companion_messages BEGIN
              DELETE FROM {_FTS5_TABLE} WHERE msg_id = old.id;
            END
            """
        )
    )
    sync_conn.execute(
        text(
            f"""
            CREATE TRIGGER companion_messages_au AFTER UPDATE ON companion_messages BEGIN
              DELETE FROM {_FTS5_TABLE} WHERE msg_id = old.id;
              INSERT INTO {_FTS5_TABLE}(
                text, msg_id, identity_id, peer_pubkey, peer_name,
                channel_name, ts, direction
              ) VALUES (
                COALESCE(new.text, ''), new.id, new.identity_id, new.peer_pubkey,
                new.peer_name, new.channel_name, new.ts, new.direction
              );
            END
            """
        )
    )


async def close_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None


@asynccontextmanager
async def get_session() -> AsyncIterator[AsyncSession]:
    if _sessionmaker is None:
        raise RuntimeError("DB not initialized — call init_engine() first")
    async with _sessionmaker() as session:
        yield session
