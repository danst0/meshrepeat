"""Async SQLAlchemy engine + session management."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
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
# Spalte, DDL-Snippet). Bis Alembic-Migrations beim Start laufen.
_COLUMN_PATCHES: tuple[tuple[str, str, str], ...] = (
    ("companion_contacts", "favorite", "BOOLEAN NOT NULL DEFAULT 0"),
    ("companion_contacts", "last_lat", "FLOAT NULL"),
    ("companion_contacts", "last_lon", "FLOAT NULL"),
)


async def init_engine(sqlite_path: Path) -> AsyncEngine:
    """Create the async engine, ensure parent dir exists, run create_all,
    apply idempotente Spalten-Patches für Bestands-DBs.
    """
    global _engine, _sessionmaker

    sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    url = f"sqlite+aiosqlite:///{sqlite_path}"
    _engine = create_async_engine(url, echo=False, future=True)
    _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)

    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_apply_column_patches)
        await conn.run_sync(_ensure_fts5)
    return _engine


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
        text(
            "SELECT name FROM sqlite_master WHERE type IN ('table','view') "
            "AND name = :n"
        ),
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
