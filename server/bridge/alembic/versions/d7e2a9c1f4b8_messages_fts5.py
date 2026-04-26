"""companion_messages full-text-search via FTS5

Revision ID: d7e2a9c1f4b8
Revises: c5a1ee9d7720
Create Date: 2026-04-26

Contentless FTS5-Tabelle ``companion_messages_fts``: text + UNINDEXED-
Metadaten (msg_id, identity_id, peer_pubkey, channel_name, peer_name, ts,
direction). companion_messages.id ist UUID-BLOB, daher kein
external-content (FTS5 erwartet INTEGER content_rowid).

Tokenizer ``unicode61 remove_diacritics 2`` matcht "tach" auch in "Tach!"
und macht ä/ö/ü unempfindlich. Backfill ist idempotent.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "d7e2a9c1f4b8"
down_revision: str | None = "c5a1ee9d7720"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE VIRTUAL TABLE companion_messages_fts USING fts5(
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
    op.execute(
        """
        INSERT INTO companion_messages_fts(
          text, msg_id, identity_id, peer_pubkey, peer_name,
          channel_name, ts, direction
        )
        SELECT COALESCE(text, ''), id, identity_id, peer_pubkey, peer_name,
               channel_name, ts, direction
        FROM companion_messages
        """
    )
    op.execute(
        """
        CREATE TRIGGER companion_messages_ai AFTER INSERT ON companion_messages BEGIN
          INSERT INTO companion_messages_fts(
            text, msg_id, identity_id, peer_pubkey, peer_name,
            channel_name, ts, direction
          ) VALUES (
            COALESCE(new.text, ''), new.id, new.identity_id, new.peer_pubkey,
            new.peer_name, new.channel_name, new.ts, new.direction
          );
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER companion_messages_ad AFTER DELETE ON companion_messages BEGIN
          DELETE FROM companion_messages_fts WHERE msg_id = old.id;
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER companion_messages_au AFTER UPDATE ON companion_messages BEGIN
          DELETE FROM companion_messages_fts WHERE msg_id = old.id;
          INSERT INTO companion_messages_fts(
            text, msg_id, identity_id, peer_pubkey, peer_name,
            channel_name, ts, direction
          ) VALUES (
            COALESCE(new.text, ''), new.id, new.identity_id, new.peer_pubkey,
            new.peer_name, new.channel_name, new.ts, new.direction
          );
        END
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS companion_messages_au")
    op.execute("DROP TRIGGER IF EXISTS companion_messages_ad")
    op.execute("DROP TRIGGER IF EXISTS companion_messages_ai")
    op.execute("DROP TABLE IF EXISTS companion_messages_fts")
