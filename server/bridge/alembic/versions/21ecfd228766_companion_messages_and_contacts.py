"""companion messages and contacts

Revision ID: 21ecfd228766
Revises: 91d1ec6c049a
Create Date: 2026-04-25
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from meshcore_bridge.db.models import _UUIDBlob

revision: str = "21ecfd228766"
down_revision: str | None = "91d1ec6c049a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "companion_contacts",
        sa.Column("id", _UUIDBlob(), nullable=False),
        sa.Column("identity_id", _UUIDBlob(), nullable=False),
        sa.Column("peer_pubkey", sa.BLOB(), nullable=False),
        sa.Column("peer_name", sa.String(length=64), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["identity_id"], ["companion_identities.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("identity_id", "peer_pubkey", name="uq_companion_contact_pair"),
    )
    op.create_index(
        "ix_companion_contacts_identity", "companion_contacts", ["identity_id"], unique=False
    )

    op.create_table(
        "companion_messages",
        sa.Column("id", _UUIDBlob(), nullable=False),
        sa.Column("identity_id", _UUIDBlob(), nullable=False),
        sa.Column("direction", sa.String(length=8), nullable=False),
        sa.Column("payload_type", sa.Integer(), nullable=False),
        sa.Column("peer_pubkey", sa.BLOB(), nullable=True),
        sa.Column("peer_name", sa.String(length=64), nullable=True),
        sa.Column("channel_name", sa.String(length=64), nullable=True),
        sa.Column("text", sa.String(), nullable=True),
        sa.Column("raw", sa.BLOB(), nullable=False),
        sa.Column(
            "ts",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["identity_id"], ["companion_identities.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_companion_messages_identity_ts",
        "companion_messages",
        ["identity_id", "ts"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_companion_messages_identity_ts", table_name="companion_messages")
    op.drop_table("companion_messages")
    op.drop_index("ix_companion_contacts_identity", table_name="companion_contacts")
    op.drop_table("companion_contacts")
