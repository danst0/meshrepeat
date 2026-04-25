"""companion channels

Revision ID: 4a3d9b1f7e02
Revises: 21ecfd228766
Create Date: 2026-04-25
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from meshcore_bridge.db.models import _UUIDBlob

revision: str = "4a3d9b1f7e02"
down_revision: str | None = "21ecfd228766"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "companion_channels",
        sa.Column("id", _UUIDBlob(), nullable=False),
        sa.Column("identity_id", _UUIDBlob(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("secret", sa.BLOB(), nullable=False),
        sa.Column("channel_hash", sa.BLOB(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["identity_id"], ["companion_identities.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("identity_id", "name", name="uq_companion_channel_name"),
    )
    op.create_index(
        "ix_companion_channels_identity",
        "companion_channels",
        ["identity_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_companion_channels_identity", table_name="companion_channels")
    op.drop_table("companion_channels")
