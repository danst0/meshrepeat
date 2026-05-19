"""companion ai agent table

1:1 zu ``companion_identities``: optionaler KI-Agent pro Identity, der den
Public-Channel mitliest (mit Jitter postet) sowie auf direkte Erwähnungen
und eingehende DMs reagiert. LLM-Backend ist das ohnehin schon
eingebundene Ollama (vgl. ``meshcore_companion.translator``).

Revision ID: c9a1f4e3d7b2
Revises: b3c7e9d2f5a1
Create Date: 2026-05-19
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c9a1f4e3d7b2"
down_revision: str | None = "b3c7e9d2f5a1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "companion_ai_agents",
        sa.Column("identity_id", sa.BLOB(), nullable=False),
        sa.Column(
            "enabled",
            sa.Boolean(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "system_prompt",
            sa.String(),
            server_default="",
            nullable=False,
        ),
        sa.Column(
            "interval_s",
            sa.Integer(),
            server_default=sa.text("14400"),
            nullable=False,
        ),
        sa.Column("channel_id", sa.BLOB(), nullable=True),
        sa.Column(
            "respond_on_mention",
            sa.Boolean(),
            server_default=sa.text("1"),
            nullable=False,
        ),
        sa.Column(
            "respond_to_dms",
            sa.Boolean(),
            server_default=sa.text("1"),
            nullable=False,
        ),
        sa.Column(
            "dm_rate_per_hour",
            sa.Integer(),
            server_default=sa.text("6"),
            nullable=False,
        ),
        sa.Column(
            "dm_min_delay_s",
            sa.Integer(),
            server_default=sa.text("10"),
            nullable=False,
        ),
        sa.Column(
            "dm_max_delay_s",
            sa.Integer(),
            server_default=sa.text("60"),
            nullable=False,
        ),
        sa.Column(
            "blocked_peer_names",
            sa.String(),
            server_default="",
            nullable=False,
        ),
        sa.Column(
            "ollama_model",
            sa.String(length=128),
            server_default="llama3.1:8b",
            nullable=False,
        ),
        sa.Column(
            "lookback_minutes",
            sa.Integer(),
            server_default=sa.text("60"),
            nullable=False,
        ),
        sa.Column("last_post_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_post_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["identity_id"],
            ["companion_identities.id"],
        ),
        sa.ForeignKeyConstraint(
            ["channel_id"],
            ["companion_channels.id"],
        ),
        sa.PrimaryKeyConstraint("identity_id"),
    )
    op.create_index(
        "ix_companion_ai_agents_due",
        "companion_ai_agents",
        ["enabled", "next_post_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_companion_ai_agents_due",
        table_name="companion_ai_agents",
    )
    op.drop_table("companion_ai_agents")
