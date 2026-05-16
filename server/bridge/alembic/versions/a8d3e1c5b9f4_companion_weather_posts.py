"""companion_weather_posts

Neue Tabelle für den HA-getriebenen Wetter-Auto-Post pro Identity.
Pro Eintrag: identity_id + channel_id + ha_entity_id + interval_s +
optional location_label + enabled-Flag + last_posted_at. Der
CompanionService-Loop iteriert ``enabled``-Rows, prüft Fälligkeit und
postet via ``send_channel``.

Revision ID: a8d3e1c5b9f4
Revises: c7f4a9e3b6d2
Create Date: 2026-05-16
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a8d3e1c5b9f4"
down_revision: str | None = "c7f4a9e3b6d2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "companion_weather_posts",
        sa.Column("id", sa.BLOB(), primary_key=True),
        sa.Column(
            "identity_id",
            sa.BLOB(),
            sa.ForeignKey("companion_identities.id"),
            nullable=False,
        ),
        sa.Column(
            "channel_id",
            sa.BLOB(),
            sa.ForeignKey("companion_channels.id"),
            nullable=False,
        ),
        sa.Column("ha_entity_id", sa.String(length=128), nullable=False),
        sa.Column("interval_s", sa.Integer(), nullable=False, server_default="21600"),
        sa.Column("location_label", sa.String(length=64), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("last_posted_at", sa.DateTime(timezone=True), nullable=True),
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
    )
    op.create_index(
        "ix_companion_weather_posts_identity",
        "companion_weather_posts",
        ["identity_id"],
    )
    op.create_index(
        "ix_companion_weather_posts_due",
        "companion_weather_posts",
        ["enabled", "last_posted_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_companion_weather_posts_due", table_name="companion_weather_posts")
    op.drop_index("ix_companion_weather_posts_identity", table_name="companion_weather_posts")
    op.drop_table("companion_weather_posts")
