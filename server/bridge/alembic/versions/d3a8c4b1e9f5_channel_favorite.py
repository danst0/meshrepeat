"""companion_channels.favorite

Markiert Kanäle als Favorit für die UI-Sortierung. Der Public-Channel
wird beim Erst-Setup einer Identity auf ``favorite=1`` gesetzt; alle
anderen (auch die voreingestellten Hash-Channels) sind per Default
nicht favorisiert und können vom User manuell markiert werden.

Revision ID: d3a8c4b1e9f5
Revises: a7b2e9f4c1d3
Create Date: 2026-05-10
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d3a8c4b1e9f5"
down_revision: str | None = "a7b2e9f4c1d3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("companion_channels") as batch:
        batch.add_column(
            sa.Column(
                "favorite",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("0"),
            )
        )
    # Bestehender Public-Channel ist nach Migration favorisiert.
    op.execute("UPDATE companion_channels SET favorite = 1 WHERE name = 'public'")


def downgrade() -> None:
    with op.batch_alter_table("companion_channels") as batch:
        batch.drop_column("favorite")
