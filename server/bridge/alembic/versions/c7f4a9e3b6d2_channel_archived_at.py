"""companion_channels.archived_at

Erlaubt, einen Kanal aus der Sidebar zu verbannen, ohne Secret/Hash zu
verlieren. Kein Auto-Unarchive bei eingehenden Channel-Posts (anders als
bei DMs) — der Sinn des Archivierens ist gerade, einen lauten Channel
auszublenden. Restore über den Settings-Tab.

Revision ID: c7f4a9e3b6d2
Revises: b6e3d4f8a2c1
Create Date: 2026-05-16
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c7f4a9e3b6d2"
down_revision: str | None = "b6e3d4f8a2c1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("companion_channels") as batch:
        batch.add_column(sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("companion_channels") as batch:
        batch.drop_column("archived_at")
