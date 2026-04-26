"""contact favorite flag

Revision ID: 8c1a4e2d9f3b
Revises: 4a3d9b1f7e02
Create Date: 2026-04-25
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "8c1a4e2d9f3b"
down_revision: str | None = "4a3d9b1f7e02"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("companion_contacts") as batch:
        batch.add_column(
            sa.Column(
                "favorite",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("0"),
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("companion_contacts") as batch:
        batch.drop_column("favorite")
