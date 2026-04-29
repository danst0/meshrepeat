"""contact out_path cache

Revision ID: 9b2f8e1c4a7d
Revises: 7a4e9b2c8d10
Create Date: 2026-04-29
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "9b2f8e1c4a7d"
down_revision: str | None = "7a4e9b2c8d10"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("companion_contacts") as batch:
        batch.add_column(sa.Column("out_path", sa.LargeBinary(), nullable=True))
        batch.add_column(
            sa.Column("out_path_updated_at", sa.DateTime(timezone=True), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("companion_contacts") as batch:
        batch.drop_column("out_path_updated_at")
        batch.drop_column("out_path")
