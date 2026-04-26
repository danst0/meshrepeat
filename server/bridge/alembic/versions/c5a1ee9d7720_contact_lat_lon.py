"""contact lat/lon from advert

Revision ID: c5a1ee9d7720
Revises: 8c1a4e2d9f3b
Create Date: 2026-04-26
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c5a1ee9d7720"
down_revision: str | None = "8c1a4e2d9f3b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("companion_contacts") as batch:
        batch.add_column(sa.Column("last_lat", sa.Float(), nullable=True))
        batch.add_column(sa.Column("last_lon", sa.Float(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("companion_contacts") as batch:
        batch.drop_column("last_lon")
        batch.drop_column("last_lat")
