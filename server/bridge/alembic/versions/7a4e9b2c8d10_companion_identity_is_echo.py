"""companion identity is_echo flag

Revision ID: 7a4e9b2c8d10
Revises: f1a2b3c4d5e6
Create Date: 2026-04-29
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "7a4e9b2c8d10"
down_revision: str | None = "f1a2b3c4d5e6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("companion_identities") as batch:
        batch.add_column(
            sa.Column(
                "is_echo",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("0"),
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("companion_identities") as batch:
        batch.drop_column("is_echo")
