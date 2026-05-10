"""companion identity path_hash_mode

Hinzugefügt zu ``companion_identities`` als 0/1/2-Modus für die
hash_size in den ausgehenden Paketen einer Identity (DM, GRP_TXT,
eigene Adverts). Konvention identisch zum firmware-CLI ``path.hash.mode``:
0 → 1 Byte (default), 1 → 2 Byte, 2 → 3 Byte.

Revision ID: f5c1d8a3b2e7
Revises: e4b8d5c2f1a9
Create Date: 2026-05-10
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f5c1d8a3b2e7"
down_revision: str | None = "e4b8d5c2f1a9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("companion_identities") as batch:
        batch.add_column(
            sa.Column(
                "path_hash_mode",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("0"),
            )
        )
        batch.create_check_constraint(
            "ck_companion_identity_path_hash_mode",
            "path_hash_mode IN (0, 1, 2)",
        )


def downgrade() -> None:
    with op.batch_alter_table("companion_identities") as batch:
        batch.drop_constraint(
            "ck_companion_identity_path_hash_mode", type_="check"
        )
        batch.drop_column("path_hash_mode")
