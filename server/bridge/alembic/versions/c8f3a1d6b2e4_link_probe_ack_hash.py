"""link_probes: ack_hash-Spalte für DM-Probes, req_tag nullable

Hintergrund: STATUS-REQ-basierte Probes scheiterten am Login-Erfordernis
der Repeater-FW (Sender muss in ACL). DM-basierte Probes funktionieren
ohne Login (jede DM erzeugt einen ACK). Korrelations-Key wechselt von
``req_tag`` (Tag-Word des REQ) auf ``ack_hash`` (sha256[:4] aus
DM-Plaintext + sender_pubkey).

Revision ID: c8f3a1d6b2e4
Revises: b4e7d2c9f1a3
Create Date: 2026-05-01
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c8f3a1d6b2e4"
down_revision: str | None = "b4e7d2c9f1a3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_index("ix_companion_link_probes_tag", table_name="companion_link_probes")
    with op.batch_alter_table("companion_link_probes") as batch:
        batch.add_column(sa.Column("ack_hash", sa.LargeBinary(), nullable=True))
        batch.alter_column("req_tag", existing_type=sa.Integer(), nullable=True)
    op.create_index(
        "ix_companion_link_probes_ack_hash",
        "companion_link_probes",
        ["ack_hash"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_companion_link_probes_ack_hash", table_name="companion_link_probes"
    )
    with op.batch_alter_table("companion_link_probes") as batch:
        batch.alter_column("req_tag", existing_type=sa.Integer(), nullable=False)
        batch.drop_column("ack_hash")
    op.create_index(
        "ix_companion_link_probes_tag",
        "companion_link_probes",
        ["req_tag"],
    )
