"""companion_link_probes (DM-/REQ-Probe-Ergebnisse)

Revision ID: b4e7d2c9f1a3
Revises: 9b2f8e1c4a7d
Create Date: 2026-05-01
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b4e7d2c9f1a3"
down_revision: str | None = "9b2f8e1c4a7d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "companion_link_probes",
        sa.Column("id", sa.LargeBinary(length=16), primary_key=True),
        sa.Column(
            "identity_id",
            sa.LargeBinary(length=16),
            sa.ForeignKey("companion_identities.id"),
            nullable=False,
        ),
        sa.Column("peer_pubkey", sa.LargeBinary(), nullable=False),
        sa.Column(
            "sent_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("req_tag", sa.Integer(), nullable=False),
        sa.Column("route_kind", sa.String(length=8), nullable=False),
        sa.Column("hop_count", sa.Integer(), nullable=True),
        sa.Column(
            "status",
            sa.String(length=16),
            nullable=False,
            server_default=sa.text("'pending'"),
        ),
        sa.Column("rtt_ms", sa.Integer(), nullable=True),
        sa.Column("answered_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_companion_link_probes_pair_time",
        "companion_link_probes",
        ["identity_id", "peer_pubkey", "sent_at"],
    )
    op.create_index(
        "ix_companion_link_probes_tag",
        "companion_link_probes",
        ["req_tag"],
    )


def downgrade() -> None:
    op.drop_index("ix_companion_link_probes_tag", table_name="companion_link_probes")
    op.drop_index("ix_companion_link_probes_pair_time", table_name="companion_link_probes")
    op.drop_table("companion_link_probes")
