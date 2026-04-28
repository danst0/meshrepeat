"""raw_packets table for the wireshark-style packet inspector

Revision ID: f1a2b3c4d5e6
Revises: e9f08c1ab3d2
Create Date: 2026-04-28

Persistiert eingehende LoRa-Frames (Header + Path + Payload als rohe Bytes)
plus dekodierte Header-Felder. Befüllt vom Packet-Spool-Worker; Retention
7 Tage. Wird von ``/admin/inspector`` gelesen.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f1a2b3c4d5e6"
down_revision: str | None = "e9f08c1ab3d2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "raw_packets",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "ts",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("site_id", sa.BLOB(), nullable=False),
        sa.Column("site_name", sa.String(64), nullable=True),
        sa.Column("scope", sa.String(64), nullable=False),
        sa.Column("route_type", sa.String(24), nullable=False),
        sa.Column("payload_type", sa.String(24), nullable=False),
        sa.Column("raw", sa.BLOB(), nullable=False),
        sa.Column("path_hashes", sa.String(), nullable=False, server_default=""),
        sa.Column("advert_pubkey", sa.String(64), nullable=True),
        sa.Column("forwarded_to", sa.String(), nullable=False, server_default="[]"),
        sa.Column("dropped_reason", sa.String(64), nullable=True),
    )
    op.create_index(
        "ix_raw_packets_site_ts", "raw_packets", ["site_id", "ts"]
    )
    op.create_index("ix_raw_packets_ts", "raw_packets", ["ts"])


def downgrade() -> None:
    op.drop_index("ix_raw_packets_ts", table_name="raw_packets")
    op.drop_index("ix_raw_packets_site_ts", table_name="raw_packets")
    op.drop_table("raw_packets")
