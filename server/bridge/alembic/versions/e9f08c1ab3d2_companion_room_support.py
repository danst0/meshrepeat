"""companion room support: contact node_type + message room_sender_pubkey

Revision ID: e9f08c1ab3d2
Revises: d7e2a9c1f4b8
Create Date: 2026-04-28

``companion_contacts.node_type`` speichert ADV_TYPE aus dem Advert
(1=Chat, 2=Repeater, 3=Room, 4=Sensor; NULL = bisher nicht beobachtet).

``companion_messages.room_sender_pubkey`` enthält bei Room-Push-Inbound die
ersten 4 Bytes des Original-Senders (im TXT_TYPE_SIGNED_PLAIN-Plaintext
zwischen flags und text). Bei DMs/Channel-Posts NULL.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e9f08c1ab3d2"
down_revision: str | None = "d7e2a9c1f4b8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("companion_contacts") as batch:
        batch.add_column(sa.Column("node_type", sa.Integer(), nullable=True))
    with op.batch_alter_table("companion_messages") as batch:
        batch.add_column(sa.Column("room_sender_pubkey", sa.BLOB(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("companion_messages") as batch:
        batch.drop_column("room_sender_pubkey")
    with op.batch_alter_table("companion_contacts") as batch:
        batch.drop_column("node_type")
