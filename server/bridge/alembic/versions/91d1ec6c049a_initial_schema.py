"""initial schema

Revision ID: 91d1ec6c049a
Revises:
Create Date: 2026-04-25
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from meshcore_bridge.db.models import _UUIDBlob

revision: str = "91d1ec6c049a"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", _UUIDBlob(), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("password_hash", sa.String(), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint("role IN ('admin','owner')", name="ck_users_role"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
    )

    op.create_table(
        "companion_identities",
        sa.Column("id", _UUIDBlob(), nullable=False),
        sa.Column("user_id", _UUIDBlob(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("pubkey", sa.BLOB(), nullable=False),
        sa.Column("privkey_enc", sa.BLOB(), nullable=False),
        sa.Column("scope", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("pubkey"),
    )
    op.create_index("ix_companion_owner", "companion_identities", ["user_id"], unique=False)

    op.create_table(
        "email_verifications",
        sa.Column("token_hash", sa.BLOB(), nullable=False),
        sa.Column("user_id", _UUIDBlob(), nullable=False),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("token_hash"),
        sa.UniqueConstraint(
            "user_id", "purpose", name="uq_email_verification_user_purpose"
        ),
    )
    op.create_index(
        "ix_email_verifications_user", "email_verifications", ["user_id"], unique=False
    )

    op.create_table(
        "repeaters",
        sa.Column("id", _UUIDBlob(), nullable=False),
        sa.Column("owner_id", _UUIDBlob(), nullable=False),
        sa.Column("site_id", _UUIDBlob(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("scope", sa.String(length=64), nullable=False),
        sa.Column("token_prefix", sa.BLOB(), nullable=False),
        sa.Column("token_hash", sa.String(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("site_id"),
    )
    op.create_index("ix_repeaters_owner", "repeaters", ["owner_id"], unique=False)
    op.create_index("ix_repeaters_token_prefix", "repeaters", ["token_prefix"], unique=False)

    op.create_table(
        "sessions",
        sa.Column("id", sa.BLOB(), nullable=False),
        sa.Column("user_id", _UUIDBlob(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column("user_agent", sa.String(length=256), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_sessions_user", "sessions", ["user_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_sessions_user", table_name="sessions")
    op.drop_table("sessions")
    op.drop_index("ix_repeaters_token_prefix", table_name="repeaters")
    op.drop_index("ix_repeaters_owner", table_name="repeaters")
    op.drop_table("repeaters")
    op.drop_index("ix_email_verifications_user", table_name="email_verifications")
    op.drop_table("email_verifications")
    op.drop_index("ix_companion_owner", table_name="companion_identities")
    op.drop_table("companion_identities")
    op.drop_table("users")
