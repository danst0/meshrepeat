"""companion api tokens

Bearer-Token pro Companion-Identity zum Ansprechen der Companion-REST-API
ohne Web-Session. Scopes ``read`` und/oder ``write`` (CSV), Hash-Pattern
identisch zu Repeater-Tokens (4-Byte-Prefix-Index + argon2id).

Revision ID: a1f3e7b9c2d4
Revises: f5c1d8a3b2e7
Create Date: 2026-05-14
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from meshcore_bridge.db.models import _UUIDBlob

revision: str = "a1f3e7b9c2d4"
down_revision: str | None = "f5c1d8a3b2e7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "companion_api_tokens",
        sa.Column("id", _UUIDBlob(), nullable=False),
        sa.Column("user_id", _UUIDBlob(), nullable=False),
        sa.Column("identity_id", _UUIDBlob(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("prefix", sa.BLOB(), nullable=False),
        sa.Column("token_hash", sa.String(), nullable=False),
        sa.Column("scopes", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["identity_id"], ["companion_identities.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_companion_api_tokens_prefix", "companion_api_tokens", ["prefix"], unique=False
    )
    op.create_index(
        "ix_companion_api_tokens_identity", "companion_api_tokens", ["identity_id"], unique=False
    )
    op.create_index(
        "ix_companion_api_tokens_user", "companion_api_tokens", ["user_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_companion_api_tokens_user", table_name="companion_api_tokens")
    op.drop_index("ix_companion_api_tokens_identity", table_name="companion_api_tokens")
    op.drop_index("ix_companion_api_tokens_prefix", table_name="companion_api_tokens")
    op.drop_table("companion_api_tokens")
