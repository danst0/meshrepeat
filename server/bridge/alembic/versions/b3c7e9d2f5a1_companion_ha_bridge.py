"""companion ha bridge tables

Drei neue Tabellen für die Home-Assistant-LLM-Bridge:

* ``companion_ha_bridges`` — 1:1 zu ``companion_identities``, hält das
  Enable-Flag und die Routing-Parameter (Ollama-Modell, max. Entities
  pro Anfrage, Rate-Limit).
* ``companion_ha_allowed_pubkeys`` — Whitelist von Sender-Pubkeys, die
  die Bridge benutzen dürfen.
* ``companion_ha_exposed_entities`` — kuratierter HA-Entity-Katalog, den
  der LLM-Router je Identity sehen darf.

Revision ID: b3c7e9d2f5a1
Revises: a8d3e1c5b9f4
Create Date: 2026-05-16
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b3c7e9d2f5a1"
down_revision: str | None = "a8d3e1c5b9f4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "companion_ha_bridges",
        sa.Column("identity_id", sa.BLOB(), nullable=False),
        sa.Column(
            "enabled",
            sa.Boolean(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "ollama_model",
            sa.String(length=128),
            server_default="llama3.1:8b",
            nullable=False,
        ),
        sa.Column(
            "max_entities_per_query",
            sa.Integer(),
            server_default=sa.text("3"),
            nullable=False,
        ),
        sa.Column(
            "rate_limit_per_min",
            sa.Integer(),
            server_default=sa.text("5"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["identity_id"],
            ["companion_identities.id"],
        ),
        sa.PrimaryKeyConstraint("identity_id"),
    )

    op.create_table(
        "companion_ha_allowed_pubkeys",
        sa.Column("id", sa.BLOB(), nullable=False),
        sa.Column("identity_id", sa.BLOB(), nullable=False),
        sa.Column("pubkey", sa.BLOB(), nullable=False),
        sa.Column("label", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["identity_id"],
            ["companion_ha_bridges.identity_id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "identity_id", "pubkey", name="uq_companion_ha_allowed_pubkey"
        ),
    )
    op.create_index(
        "ix_companion_ha_allowed_identity",
        "companion_ha_allowed_pubkeys",
        ["identity_id"],
    )

    op.create_table(
        "companion_ha_exposed_entities",
        sa.Column("id", sa.BLOB(), nullable=False),
        sa.Column("identity_id", sa.BLOB(), nullable=False),
        sa.Column("entity_id", sa.String(length=255), nullable=False),
        sa.Column("alias", sa.String(length=64), nullable=False),
        sa.Column("hint", sa.String(length=255), nullable=True),
        sa.Column(
            "sort_order",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["identity_id"],
            ["companion_ha_bridges.identity_id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "identity_id", "entity_id", name="uq_companion_ha_exposed_entity"
        ),
    )
    op.create_index(
        "ix_companion_ha_exposed_identity",
        "companion_ha_exposed_entities",
        ["identity_id", "sort_order"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_companion_ha_exposed_identity",
        table_name="companion_ha_exposed_entities",
    )
    op.drop_table("companion_ha_exposed_entities")
    op.drop_index(
        "ix_companion_ha_allowed_identity",
        table_name="companion_ha_allowed_pubkeys",
    )
    op.drop_table("companion_ha_allowed_pubkeys")
    op.drop_table("companion_ha_bridges")
