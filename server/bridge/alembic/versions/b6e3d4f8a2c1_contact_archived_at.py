"""companion_contacts.archived_at

Erlaubt es, einen Kontakt aus der Sidebar-Liste zu verbannen, ohne ihn
zu löschen. Nachrichten und Pubkey bleiben erhalten; der Eintrag taucht
weiter in der Suche/Auto-Complete auf. Eingehende DMs setzen den Wert
in service.py wieder auf NULL zurück (Auto-Unarchive).

Revision ID: b6e3d4f8a2c1
Revises: a1f3e7b9c2d4
Create Date: 2026-05-16
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b6e3d4f8a2c1"
down_revision: str | None = "a1f3e7b9c2d4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("companion_contacts") as batch:
        batch.add_column(sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("companion_contacts") as batch:
        batch.drop_column("archived_at")
