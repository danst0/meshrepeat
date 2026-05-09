"""companion_messages: Auto-Übersetzungs-Felder

Drei optionale Spalten für die clientseitig zuschaltbare Auto-Übersetzung
eingehender Companion-Nachrichten:
- ``language``         — ISO-639-1 der erkannten Quellsprache (z.B. ``nl``)
- ``translated_text``  — Übersetzung in die konfigurierte Zielsprache
- ``translated_at``    — UTC-Timestamp, wann die Übersetzung gesetzt wurde

Befüllt vom ``meshcore_companion.translator`` (Ollama). NULL bleibt das
Default — z.B. bei deaktiviertem Feature, Skip-Heuristik oder wenn der
Übersetzer-Aufruf fehlgeschlagen ist.

Revision ID: a7b2e9f4c1d3
Revises: c8f3a1d6b2e4
Create Date: 2026-05-09
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a7b2e9f4c1d3"
down_revision: str | None = "c8f3a1d6b2e4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("companion_messages") as batch:
        batch.add_column(sa.Column("language", sa.String(length=8), nullable=True))
        batch.add_column(sa.Column("translated_text", sa.String(), nullable=True))
        batch.add_column(
            sa.Column("translated_at", sa.DateTime(timezone=True), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("companion_messages") as batch:
        batch.drop_column("translated_at")
        batch.drop_column("translated_text")
        batch.drop_column("language")
