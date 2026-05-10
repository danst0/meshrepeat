"""Hashtag-Sigil aus Channel-Namen entfernen

In v0.4.6 wurden die voreingestellten Hashtag-Channels mit führendem ``#``
in der DB abgelegt (z.B. ``#bonn``). Das UI präfixiert beim Rendern aber
ein weiteres ``#``, sodass die Channels als ``##bonn`` auftauchten.

Konvention ab v0.4.7: ``name`` enthält *keinen* Sigil; das ``#`` ist eine
reine UI-Anzeigekonvention. Die PSK-Ableitung rechnet weiter mit ``#`` als
Hash-Input (Mesh-Rheinland-Doku: ``sha256("#test")[:16]``).

Diese Migration normalisiert ``companion_channels.name`` und die
zugehörigen ``companion_messages.channel_name`` zurück auf den nackten
Namen. ``public`` ist nicht betroffen (kein führendes ``#``).

Revision ID: e4b8d5c2f1a9
Revises: d3a8c4b1e9f5
Create Date: 2026-05-10
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "e4b8d5c2f1a9"
down_revision: str | None = "d3a8c4b1e9f5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Schon entsigilte Bestände (z.B. user-erstellte Kanäle ``test``)
    # könnten mit den umzubenennenden ``#test`` kollidieren — in dem Fall
    # behalten wir den existierenden Namen und löschen den auto-seed-
    # Eintrag, sonst schlägt UPDATE wegen UNIQUE-Constraint fehl.
    op.execute(
        """
        DELETE FROM companion_channels
        WHERE name LIKE '#%'
          AND EXISTS (
              SELECT 1 FROM companion_channels c2
              WHERE c2.identity_id = companion_channels.identity_id
                AND c2.name = SUBSTR(companion_channels.name, 2)
          )
        """
    )
    op.execute(
        "UPDATE companion_channels SET name = SUBSTR(name, 2) WHERE name LIKE '#%'"
    )
    op.execute(
        """
        UPDATE companion_messages
        SET channel_name = SUBSTR(channel_name, 2)
        WHERE channel_name LIKE '#%'
        """
    )


def downgrade() -> None:
    # Reine Daten-Migration; ein Downgrade wäre nicht eindeutig
    # (welche Channels waren ursprünglich auto-seeded?).
    raise RuntimeError("downgrade not supported for e4b8d5c2f1a9")
