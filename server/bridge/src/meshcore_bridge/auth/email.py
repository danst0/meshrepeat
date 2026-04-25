"""E-Mail-Verifikations- und Passwort-Reset-Tokens.

In Phase 1 ist der Versand-Channel pluggable; Default ist
``ConsoleEmailSender``, der die Mail einfach ins Log schreibt. Phase 5
ergänzt ``SmtpEmailSender``.
"""

from __future__ import annotations

import hashlib
import secrets
from abc import ABC, abstractmethod
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from meshcore_bridge.db.models import EmailVerification
from meshcore_bridge.log import get_logger

Purpose = Literal["email_verify", "password_reset"]

DEFAULT_TTL = timedelta(hours=24)
TOKEN_BYTES = 24


def _new_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def _hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode("ascii")).digest()


async def issue_token(
    db: AsyncSession,
    *,
    user_id: UUID,
    purpose: Purpose,
    ttl: timedelta = DEFAULT_TTL,
) -> str:
    """Erzeugt einen neuen Verifikations-Token, ersetzt evtl. existierenden für dieselbe Purpose."""
    existing = (
        await db.execute(
            select(EmailVerification).where(
                EmailVerification.user_id == user_id,
                EmailVerification.purpose == purpose,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        await db.delete(existing)
        await db.flush()

    token = _new_token()
    db.add(
        EmailVerification(
            token_hash=_hash_token(token),
            user_id=user_id,
            purpose=purpose,
            expires_at=datetime.now(UTC) + ttl,
        )
    )
    await db.commit()
    return token


async def consume_token(
    db: AsyncSession,
    *,
    token: str,
    purpose: Purpose,
) -> UUID | None:
    """Versucht, ``token`` zu verifizieren und zu konsumieren.

    Returns ``user_id`` bei Erfolg, ``None`` bei Mismatch/Ablauf/Verbraucht.
    """
    row = (
        await db.execute(
            select(EmailVerification).where(EmailVerification.token_hash == _hash_token(token))
        )
    ).scalar_one_or_none()
    if row is None:
        return None
    if row.purpose != purpose:
        return None
    if row.consumed_at is not None:
        return None
    expires_at = row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at < datetime.now(UTC):
        await db.delete(row)
        await db.commit()
        return None

    user_id = row.user_id
    row.consumed_at = datetime.now(UTC)
    await db.commit()
    return user_id


class EmailSender(ABC):
    @abstractmethod
    async def send(self, *, to: str, subject: str, body: str) -> None: ...


class ConsoleEmailSender(EmailSender):
    """Schreibt die Mail einfach ins Log. Für Dev und v1 ausreichend."""

    def __init__(self) -> None:
        self._log = get_logger("email")

    async def send(self, *, to: str, subject: str, body: str) -> None:
        self._log.info("send_email_console", to=to, subject=subject, body=body)
