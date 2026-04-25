"""E-Mail-Verifikations- und Passwort-Reset-Tokens.

Versand-Channel ist pluggable: ``ConsoleEmailSender`` (Dev/Default,
schreibt ins Log) und ``SmtpEmailSender`` (Prod, nutzt aiosmtplib via
asyncio.to_thread auf smtplib).
"""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import smtplib
import ssl
from abc import ABC, abstractmethod
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
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
    """Schreibt die Mail einfach ins Log. Für Dev ausreichend."""

    def __init__(self) -> None:
        self._log = get_logger("email")

    async def send(self, *, to: str, subject: str, body: str) -> None:
        self._log.info("send_email_console", to=to, subject=subject, body=body)


class SmtpEmailSender(EmailSender):
    """Versendet via SMTP. STARTTLS bevorzugt, alternativ implicit TLS.

    Konfiguration kommt aus :class:`SmtpConfig` (siehe
    :mod:`meshcore_bridge.config`). smtplib ist blockierend; wir lassen
    es in einem Thread laufen, damit der event loop frei bleibt.
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str | None,
        password: str | None,
        sender: str,
        use_tls: bool,
        starttls: bool,
        timeout_s: int = 20,
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._sender = sender
        self._use_tls = use_tls
        self._starttls = starttls
        self._timeout = timeout_s
        self._log = get_logger("email")

    async def send(self, *, to: str, subject: str, body: str) -> None:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self._sender
        msg["To"] = to
        msg.set_content(body)

        await asyncio.to_thread(self._send_blocking, msg)
        self._log.info("send_email_smtp", to=to, subject=subject, host=self._host)

    def _send_blocking(self, msg: EmailMessage) -> None:
        ctx = ssl.create_default_context()
        if self._use_tls:
            with smtplib.SMTP_SSL(self._host, self._port, timeout=self._timeout, context=ctx) as s:
                self._login_and_send(s, msg)
        else:
            with smtplib.SMTP(self._host, self._port, timeout=self._timeout) as s:
                if self._starttls:
                    s.starttls(context=ctx)
                self._login_and_send(s, msg)

    def _login_and_send(self, s: smtplib.SMTP, msg: EmailMessage) -> None:
        if self._username and self._password:
            s.login(self._username, self._password)
        s.send_message(msg)
