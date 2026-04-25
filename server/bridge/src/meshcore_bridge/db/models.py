"""SQLAlchemy 2.0 ORM models.

Schema-Sketch in ``docs/auth.md`` und ADR 007. Alle UUIDs werden als
16-Byte-BLOBs gespeichert (kompakter als Strings, sortierbar).
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    BLOB,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator


class _UUIDBlob(TypeDecorator[UUID]):
    """UUID stored as 16 raw bytes (BLOB) — portable across SQLite/Postgres."""

    impl = BLOB
    cache_ok = True

    _UUID_BYTES = 16

    def process_bind_param(self, value: UUID | None, dialect: object) -> bytes | None:
        if value is None:
            return None
        if isinstance(value, UUID):
            return value.bytes
        if isinstance(value, bytes) and len(value) == self._UUID_BYTES:
            return value
        raise TypeError(f"expected UUID or 16-byte bytes, got {type(value).__name__}")

    def process_result_value(self, value: bytes | None, dialect: object) -> UUID | None:
        if value is None:
            return None
        return UUID(bytes=value)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(_UUIDBlob, primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="owner")
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    repeaters: Mapped[list[Repeater]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )
    identities: Mapped[list[CompanionIdentity]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )
    sessions: Mapped[list[Session]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    __table_args__ = (CheckConstraint("role IN ('admin','owner')", name="ck_users_role"),)


class Repeater(Base):
    __tablename__ = "repeaters"

    id: Mapped[UUID] = mapped_column(_UUIDBlob, primary_key=True, default=uuid4)
    owner_id: Mapped[UUID] = mapped_column(_UUIDBlob, ForeignKey("users.id"), nullable=False)
    site_id: Mapped[UUID] = mapped_column(_UUIDBlob, unique=True, nullable=False, default=uuid4)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    scope: Mapped[str] = mapped_column(String(64), nullable=False, default="public")
    """Either 'public' or 'pool:<uuid>'."""

    token_prefix: Mapped[bytes] = mapped_column(BLOB, nullable=False)
    """First 4 bytes of SHA-256(token) — index for lookup. Not unique by itself."""
    token_hash: Mapped[str] = mapped_column(String, nullable=False)
    """argon2id(token) — full verification."""

    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    owner: Mapped[User] = relationship(back_populates="repeaters")

    __table_args__ = (
        Index("ix_repeaters_token_prefix", "token_prefix"),
        Index("ix_repeaters_owner", "owner_id"),
    )


class CompanionIdentity(Base):
    __tablename__ = "companion_identities"

    id: Mapped[UUID] = mapped_column(_UUIDBlob, primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(_UUIDBlob, ForeignKey("users.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    pubkey: Mapped[bytes] = mapped_column(BLOB, unique=True, nullable=False)  # 32 bytes Ed25519
    privkey_enc: Mapped[bytes] = mapped_column(BLOB, nullable=False)  # XChaCha20-Poly1305(privkey)
    scope: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    owner: Mapped[User] = relationship(back_populates="identities")

    __table_args__ = (Index("ix_companion_owner", "user_id"),)


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[bytes] = mapped_column(BLOB, primary_key=True)  # 32 random bytes
    user_id: Mapped[UUID] = mapped_column(_UUIDBlob, ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    user_agent: Mapped[str | None] = mapped_column(String(256))

    user: Mapped[User] = relationship(back_populates="sessions")

    __table_args__ = (Index("ix_sessions_user", "user_id"),)


class EmailVerification(Base):
    __tablename__ = "email_verifications"

    token_hash: Mapped[bytes] = mapped_column(BLOB, primary_key=True)  # sha256(token)
    user_id: Mapped[UUID] = mapped_column(_UUIDBlob, ForeignKey("users.id"), nullable=False)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    """'email_verify' or 'password_reset'."""
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("user_id", "purpose", name="uq_email_verification_user_purpose"),
        Index("ix_email_verifications_user", "user_id"),
    )


class CompanionMessage(Base):
    """Companion-Nachrichten. Direction 'in' = vom Mesh empfangen, 'out' = von uns
    gesendet. Bei DMs ist ``peer_pubkey`` gefüllt; bei Channel-Posts ist
    ``channel_name`` gesetzt und peer_pubkey leer."""

    __tablename__ = "companion_messages"

    id: Mapped[UUID] = mapped_column(_UUIDBlob, primary_key=True, default=uuid4)
    identity_id: Mapped[UUID] = mapped_column(
        _UUIDBlob, ForeignKey("companion_identities.id"), nullable=False
    )
    direction: Mapped[str] = mapped_column(String(8), nullable=False)  # 'in' | 'out'
    payload_type: Mapped[int] = mapped_column(Integer, nullable=False)  # MeshCore PayloadType
    peer_pubkey: Mapped[bytes | None] = mapped_column(BLOB)
    peer_name: Mapped[str | None] = mapped_column(String(64))
    channel_name: Mapped[str | None] = mapped_column(String(64))
    text: Mapped[str | None] = mapped_column(String)
    raw: Mapped[bytes] = mapped_column(BLOB, nullable=False)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        Index("ix_companion_messages_identity_ts", "identity_id", "ts"),
    )


class CompanionContact(Base):
    """Bekannte Peer-Identitäten, abgeleitet aus beobachteten Adverts."""

    __tablename__ = "companion_contacts"

    id: Mapped[UUID] = mapped_column(_UUIDBlob, primary_key=True, default=uuid4)
    identity_id: Mapped[UUID] = mapped_column(
        _UUIDBlob, ForeignKey("companion_identities.id"), nullable=False
    )
    peer_pubkey: Mapped[bytes] = mapped_column(BLOB, nullable=False)
    peer_name: Mapped[str | None] = mapped_column(String(64))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("identity_id", "peer_pubkey", name="uq_companion_contact_pair"),
        Index("ix_companion_contacts_identity", "identity_id"),
    )


class CompanionChannel(Base):
    """MeshCore-Gruppenkanäle pro Identity. Secret aus name+password
    abgeleitet (``derive_channel_secret``); wird zum Verschlüsseln von
    GRP_TXT-Posts genutzt. ``channel_hash`` = sha256(secret)[:1] und
    dient als Routing-Hash auf der Wire."""

    __tablename__ = "companion_channels"

    id: Mapped[UUID] = mapped_column(_UUIDBlob, primary_key=True, default=uuid4)
    identity_id: Mapped[UUID] = mapped_column(
        _UUIDBlob, ForeignKey("companion_identities.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    secret: Mapped[bytes] = mapped_column(BLOB, nullable=False)  # 32 bytes
    channel_hash: Mapped[bytes] = mapped_column(BLOB, nullable=False)  # 1 byte
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("identity_id", "name", name="uq_companion_channel_name"),
        Index("ix_companion_channels_identity", "identity_id"),
    )
