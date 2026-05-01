"""SQLAlchemy 2.0 ORM models.

Schema-Sketch in ``docs/auth.md`` und ADR 007. Alle UUIDs werden als
16-Byte-BLOBs gespeichert (kompakter als Strings, sortierbar).
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    BLOB,
    Boolean,
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

    def process_bind_param(self, value: UUID | bytes | None, dialect: object) -> bytes | None:
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
    is_echo: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="0", default=False
    )

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
    # Bei Room-Push-Inbound: erste 4 Bytes des Original-Senders, der den
    # Post abgesetzt hat. peer_pubkey ist dann der Room-Pubkey, der echte
    # Autor lebt nur als Prefix (mehr ist auf der Wire nicht da).
    room_sender_pubkey: Mapped[bytes | None] = mapped_column(BLOB)
    raw: Mapped[bytes] = mapped_column(BLOB, nullable=False)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (Index("ix_companion_messages_identity_ts", "identity_id", "ts"),)


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
    favorite: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="0", default=False
    )
    # ADV_TYPE aus letztem Advert (1=Chat, 2=Repeater, 3=Room, 4=Sensor).
    # NULL = noch kein Advert beobachtet (Legacy oder Manuell angelegt).
    node_type: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Aus letzter ADVERT app_data extrahiert, falls Lat/Lon-Flag gesetzt war.
    last_lat: Mapped[float | None] = mapped_column(nullable=True)
    last_lon: Mapped[float | None] = mapped_column(nullable=True)
    # Gelernter Out-Path zum Peer (Bytes vom PATH-Return des Peers, 1:1
    # in DIRECT-DMs einsetzbar). NULL = noch nicht gelernt → FLOOD-Fallback.
    out_path: Mapped[bytes | None] = mapped_column(BLOB, nullable=True)
    out_path_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("identity_id", "peer_pubkey", name="uq_companion_contact_pair"),
        Index("ix_companion_contacts_identity", "identity_id"),
    )


class RawPacket(Base):
    """Persistierter LoRa-Frame, der über einen Repeater an den Bridge-Server
    angeliefert wurde. Befüllt vom Packet-Spool-Worker (siehe
    ``bridge/packet_spool.py``); Retention 7 Tage. Quelle für die Wireshark-
    Inspector-Seite (``/admin/inspector``)."""

    __tablename__ = "raw_packets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    site_id: Mapped[UUID] = mapped_column(_UUIDBlob, nullable=False)
    site_name: Mapped[str | None] = mapped_column(String(64))
    scope: Mapped[str] = mapped_column(String(64), nullable=False)
    route_type: Mapped[str] = mapped_column(String(24), nullable=False)
    payload_type: Mapped[str] = mapped_column(String(24), nullable=False)
    raw: Mapped[bytes] = mapped_column(BLOB, nullable=False)
    path_hashes: Mapped[str] = mapped_column(String, nullable=False, default="")
    advert_pubkey: Mapped[str | None] = mapped_column(String(64))
    forwarded_to: Mapped[str] = mapped_column(String, nullable=False, default="[]")
    dropped_reason: Mapped[str | None] = mapped_column(String(64))

    __table_args__ = (
        Index("ix_raw_packets_site_ts", "site_id", "ts"),
        Index("ix_raw_packets_ts", "ts"),
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


class CompanionLinkProbe(Base):
    """Ergebnis einer Companion→Peer-Erreichbarkeitsprobe.

    Probe = STATUS-REQ (PayloadType.REQ, REQ_TYPE_GET_STATUS) mit Tag.
    Wir tracken Versand-Zeit und matchen die RESPONSE über den Tag, um
    RTT zu messen. Bleibt die Antwort aus, wird der Eintrag auf
    ``status='timeout'`` gesetzt. Stabilitäts-Auswertung läuft per
    Aggregation über (identity_id, peer_pubkey, sent_at)."""

    __tablename__ = "companion_link_probes"

    id: Mapped[UUID] = mapped_column(_UUIDBlob, primary_key=True, default=uuid4)
    identity_id: Mapped[UUID] = mapped_column(
        _UUIDBlob, ForeignKey("companion_identities.id"), nullable=False
    )
    peer_pubkey: Mapped[bytes] = mapped_column(BLOB, nullable=False)
    sent_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # Korrelations-Tag (4 Byte little-endian aus dem REQ-Plaintext, als int).
    req_tag: Mapped[int] = mapped_column(Integer, nullable=False)
    # 'FLOOD' oder 'DIRECT' — bei DIRECT zusätzlich hop_count gesetzt.
    route_kind: Mapped[str] = mapped_column(String(8), nullable=False)
    hop_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # 'pending' beim Anlegen, später 'ack' oder 'timeout'.
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    rtt_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    answered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("ix_companion_link_probes_pair_time", "identity_id", "peer_pubkey", "sent_at"),
        Index("ix_companion_link_probes_tag", "req_tag"),
    )
