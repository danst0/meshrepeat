"""Bearer-Token-Generation für Repeater-Auth.

Token = 160 Bit Entropie, base32 (ohne Padding) → 32 ASCII-Zeichen.
Server speichert: SHA-256-Prefix (4 Byte) für O(1)-Lookup +
argon2id-Hash für die finale Verifikation.
"""

from __future__ import annotations

import base64
import hashlib
import secrets

from meshcore_bridge.auth.passwords import hash_password, verify_password

TOKEN_BYTES = 20  # 160 bit
TOKEN_LEN = 32  # base32 ohne Padding


def generate_bearer_token() -> str:
    """Erzeugt einen neuen Bearer-Token (32 ASCII-Zeichen, base32)."""
    raw = secrets.token_bytes(TOKEN_BYTES)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def token_prefix(token: str) -> bytes:
    """Erste 4 Bytes von ``sha256(token)`` — Lookup-Index."""
    return hashlib.sha256(token.encode("ascii")).digest()[:4]


def hash_bearer_token(token: str) -> str:
    """Erzeugt den argon2id-Hash für persistierte Verifikation."""
    return hash_password(token)


def verify_bearer_token(stored_hash: str, presented: str) -> bool:
    return verify_password(stored_hash, presented)
