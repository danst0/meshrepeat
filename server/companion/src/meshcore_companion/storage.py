"""Persistenz für Companion-Identitäten.

Privkeys werden mit XChaCha20-Poly1305 verschlüsselt (libsodium SecretBox
via PyNaCl). Der Master-Key kommt aus :class:`AppConfig` (Bridge-Seite,
gemeinsame DB).

Subkey-Ableitung:
    per_identity_key = HKDF-SHA256(master_key, salt=identity_id_bytes,
                                   info="companion-privkey", L=32)
"""

from __future__ import annotations

import hashlib
import hmac
from uuid import UUID

from nacl.secret import SecretBox
from nacl.utils import random as nacl_random

KEY_LEN = 32
NONCE_LEN = 24
SEED_LEN = 32  # Ed25519 seed
MASTER_MIN_LEN = 32


def _hkdf_extract_and_expand(master: bytes, *, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC-5869 HKDF mit SHA-256 (extract+expand)."""
    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, master, hashlib.sha256).digest()
    out = bytearray()
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return bytes(out[:length])


def derive_identity_key(master_key: bytes, identity_id: UUID) -> bytes:
    """Pro-Identity Encryption-Key, deterministisch reproduzierbar."""
    if len(master_key) < MASTER_MIN_LEN:
        raise ValueError("master_key must be >= 32 bytes")
    return _hkdf_extract_and_expand(
        master_key,
        salt=identity_id.bytes,
        info=b"companion-privkey",
        length=KEY_LEN,
    )


def encrypt_seed(master_key: bytes, identity_id: UUID, seed: bytes) -> bytes:
    """Returns ``nonce (24) || ciphertext_with_mac``."""
    if len(seed) != SEED_LEN:
        raise ValueError("seed must be 32 bytes (Ed25519)")
    box = SecretBox(derive_identity_key(master_key, identity_id))
    nonce = nacl_random(NONCE_LEN)
    return bytes(box.encrypt(seed, nonce))  # nonce + ct + mac


def decrypt_seed(master_key: bytes, identity_id: UUID, blob: bytes) -> bytes:
    """Inverse von :func:`encrypt_seed`."""
    box = SecretBox(derive_identity_key(master_key, identity_id))
    return bytes(box.decrypt(blob))
