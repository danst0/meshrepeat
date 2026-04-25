from __future__ import annotations

from uuid import uuid4

import pytest

from meshcore_companion.storage import (
    decrypt_seed,
    derive_identity_key,
    encrypt_seed,
)


def test_derive_identity_key_deterministic_per_id() -> None:
    master = b"M" * 32
    a = uuid4()
    b = uuid4()
    k1 = derive_identity_key(master, a)
    k2 = derive_identity_key(master, a)
    k_other = derive_identity_key(master, b)
    assert k1 == k2
    assert len(k1) == 32
    assert k1 != k_other


def test_encrypt_then_decrypt_seed_roundtrip() -> None:
    master = bytes(range(32))
    iid = uuid4()
    seed = b"S" * 32
    blob = encrypt_seed(master, iid, seed)
    # nonce(24) + ct+mac(48) = 72 bytes
    assert len(blob) == 24 + 48
    assert decrypt_seed(master, iid, blob) == seed


def test_decrypt_with_wrong_master_fails() -> None:
    blob = encrypt_seed(b"A" * 32, uuid4(), b"S" * 32)
    with pytest.raises(Exception):
        decrypt_seed(b"B" * 32, uuid4(), blob)


def test_decrypt_with_wrong_id_fails() -> None:
    master = b"A" * 32
    blob = encrypt_seed(master, uuid4(), b"S" * 32)
    with pytest.raises(Exception):
        decrypt_seed(master, uuid4(), blob)


def test_encrypt_seed_rejects_wrong_seed_length() -> None:
    with pytest.raises(ValueError):
        encrypt_seed(b"M" * 32, uuid4(), b"S" * 16)


def test_encrypt_seed_rejects_short_master() -> None:
    with pytest.raises(ValueError):
        encrypt_seed(b"M" * 16, uuid4(), b"S" * 32)
