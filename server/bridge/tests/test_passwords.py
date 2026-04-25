from __future__ import annotations

import pytest

from meshcore_bridge.auth.passwords import (
    hash_password,
    make_hasher,
    verify_password,
)


@pytest.mark.usefixtures("fast_argon2")
def test_hash_then_verify_roundtrip() -> None:
    hashed = hash_password("hunter2")
    assert hashed.startswith("$argon2id$")
    assert verify_password(hashed, "hunter2") is True


@pytest.mark.usefixtures("fast_argon2")
def test_verify_wrong_password_returns_false() -> None:
    hashed = hash_password("hunter2")
    assert verify_password(hashed, "hunter3") is False


@pytest.mark.usefixtures("fast_argon2")
def test_two_hashes_of_same_password_differ() -> None:
    a = hash_password("hunter2")
    b = hash_password("hunter2")
    assert a != b


def test_invalid_hash_raises() -> None:
    with pytest.raises(Exception):
        verify_password("nonsense", "anything")


def test_make_hasher_uses_supplied_params() -> None:
    h = make_hasher(time_cost=1, memory_cost_kib=8192, parallelism=2)
    hashed = h.hash("x")
    # PHC string encodes parameters, e.g. m=8192,t=1,p=2
    assert "m=8192" in hashed
    assert "t=1" in hashed
    assert "p=2" in hashed
