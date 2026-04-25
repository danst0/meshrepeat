"""Argon2id password hashing.

Wir nutzen :class:`argon2.PasswordHasher` mit konservativen Defaults
und parametrisieren auf Wunsch über die App-Config.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_DEFAULT_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65_536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def hash_password(
    password: str,
    *,
    hasher: PasswordHasher | None = None,
) -> str:
    """Return the argon2id hash of ``password`` (PHC string format)."""
    h = hasher or _DEFAULT_HASHER
    return h.hash(password)


def verify_password(
    hashed: str,
    password: str,
    *,
    hasher: PasswordHasher | None = None,
) -> bool:
    """Verify a previously hashed password.

    Returns ``True`` on match, ``False`` on mismatch. Other argon2 errors
    propagate (e.g. invalid hash strings).
    """
    h = hasher or _DEFAULT_HASHER
    try:
        h.verify(hashed, password)
        return True
    except VerifyMismatchError:
        return False


def make_hasher(time_cost: int, memory_cost_kib: int, parallelism: int) -> PasswordHasher:
    return PasswordHasher(
        time_cost=time_cost,
        memory_cost=memory_cost_kib,
        parallelism=parallelism,
        hash_len=32,
        salt_len=16,
    )
