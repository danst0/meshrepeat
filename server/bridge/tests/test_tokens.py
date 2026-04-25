from __future__ import annotations

import re

import pytest

from meshcore_bridge.auth.tokens import (
    TOKEN_LEN,
    generate_bearer_token,
    hash_bearer_token,
    token_prefix,
    verify_bearer_token,
)

_BASE32_RE = re.compile(r"^[A-Z2-7]{32}$")


def test_generated_token_is_32_chars_base32() -> None:
    tok = generate_bearer_token()
    assert len(tok) == TOKEN_LEN
    assert _BASE32_RE.match(tok), tok


def test_two_tokens_are_distinct() -> None:
    a = generate_bearer_token()
    b = generate_bearer_token()
    assert a != b


def test_token_prefix_is_4_bytes_and_deterministic() -> None:
    tok = generate_bearer_token()
    p1 = token_prefix(tok)
    p2 = token_prefix(tok)
    assert len(p1) == 4
    assert p1 == p2


@pytest.mark.usefixtures("fast_argon2")
def test_token_hash_verify_roundtrip() -> None:
    tok = generate_bearer_token()
    h = hash_bearer_token(tok)
    assert verify_bearer_token(h, tok) is True
    assert verify_bearer_token(h, "wrong") is False
