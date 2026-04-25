from __future__ import annotations

import pytest

from meshcore_companion.crypto import (
    CIPHER_MAC_SIZE,
    PUB_KEY_SIZE,
    Identity,
    LocalIdentity,
    aes128_ecb_decrypt,
    aes128_ecb_encrypt,
    encrypt_then_mac,
    mac_then_decrypt,
    packet_hash,
)


def test_local_identity_generate_has_correct_sizes() -> None:
    li = LocalIdentity.generate()
    assert len(li.seed) == PUB_KEY_SIZE
    assert len(li.pub_key) == PUB_KEY_SIZE


def test_local_identity_deterministic_from_seed() -> None:
    seed = bytes([1] * PUB_KEY_SIZE)
    a = LocalIdentity(seed)
    b = LocalIdentity(seed)
    assert a.pub_key == b.pub_key
    assert a.sign(b"hello") == b.sign(b"hello")


def test_sign_then_verify_roundtrip() -> None:
    li = LocalIdentity.generate()
    msg = b"the quick brown fox"
    sig = li.sign(msg)
    assert Identity(li.pub_key).verify(sig, msg) is True
    assert Identity(li.pub_key).verify(sig, b"tampered") is False


def test_ecdh_shared_secret_symmetric() -> None:
    alice = LocalIdentity.generate()
    bob = LocalIdentity.generate()
    s_ab = alice.calc_shared_secret(bob.pub_key)
    s_ba = bob.calc_shared_secret(alice.pub_key)
    assert s_ab == s_ba
    assert len(s_ab) == 32


def test_ecdh_with_self_works() -> None:
    me = LocalIdentity.generate()
    s = me.calc_shared_secret(me.pub_key)
    assert len(s) == 32


def test_aes_ecb_roundtrip_with_partial_last_block() -> None:
    key = b"K" * 16
    pt = b"abc"  # 3 bytes — gets zero-padded to 16
    ct = aes128_ecb_encrypt(key, pt)
    assert len(ct) == 16
    decoded = aes128_ecb_decrypt(key, ct)
    assert decoded[: len(pt)] == pt
    assert decoded[len(pt):] == b"\x00" * (16 - len(pt))


def test_encrypt_then_mac_format_and_roundtrip() -> None:
    secret = b"S" * 32
    pt = b"hello world"
    blob = encrypt_then_mac(secret, pt)
    assert len(blob) == CIPHER_MAC_SIZE + 16
    decoded = mac_then_decrypt(secret, blob)
    assert decoded is not None
    assert decoded.startswith(pt)


def test_mac_then_decrypt_rejects_tampered_mac() -> None:
    secret = b"S" * 32
    blob = bytearray(encrypt_then_mac(secret, b"data"))
    blob[0] ^= 0x01
    assert mac_then_decrypt(secret, bytes(blob)) is None


def test_mac_then_decrypt_rejects_wrong_key() -> None:
    blob = encrypt_then_mac(b"A" * 32, b"data")
    assert mac_then_decrypt(b"B" * 32, blob) is None


def test_mac_then_decrypt_rejects_short_blob() -> None:
    assert mac_then_decrypt(b"S" * 32, b"\x00") is None
    assert mac_then_decrypt(b"S" * 32, b"\x00\x00") is None


def test_mac_then_decrypt_rejects_misaligned_ciphertext() -> None:
    secret = b"S" * 32
    # craft 3-byte ciphertext + correct mac → still rejected (not 16-aligned)
    bad_blob = b"\x00\x00" + b"\x01\x02\x03"
    assert mac_then_decrypt(secret, bad_blob) is None


def test_packet_hash_distinguishes_payload_types() -> None:
    h1 = packet_hash(0x02, b"payload")
    h2 = packet_hash(0x04, b"payload")
    assert h1 != h2
    assert len(h1) == 32


def test_packet_hash_includes_path_len_for_trace_only() -> None:
    h_no_path = packet_hash(0x09, b"x")
    h_with_path = packet_hash(0x09, b"x", path_len_byte=5)
    assert h_no_path != h_with_path

    # Non-TRACE: path_len wird ignoriert
    h1 = packet_hash(0x04, b"x")
    h2 = packet_hash(0x04, b"x", path_len_byte=5)
    assert h1 == h2


def test_local_identity_invalid_seed_size_raises() -> None:
    with pytest.raises(ValueError):
        LocalIdentity(b"\x00" * 16)


def test_identity_invalid_pubkey_size_raises() -> None:
    with pytest.raises(ValueError):
        Identity(b"\x00" * 16)
