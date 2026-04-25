"""MeshCore-Crypto in Python.

Spiegelt die Algorithmen aus ``firmware/lib/meshcore/src/Utils.cpp``
und ``Identity.cpp`` 1:1, damit unser virtueller Companion mit echten
MeshCore-Nodes austauschen kann.

Konstanten (Quelle: ``firmware/lib/meshcore/src/MeshCore.h``):
- ``PUB_KEY_SIZE``    32 — Ed25519-Public-Key-Bytes
- ``CIPHER_KEY_SIZE`` 16 — AES-128
- ``CIPHER_MAC_SIZE``  2 — HMAC-Truncation (SCHWACH; bewusst auf 16 Bit
  beschnitten, gespart wegen LoRa-MTU)
- ``PATH_HASH_SIZE``   1 — 1-Byte Pubkey-Prefix als Pfad-Hash

Algorithmen:
- ECDH: Ed25519-Privkey → X25519-Privkey, Ed25519-Pubkey → X25519-Pubkey,
  dann Curve25519-Scalar-Mult. Output: 32 Byte Shared-Secret.
- Symmetric encrypt-then-MAC:
    ciphertext = AES-128-ECB(key=secret[:16], pt) — letzter Block null-padded
    mac        = HMAC-SHA256(key=secret[0:32], ciphertext)[:2]
    wire       = mac || ciphertext
- Decrypt: spiegelt encrypt-then-MAC
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from nacl.bindings import crypto_scalarmult
from nacl.signing import SigningKey, VerifyKey

PAYLOAD_TYPE_TRACE = 0x09
PUB_KEY_SIZE = 32
PRV_KEY_SIZE = 64
SIG_SIZE = 64
CIPHER_KEY_SIZE = 16
CIPHER_MAC_SIZE = 2
PATH_HASH_SIZE = 1
SHARED_SECRET_SIZE = 32


class Identity:
    """Ed25519-Identität (nur Public Key, fremde Nodes)."""

    __slots__ = ("pub_key",)

    def __init__(self, pub_key: bytes) -> None:
        if len(pub_key) != PUB_KEY_SIZE:
            raise ValueError(f"pub_key must be {PUB_KEY_SIZE} bytes")
        self.pub_key = pub_key

    def hash_prefix(self, n: int = PATH_HASH_SIZE) -> bytes:
        return self.pub_key[:n]

    def verify(self, signature: bytes, message: bytes) -> bool:
        try:
            VerifyKey(self.pub_key).verify(message, signature)
            return True
        except Exception:
            return False


class LocalIdentity:
    """Eigene Identität — Public + Private Key.

    Speicher-Format (für Persistenz): ``seed`` 32 Byte. Daraus lassen
    sich pub_key + signing-state deterministisch rekonstruieren.
    """

    __slots__ = ("_signing", "pub_key", "seed")

    def __init__(self, seed: bytes) -> None:
        if len(seed) != PUB_KEY_SIZE:
            raise ValueError("seed must be 32 bytes")
        self.seed = seed
        self._signing = SigningKey(seed)
        self.pub_key = bytes(self._signing.verify_key)

    @classmethod
    def generate(cls) -> LocalIdentity:
        sk = SigningKey.generate()
        return cls(bytes(sk))

    def sign(self, message: bytes) -> bytes:
        return bytes(self._signing.sign(message).signature)

    def calc_shared_secret(self, other_pub_key: bytes) -> bytes:
        """ECDH gegen einen Ed25519-Pubkey. Returns 32-byte secret.

        Konvertiert beide Seiten Ed25519 → X25519, dann Curve25519-DH.
        Spiegel zu ``ed25519_key_exchange()`` aus orlp/ed25519.
        """
        if len(other_pub_key) != PUB_KEY_SIZE:
            raise ValueError(f"peer pub_key must be {PUB_KEY_SIZE} bytes")
        my_x = self._signing.to_curve25519_private_key()
        peer_x = VerifyKey(other_pub_key).to_curve25519_public_key()
        return crypto_scalarmult(bytes(my_x), bytes(peer_x))


def aes128_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-128-ECB, last partial block ist mit Null-Bytes gepadded.

    MeshCore-spezifisch: ECB-Mode (kein IV), kein PKCS7. Letzter Block
    wird auf 16 Byte mit Nullen aufgefüllt — bei Decrypt müssen wir die
    ursprüngliche Länge anders mitführen (siehe encrypt_then_mac).
    """
    if len(key) < CIPHER_KEY_SIZE:
        raise ValueError("AES-128 requires 16-byte key")
    cipher = Cipher(algorithms.AES(key[:CIPHER_KEY_SIZE]), modes.ECB()).encryptor()  # noqa: S305
    out = bytearray()
    n = len(plaintext)
    full = n - (n % 16)
    out += cipher.update(plaintext[:full])
    if n % 16:
        block = plaintext[full:].ljust(16, b"\x00")
        out += cipher.update(block)
    out += cipher.finalize()
    return bytes(out)


def aes128_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    if len(key) < CIPHER_KEY_SIZE:
        raise ValueError("AES-128 requires 16-byte key")
    if len(ciphertext) % 16 != 0:
        raise ValueError("ciphertext length must be multiple of 16")
    cipher = Cipher(algorithms.AES(key[:CIPHER_KEY_SIZE]), modes.ECB()).decryptor()  # noqa: S305
    return cipher.update(ciphertext) + cipher.finalize()


def encrypt_then_mac(secret: bytes, plaintext: bytes) -> bytes:
    """Returns ``mac (2 byte) || aes128-ecb(plaintext, zero-padded)``.

    Spiegel zu ``Utils::encryptThenMAC`` (Utils.cpp:63).
    """
    ciphertext = aes128_ecb_encrypt(secret, plaintext)
    mac = hmac.new(secret, ciphertext, hashlib.sha256).digest()[:CIPHER_MAC_SIZE]
    return mac + ciphertext


def mac_then_decrypt(secret: bytes, blob: bytes) -> bytes | None:
    """Verifiziert MAC und entschlüsselt. Returns plaintext-bytes
    (mit eventuellem Null-Padding bis 16-Byte-Grenze) oder ``None``
    bei MAC-Mismatch.

    Spiegel zu ``Utils::MACThenDecrypt`` (Utils.cpp:74).
    """
    if len(blob) <= CIPHER_MAC_SIZE:
        return None
    mac, ciphertext = blob[:CIPHER_MAC_SIZE], blob[CIPHER_MAC_SIZE:]
    expected = hmac.new(secret, ciphertext, hashlib.sha256).digest()[:CIPHER_MAC_SIZE]
    if not hmac.compare_digest(mac, expected):
        return None
    if len(ciphertext) % 16 != 0:
        return None
    return aes128_ecb_decrypt(secret, ciphertext)


def packet_hash(payload_type: int, payload: bytes, *, path_len_byte: int | None = None) -> bytes:
    """SHA-256 des Pakets — analog ``Packet::calculatePacketHash``.

    TRACE-Pakete (payload_type 0x09) inkludieren das path_len-Byte, damit
    Reverse-Path nicht als Duplikat verworfen wird.
    """
    h = hashlib.sha256()
    h.update(bytes([payload_type]))
    if payload_type == PAYLOAD_TYPE_TRACE and path_len_byte is not None:
        h.update(bytes([path_len_byte]))
    h.update(payload)
    return h.digest()


def derive_channel_secret(name: str, password: str) -> bytes:
    """Channel-Secret-Ableitung — MeshCore nutzt aktuell keinen
    standardisierten KDF; einige Apps nutzen ``sha256(name + ":" + pw)[:32]``.
    Bis wir das auf der App-Seite bestätigt haben, exposen wir den
    Helper aber nutzen ihn intern noch nicht.
    """
    return hashlib.sha256(f"{name}:{password}".encode()).digest()[:32]
