"""Software-Companion: virtueller MeshCore-Node.

Phase 4a: Crypto + Paket-Codec. Phase 4b: virtueller Node + Bridge-Hook.
"""

from meshcore_companion.crypto import (
    CIPHER_KEY_SIZE,
    CIPHER_MAC_SIZE,
    PUB_KEY_SIZE,
    Identity,
    LocalIdentity,
    encrypt_then_mac,
    mac_then_decrypt,
    packet_hash,
)
from meshcore_companion.packet import Advert, Packet, PayloadType, RouteType

__all__ = [
    "CIPHER_KEY_SIZE",
    "CIPHER_MAC_SIZE",
    "PUB_KEY_SIZE",
    "Advert",
    "Identity",
    "LocalIdentity",
    "Packet",
    "PayloadType",
    "RouteType",
    "encrypt_then_mac",
    "mac_then_decrypt",
    "packet_hash",
]

__version__ = "0.0.1"
