"""CBOR-Codec für Wire-Frames.

Ein WS-Binary-Frame == ein Wire-Frame. Wir encoden mit kanonischem CBOR
(deterministic + canonical = stable Hashes für Dedup).

UUID-Felder werden on-wire als raw 16 Byte (Major-Type 2 / bytes) ohne
CBOR-Tag übertragen — wir konvertieren UUID-Instanzen vor dem Encode
und akzeptieren bytes(len=16) im Decode (siehe ``UUIDBytes`` in frames).
"""

from __future__ import annotations

from uuid import UUID

import cbor2
from pydantic import TypeAdapter, ValidationError

from meshcore_bridge.wire.frames import Frame

MAX_FRAME_BYTES = 8192

_FRAME_ADAPTER: TypeAdapter[Frame] = TypeAdapter(Frame)


class FrameDecodeError(Exception):
    """Raised when a frame cannot be decoded or validated."""


def _coerce_for_cbor(obj: object) -> object:
    if isinstance(obj, UUID):
        return obj.bytes
    if isinstance(obj, dict):
        return {k: _coerce_for_cbor(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_coerce_for_cbor(v) for v in obj]
    return obj


def encode_frame(frame: Frame) -> bytes:
    # exclude_none: Firmware-CBOR-Reader (CborReader::skipItem) unterstützt
    # CBOR-null (Major-Type 7) nicht — siehe firmware/src/wire/CborReader.h.
    # Wenn wir None-Felder sparen, hängt sich das Repeater-Parsing nicht auf.
    payload = _FRAME_ADAPTER.dump_python(frame, mode="python", exclude_none=True)
    payload = _coerce_for_cbor(payload)
    encoded = cbor2.dumps(payload, canonical=True)
    if len(encoded) > MAX_FRAME_BYTES:
        raise FrameDecodeError(f"encoded frame {len(encoded)} > {MAX_FRAME_BYTES} bytes")
    return encoded


def decode_frame(data: bytes) -> Frame:
    if len(data) > MAX_FRAME_BYTES:
        raise FrameDecodeError(f"frame {len(data)} > {MAX_FRAME_BYTES} bytes")
    try:
        decoded = cbor2.loads(data)
    except cbor2.CBORDecodeError as exc:
        raise FrameDecodeError(f"invalid CBOR: {exc}") from exc
    if not isinstance(decoded, dict):
        raise FrameDecodeError(f"top-level CBOR must be a map, got {type(decoded).__name__}")
    try:
        return _FRAME_ADAPTER.validate_python(decoded)
    except ValidationError as exc:
        raise FrameDecodeError(str(exc)) from exc
