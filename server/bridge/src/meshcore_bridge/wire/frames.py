"""Frame-Modelle nach ``protocol/WIRE.md``.

Top-Level: ``Frame = Hello | HelloAck | Packet | Heartbeat | HeartbeatAck | Flow | Bye``
mit Discriminator-Field ``t``. Pydantic kümmert sich um Validierung;
Serialisierung nach CBOR macht :mod:`meshcore_bridge.wire.codec`.

Wire-spezifisch: UUID-Felder werden on-wire als raw 16 Bytes übertragen
(siehe ``UUIDBytes``). Standard-Pydantic-UUID akzeptiert strings/UUIDs;
mit ``BeforeValidator`` ergänzen wir die Variante "bytes der Länge 16".
"""

from __future__ import annotations

from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

PROTO_VERSION = 1

CapTag = Literal["rssi", "snr"]


_UUID_BYTES = 16


def _coerce_uuid(v: Any) -> UUID:
    if isinstance(v, UUID):
        return v
    if isinstance(v, bytes) and len(v) == _UUID_BYTES:
        return UUID(bytes=v)
    if isinstance(v, str):
        return UUID(v)
    raise ValueError(f"invalid UUID: {v!r}")


UUIDBytes = Annotated[UUID, BeforeValidator(_coerce_uuid)]


class _FrameBase(BaseModel):
    model_config = ConfigDict(frozen=False, extra="forbid")


class Hello(_FrameBase):
    t: Literal["hello"] = "hello"
    site: UUIDBytes
    tok: str = Field(min_length=8, max_length=64)
    fw: str = Field(max_length=32)
    proto: int = Field(ge=1)
    scope: str = Field(max_length=64)
    caps: list[CapTag] = Field(default_factory=list)


class HelloAck(_FrameBase):
    t: Literal["helloack"] = "helloack"
    proto: int = Field(ge=1)
    policy_ep: int = Field(ge=0)
    srv_time: int
    max_bytes: int = Field(ge=64)
    hb_iv: int = Field(ge=1)


class Packet(_FrameBase):
    t: Literal["pkt"] = "pkt"
    raw: bytes = Field(min_length=1, max_length=512)
    rssi: int | None = None
    snr: int | None = None
    rxts: int | None = None


class Heartbeat(_FrameBase):
    t: Literal["hb"] = "hb"
    seq: int = Field(ge=0)
    ts: int


class HeartbeatAck(_FrameBase):
    t: Literal["hback"] = "hback"
    seq: int = Field(ge=0)


class Flow(_FrameBase):
    t: Literal["flow"] = "flow"
    pause_ms: int = Field(ge=0, le=60_000)


class Bye(_FrameBase):
    t: Literal["bye"] = "bye"
    reason: str = Field(max_length=64)


Frame = Annotated[
    Hello | HelloAck | Packet | Heartbeat | HeartbeatAck | Flow | Bye,
    Field(discriminator="t"),
]
