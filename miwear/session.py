"""Assemble ATT values into a coherent SAR session and decode it.

A single SAR frame can be spread across several ATT writes, and a single
ATT write can contain several frames, so the only correct approach is to
concatenate the values of one direction in capture order and then run the
frame parser over the resulting byte stream.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from . import constants as C
from .capture import DIR_DEVICE_TO_HOST, DIR_HOST_TO_DEVICE, AttValue
from .layer_l1 import L1Frame, TruncatedFrame, iter_frames
from .layer_l2 import decode_config_tlv, parse_l2
from .protobuf import ProtoError, decode as proto_decode

__all__ = ["DecodedFrame", "decode_stream", "decode_att_values", "summarise"]


@dataclass
class DecodedFrame:
    """An L1 frame with its L2/application layer already peeled."""

    frame: L1Frame
    direction: str
    cmd: dict | None = None
    l2_channel: int | None = None
    l2_channel_name: str | None = None
    l2_opcode: int | None = None
    l2_opcode_name: str | None = None
    l2_payload: bytes = b""
    proto_fields: list | None = None
    proto_error: str | None = None

    @property
    def type_name(self) -> str:
        return self.frame.type_name

    @property
    def is_encrypted(self) -> bool:
        return self.l2_opcode == C.OP_WRITE_ENC


def decode_stream(buf: bytes, direction: str = "?") -> list[DecodedFrame]:
    """Decode a raw byte stream into fully peeled frames."""
    results: list[DecodedFrame] = []
    for item in iter_frames(buf):
        if isinstance(item, TruncatedFrame):
            continue

        entry = DecodedFrame(frame=item, direction=direction)

        if item.type_raw == C.TYPE_CMD:
            entry.cmd = decode_config_tlv(item.payload)

        elif item.type_raw == C.TYPE_DATA:
            l2 = parse_l2(item.payload)
            if l2 is not None:
                entry.l2_channel = l2.channel
                entry.l2_channel_name = l2.channel_name
                entry.l2_opcode = l2.opcode
                entry.l2_opcode_name = l2.opcode_name
                entry.l2_payload = l2.data
                if not l2.is_encrypted and l2.data:
                    try:
                        entry.proto_fields = proto_decode(l2.data)
                    except ProtoError as exc:
                        entry.proto_error = str(exc)

        results.append(entry)
    return results


def decode_att_values(values: Iterable[AttValue], *,
                      split_directions: bool = True) -> list[DecodedFrame]:
    """Concatenate ATT values and decode them.

    With ``split_directions`` (the default) each direction is decoded as its
    own stream, which is what the device actually sees.
    """
    values = list(values)
    if not split_directions:
        stream = b"".join(v.value for v in values)
        return decode_stream(stream, direction="mixed")

    out: list[DecodedFrame] = []
    for direction, label in ((DIR_HOST_TO_DEVICE, "MTU->DEV"),
                             (DIR_DEVICE_TO_HOST, "DEV->MTU")):
        stream = b"".join(v.value for v in values if v.direction == direction)
        if stream:
            out.extend(decode_stream(stream, direction=label))
    return out


def summarise(frames: list[DecodedFrame]) -> dict:
    """Aggregate counters for a decoded session (handy for tests and CLI)."""
    counts: dict[str, int] = {}
    bad_crc = 0
    for entry in frames:
        counts[entry.type_name] = counts.get(entry.type_name, 0) + 1
        if not entry.frame.crc_ok:
            bad_crc += 1
    return {
        "frames": len(frames),
        "by_type": counts,
        "crc_failures": bad_crc,
    }
