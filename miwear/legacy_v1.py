"""Legacy (V1) protocol used by devices reporting firmware version ``0.x``.

Two different framings share the ``BA DC FE`` preamble:

SPP / RFCOMM (``com.xiaomi.wearable.spp.b``)::

    BA DC FE | header u16 | dataLen u16 | opcode u8 | opCodeSN u8
             | dataType u8 | payload (dataLen-3) | EF

ATT characteristic channels (``defpackage.e84``)::

    sessionId u16 | type u8 | code u8 | [seq u16]* | [payload]

The SPP framing is the one that can be recovered from a plain byte stream,
so :func:`iter_v1_frames` targets it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from . import constants as C

__all__ = ["V1Frame", "iter_v1_frames", "build_v1_frame"]


@dataclass
class V1Frame:
    """One decoded legacy frame."""

    offset: int
    channel_type: int
    need_response: bool
    flag: bool
    opcode: int
    opcode_sn: int
    data_type: int
    payload: bytes

    @property
    def data_type_name(self) -> str:
        return C.V1_DATATYPE_NAMES.get(self.data_type,
                                       f"unknown({self.data_type})")

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (f"<V1Frame ch={self.channel_type} op=0x{self.opcode:02x} "
                f"sn={self.opcode_sn} type={self.data_type_name}>")


def iter_v1_frames(buf: bytes) -> Iterator[V1Frame]:
    """Scan *buf* for legacy ``BA DC FE ... EF`` frames."""
    magic = C.V1_FRAME_START
    pos = 0
    total = len(buf)
    while True:
        start = buf.find(magic, pos)
        if start < 0 or start + 11 > total:
            return

        header = int.from_bytes(buf[start + 3:start + 5], "little")
        data_len = int.from_bytes(buf[start + 5:start + 7], "little")
        # dataLen counts the 3-byte opcode/SN/dataType area plus the payload,
        # so the whole frame is: 3 (magic) + 2 (header) + 2 (dataLen)
        #                         + dataLen + 1 (terminator)
        frame_len = 8 + data_len

        if start + frame_len > total or buf[start + frame_len - 1] != C.V1_FRAME_END:
            pos = start + 3
            continue

        yield V1Frame(
            offset=start,
            channel_type=header & 0x0F,
            need_response=bool((header >> 14) & 1),
            flag=bool((header >> 15) & 1),
            opcode=buf[start + 7],
            opcode_sn=buf[start + 8],
            data_type=buf[start + 9],
            payload=buf[start + 10:start + 7 + data_len],
        )
        pos = start + frame_len


def build_v1_frame(channel_type: int, opcode: int, opcode_sn: int,
                   data_type: int, payload: bytes = b"",
                   *, need_response: bool = False, flag: bool = False) -> bytes:
    """Serialise a legacy frame (mirrors ``com.xiaomi.wearable.spp.b.x()``)."""
    header = (channel_type & 0x0F)
    if need_response:
        header |= 1 << 14
    if flag:
        header |= 1 << 15

    data_len = len(payload) + 3
    return (
        C.V1_FRAME_START
        + header.to_bytes(2, "little")
        + data_len.to_bytes(2, "little")
        + bytes([opcode, opcode_sn, data_type])
        + payload
        + bytes([C.V1_FRAME_END])
    )
