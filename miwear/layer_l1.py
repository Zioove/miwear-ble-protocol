"""L1 SAR framing: parse and build 8-byte-header frames.

Wire format (all little-endian)::

    offset  size  field
    0       2     magic          always A5 A5
    2       1     type | frx     bits 0-3 = type, bit 4 = frx, bits 5-7 reserved
    3       1     seq            8-bit sequence number, wraps at 256
    4       2     dataLength     payload byte count
    6       2     crc            CRC-16/ARC over payload, 0 when payload is empty
    8       n     payload
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterator

from . import constants as C
from .crc import crc16_arc

__all__ = ["L1Frame", "iter_frames", "build_frame", "build_ack", "build_cmd",
           "build_data"]


@dataclass
class L1Frame:
    """One decoded L1 SAR frame."""

    offset: int
    type_raw: int
    seq: int
    data_length: int
    crc: int
    crc_ok: bool
    frx: int = 0
    payload: bytes = b""

    @property
    def type_name(self) -> str:
        """Human readable frame type (``NAK``/``ACK``/``CMD``/``DATA``)."""
        return C.TYPE_NAMES.get(self.type_raw, f"unknown({self.type_raw})")

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (f"<L1Frame {self.type_name} seq={self.seq} "
                f"len={self.data_length} crc_ok={self.crc_ok}>")


@dataclass
class TruncatedFrame:
    """Returned when the buffer ends in the middle of a frame."""

    offset: int
    type_raw: int
    seq: int
    data_length: int
    missing: int

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (f"<TruncatedFrame seq={self.seq} need={self.data_length} "
                f"missing={self.missing}>")


def iter_frames(buf: bytes) -> Iterator[L1Frame | TruncatedFrame]:
    """Walk *buf* and yield every SAR frame found.

    Frames that fail the CRC are still yielded with ``crc_ok=False``; the
    caller decides whether to resynchronise (``TransportL0`` drops one byte
    and re-searches for the magic on CRC failure, which is mirrored by the
    ``offset`` the next frame reports).
    """
    pos = 0
    total = len(buf)
    while pos + C.L1_HEADER_SIZE <= total:
        magic = struct.unpack_from("<H", buf, pos)[0]
        if magic != C.L1_MAGIC:
            pos += 1
            continue

        flags = buf[pos + 2]
        frame_type = flags & 0x0F
        frx = (flags >> 4) & 0x01
        seq = buf[pos + 3]
        data_len = struct.unpack_from("<H", buf, pos + 4)[0]
        crc = struct.unpack_from("<H", buf, pos + 6)[0]
        end = pos + C.L1_HEADER_SIZE + data_len

        if end > total:
            yield TruncatedFrame(
                offset=pos,
                type_raw=frame_type,
                seq=seq,
                data_length=data_len,
                missing=end - total,
            )
            return

        payload = buf[pos + C.L1_HEADER_SIZE:end]
        expected = crc16_arc(payload)
        yield L1Frame(
            offset=pos,
            type_raw=frame_type,
            seq=seq,
            data_length=data_len,
            crc=crc,
            crc_ok=(expected == crc),
            frx=frx,
            payload=payload,
        )
        pos = end


def build_frame(frame_type: int, seq: int, payload: bytes = b"",
                frx: int = 0) -> bytes:
    """Serialise a single L1 frame."""
    if not 0 <= frame_type <= 0x0F:
        raise ValueError("frame type must fit in 4 bits")
    if not 0 <= seq <= 0xFF:
        raise ValueError("seq must fit in one byte")
    flags = ((frx & 1) << 4) | (frame_type & 0x0F)
    header = struct.pack("<HBBHH", C.L1_MAGIC, flags, seq, len(payload),
                         crc16_arc(payload))
    return header + payload


def build_ack(seq: int, ack: bool = True, force: bool = False) -> bytes:
    """Build an ACK (``ack=True``) or NAK (``ack=False``) frame.

    Mirrors ``ACKPacket``: the ``force`` flag is encoded in ``frx``.
    """
    return build_frame(C.TYPE_ACK if ack else C.TYPE_NAK, seq, b"",
                       frx=1 if force else 0)


def build_cmd(cmd: int, config: bytes = b"", seq: int = 0) -> bytes:
    """Build a CMD frame.  *config* is the TLV block following the command byte."""
    return build_frame(C.TYPE_CMD, seq, bytes([cmd]) + config)


def build_data(l2_packet: bytes, seq: int = 0) -> bytes:
    """Build a DATA frame from an already-serialised L2 packet."""
    return build_frame(C.TYPE_DATA, seq, l2_packet)


def default_start_config(version: tuple[int, int, int] = (1, 0, 0),
                         mps: int = C.SAR_DEFAULT_MPS,
                         tx_win: int = C.SAR_DEFAULT_TX_WIN,
                         send_timeout: int = C.SAR_SEND_TIMEOUT_MS) -> bytes:
    """Reproduce ``CMDPacket.Companion.createCmdData()`` — the 21-byte TLV block.

    >>> default_start_config().hex()
    '01030001000002020000fc03020020000402001027'
    """
    major, minor, build = version
    return (
        bytes([C.CONFIG_VERSION]) + (3).to_bytes(2, "little")
        + bytes([major, minor, build])
        + bytes([C.CONFIG_MPS]) + (2).to_bytes(2, "little")
        + mps.to_bytes(2, "little")
        + bytes([C.CONFIG_TX_WIN]) + (2).to_bytes(2, "little")
        + tx_win.to_bytes(2, "little")
        + bytes([C.CONFIG_SEND_TIMEOUT]) + (2).to_bytes(2, "little")
        + send_timeout.to_bytes(2, "little")
    )
