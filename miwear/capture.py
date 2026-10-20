"""Extract ATT bearer values from HCI captures (btsnoop / pcap).

The SAR frames live inside ATT PDUs, which live inside L2CAP, which live
inside HCI ACL packets.  This module peels those layers and hands back the
raw characteristic values in capture order so they can be fed to
:mod:`miwear.session`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable, Iterator

from . import constants as C

__all__ = ["AttValue", "read_btsnoop", "read_pcap", "extract_att_values",
           "open_capture"]

DIR_HOST_TO_DEVICE = 0
DIR_DEVICE_TO_HOST = 1

_DIR_NAMES = {DIR_HOST_TO_DEVICE: "MTU->DEV", DIR_DEVICE_TO_HOST: "DEV->MTU"}


class CaptureError(Exception):
    """Raised when a capture file cannot be parsed."""


@dataclass
class AttValue:
    """One ATT write/notification carrying an application payload."""

    timestamp_us: int
    direction: int
    handle: int
    value: bytes
    att_op: str

    @property
    def direction_name(self) -> str:
        return _DIR_NAMES.get(self.direction, f"dir{self.direction}")

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (f"<AttValue {self.direction_name} h=0x{self.handle:04x} "
                f"len={len(self.value)}>")


# ---------------------------------------------------------------------------
# Container formats
# ---------------------------------------------------------------------------

@dataclass
class _HciPacket:
    timestamp_us: int
    direction: int
    packet_type: int
    payload: bytes


def read_btsnoop(path: str) -> list[_HciPacket]:
    """Parse a btsnoop (HCI log) file."""
    with open(path, "rb") as fh:
        data = fh.read()
    if not data.startswith(b"btsnoop\x00"):
        raise CaptureError(f"{path} is not a btsnoop file")

    packets: list[_HciPacket] = []
    pos = 16
    end = len(data)
    while pos + 24 <= end:
        orig_len, incl_len, flags, _drops, timestamp = struct.unpack_from(
            ">IIIIq", data, pos)
        pos += 24
        body = data[pos:pos + incl_len]
        pos += incl_len
        if not body:
            continue
        packets.append(_HciPacket(
            timestamp_us=timestamp,
            direction=flags & 0x01,
            packet_type=body[0],
            payload=body[1:],
        ))
    return packets


_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",   # little-endian, microsecond
    b"\x4d\x3c\xb2\xa1": "<",   # little-endian, nanosecond
    b"\xa1\xb2\xc3\xd4": ">",   # big-endian, microsecond
    b"\xa1\xb2\x3c\x4d": ">",   # big-endian, nanosecond
}


def read_pcap(path: str) -> list[_HciPacket]:
    """Parse a pcap file carrying HCI H4 frames (link types 187 and 201)."""
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:4] not in _PCAP_MAGICS:
        raise CaptureError(
            f"{path} is not a classic pcap file "
            "(pcapng is not supported; convert with: editcap -F pcap in out)"
        )
    endian = _PCAP_MAGICS[data[:4]]
    link_type = struct.unpack_from(endian + "I", data, 20)[0]
    if link_type not in (C.DLT_BLUETOOTH_HCI_H4,
                         C.DLT_BLUETOOTH_HCI_H4_WITH_PHDR):
        raise CaptureError(
            f"unsupported pcap link type {link_type}; expected 187 or 201"
        )

    packets: list[_HciPacket] = []
    pos = 24
    end = len(data)
    while pos + 16 <= end:
        ts_sec, ts_frac, incl_len, _orig_len = struct.unpack_from(
            endian + "IIII", data, pos)
        pos += 16
        body = data[pos:pos + incl_len]
        pos += incl_len
        if not body:
            continue
        if link_type == C.DLT_BLUETOOTH_HCI_H4_WITH_PHDR:
            if len(body) < 5:
                continue
            direction = DIR_HOST_TO_DEVICE if body[0] == 0 else DIR_DEVICE_TO_HOST
            packets.append(_HciPacket(
                timestamp_us=ts_sec * 1_000_000 + ts_frac,
                direction=direction,
                packet_type=body[4],
                payload=body[5:],
            ))
        else:
            packets.append(_HciPacket(
                timestamp_us=ts_sec * 1_000_000 + ts_frac,
                direction=DIR_HOST_TO_DEVICE,
                packet_type=body[0],
                payload=body[1:],
            ))
    return packets


def open_capture(path: str) -> list[_HciPacket]:
    """Open a capture regardless of container format."""
    with open(path, "rb") as fh:
        head = fh.read(8)
    if head.startswith(b"btsnoop\x00"):
        return read_btsnoop(path)
    if head[:4] in _PCAP_MAGICS:
        return read_pcap(path)
    if head[:4] == b"\x0a\x0d\x0d\x0a":
        raise CaptureError("pcapng is not supported; convert to pcap first")
    raise CaptureError(f"unrecognised capture format: {path}")


# ---------------------------------------------------------------------------
# Layer peeling
# ---------------------------------------------------------------------------

def _l2cap_to_att(acl: bytes) -> bytes | None:
    """Return the ATT PDU inside an L2CAP frame, or ``None`` if not ATT."""
    if len(acl) < 4:
        return None
    l2cap_len, cid = struct.unpack_from("<HH", acl, 0)
    if cid != C.L2CAP_CID_ATT:
        return None
    return acl[4:4 + l2cap_len]


def _parse_att(pdu: bytes) -> tuple[str, int, bytes] | None:
    """Return ``(op name, handle, value)`` for value-bearing ATT PDUs."""
    if not pdu:
        return None
    op = pdu[0]
    name = C.ATT_OP_NAMES.get(op)
    if not name:
        return None
    if op in C.ATT_OPS_WITH_VALUE:
        if len(pdu) < 3:
            return None
        handle = struct.unpack_from("<H", pdu, 1)[0]
        return name, handle, pdu[3:]
    return None


def extract_att_values(packets: Iterable[_HciPacket], *,
                       direction: int | None = None,
                       handle: int | None = None) -> list[AttValue]:
    """Collect every value-bearing ATT PDU from *packets*.

    Parameters
    ----------
    direction:
        Keep only ``DIR_HOST_TO_DEVICE`` or ``DIR_DEVICE_TO_HOST``.
    handle:
        Keep only PDUs targeting this ATT attribute handle.
    """
    out: list[AttValue] = []
    for packet in packets:
        if direction is not None and packet.direction != direction:
            continue
        if packet.packet_type != C.HCI_ACLDATA_PKT:
            continue
        if len(packet.payload) < 4:
            continue

        data_len = struct.unpack_from("<H", packet.payload, 2)[0]
        acl = packet.payload[4:4 + data_len]
        pdu = _l2cap_to_att(acl)
        if pdu is None:
            continue

        parsed = _parse_att(pdu)
        if parsed is None:
            continue
        name, att_handle, value = parsed
        if not value:
            continue
        if handle is not None and att_handle != handle:
            continue

        out.append(AttValue(
            timestamp_us=packet.timestamp_us,
            direction=packet.direction,
            handle=att_handle,
            value=value,
            att_op=name,
        ))
    return out
