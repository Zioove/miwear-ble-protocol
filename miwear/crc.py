"""Checksums used by the miwear transport layers.

Two different CRC families show up:

``crc16_arc``
    L1 SAR frame payload checksum.  The APK hard-codes the lookup table in
    ``com.xiaomi.wearable.utils.CRCUtil.TABLE_16`` as
    ``{0, 49345, 49537, 320, 49921, 960, 640, 49729, ...}`` which is
    exactly CRC-16/ARC (reflected 0xA001 polynomial, init 0, no final xor).

``crc32``
    Optional trailing integrity check on legacy V1 channels when the
    characteristic property is enabled (``e84.g0()`` returns true).
    This is plain CRC-32/IEEE, identical to ``zlib.crc32``.
"""

from __future__ import annotations

import binascii

__all__ = ["crc16_arc", "crc32", "CRC16_TABLE"]


def _build_crc16_table() -> tuple[int, ...]:
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
        table.append(crc)
    return tuple(table)


#: Reflected CRC-16/ARC lookup table.
CRC16_TABLE: tuple[int, ...] = _build_crc16_table()


def crc16_arc(data: bytes) -> int:
    """Return the CRC-16/ARC of *data*.

    >>> hex(crc16_arc(b"123456789"))
    '0xbb3d'
    """
    crc = 0
    table = CRC16_TABLE
    for byte in data:
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc & 0xFFFF


def crc32(data: bytes) -> int:
    """Return the CRC-32/IEEE of *data* (same as ``zlib.crc32``)."""
    return binascii.crc32(data) & 0xFFFFFFFF
