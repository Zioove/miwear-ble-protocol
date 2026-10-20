"""Minimal protobuf wire-format reader/writer.

The miwear payloads are produced by ``protobuf-java-nano``, which uses the
standard protobuf wire format (varint, length-delimited, fixed32, fixed64)
without descriptors.  Because no ``.proto`` files ship with the APK, decoding
works structurally: we recover field numbers and values and let the caller
map them to meaning using the decompiled sources.

This module is intentionally dependency-free and schema-less.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

__all__ = ["WireType", "ProtoField", "decode", "encode_varint",
           "encode_field_varint", "encode_field_bytes", "to_json"]

WIRE_VARINT = 0
WIRE_FIXED64 = 1
WIRE_BYTES = 2
WIRE_FIXED32 = 5

_WIRE_NAMES = {
    WIRE_VARINT: "varint",
    WIRE_FIXED64: "fixed64",
    WIRE_BYTES: "bytes",
    WIRE_FIXED32: "fixed32",
}


class WireType(int):
    """IntEnum-ish marker kept as a plain int for zero-dependency clarity."""


@dataclass
class ProtoField:
    """A single decoded protobuf field."""

    number: int
    wire: int
    value: Any
    #: Present for length-delimited fields that parsed as a nested message.
    message: list["ProtoField"] | None = None
    #: Present for length-delimited fields that decoded as printable UTF-8.
    text: str | None = None
    raw: bytes = b""

    @property
    def wire_name(self) -> str:
        return _WIRE_NAMES.get(self.wire, f"unknown({self.wire})")

    def as_dict(self) -> dict:
        out: dict = {"field": self.number, "wire": self.wire_name}
        if self.wire == WIRE_BYTES:
            out["len"] = len(self.raw)
            out["hex"] = self.raw.hex()
            if self.text is not None:
                out["text"] = self.text
            if self.message is not None:
                out["message"] = [f.as_dict() for f in self.message]
        else:
            out["value"] = self.value
        return out

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        if self.wire == WIRE_BYTES:
            return f"<field {self.number} bytes len={len(self.raw)}>"
        return f"<field {self.number} {self.wire_name}={self.value}>"


class ProtoError(ValueError):
    """Raised when the buffer is not valid protobuf wire data."""


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    shift = 0
    value = 0
    while True:
        if pos >= len(buf):
            raise ProtoError("varint overruns buffer")
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift > 63:
            raise ProtoError("varint longer than 10 bytes")


def decode(buf: bytes, *, max_depth: int = 6, _depth: int = 0) -> list[ProtoField]:
    """Decode *buf* into a flat list of :class:`ProtoField`.

    Length-delimited fields are heuristically re-parsed as nested messages
    and/or annotated with ``text`` when the bytes are printable UTF-8.
    Raises :class:`ProtoError` if the buffer is not valid wire format.
    """
    fields: list[ProtoField] = []
    pos = 0
    total = len(buf)

    while pos < total:
        key, pos = _read_varint(buf, pos)
        number = key >> 3
        wire = key & 0x07
        if number == 0:
            raise ProtoError("field number 0 is invalid")

        if wire == WIRE_VARINT:
            value, pos = _read_varint(buf, pos)
            fields.append(ProtoField(number, wire, value))

        elif wire == WIRE_FIXED64:
            if pos + 8 > total:
                raise ProtoError("fixed64 overruns buffer")
            value = int.from_bytes(buf[pos:pos + 8], "little")
            pos += 8
            fields.append(ProtoField(number, wire, value))

        elif wire == WIRE_BYTES:
            length, pos = _read_varint(buf, pos)
            if pos + length > total:
                raise ProtoError("length-delimited field overruns buffer")
            raw = buf[pos:pos + length]
            pos += length
            item = ProtoField(number, wire, None, raw=raw)

            if _depth < max_depth:
                try:
                    nested = decode(raw, max_depth=max_depth, _depth=_depth + 1)
                except ProtoError:
                    nested = None
                # Empty or single-trivial-field parses are usually plain strings.
                if nested and not (len(nested) == 1 and nested[0].wire == WIRE_VARINT
                                   and len(raw) < 3):
                    item.message = nested

            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = None
            if text is not None and text.isprintable() and text:
                item.text = text

            fields.append(item)

        elif wire == WIRE_FIXED32:
            if pos + 4 > total:
                raise ProtoError("fixed32 overruns buffer")
            value = int.from_bytes(buf[pos:pos + 4], "little")
            pos += 4
            fields.append(ProtoField(number, wire, value))

        else:
            raise ProtoError(f"unsupported wire type {wire}")

    return fields


def encode_varint(value: int) -> bytes:
    """Encode a non-negative integer as a protobuf varint."""
    if value < 0:
        value &= 0xFFFFFFFFFFFFFFFF
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _tag(number: int, wire: int) -> bytes:
    return encode_varint((number << 3) | wire)


def encode_field_varint(number: int, value: int) -> bytes:
    """Encode a varint field."""
    return _tag(number, WIRE_VARINT) + encode_varint(value)


def encode_field_bytes(number: int, payload: bytes) -> bytes:
    """Encode a length-delimited field."""
    return _tag(number, WIRE_BYTES) + encode_varint(len(payload)) + payload


def to_json(fields: list[ProtoField], *, indent: int | None = None) -> str:
    """Render decoded fields as JSON for logging."""
    return json.dumps([f.as_dict() for f in fields], ensure_ascii=False,
                      indent=indent)
