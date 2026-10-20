"""Recover a compilable ``.proto`` from a pile of captured protobuf payloads.

The APK ships **no** descriptors: ``protobuf-java-nano`` classes are compiled
to plain Java, so every payload the band sends is anonymous.  This module goes
the other way — give it a batch of payloads and it infers a schema that
``protoc`` accepts.

How the inference works
-----------------------
1. Every payload is parsed with the structural decoder in
   :mod:`miwear.protobuf` (reused, not re-implemented) and re-encoded to make
   sure the parse was unambiguous.  Payloads that fail are reported, never
   guessed at.
2. Observations are **aggregated by field number** across the whole batch:
   "field 1: 412 varint samples", "field 3: 87 length-delimited samples".
   Wire-type conflicts are resolved by majority and flagged in a comment.
3. A length-delimited field becomes a nested message when *every* non-empty
   sample parses strictly as a message and the samples do not look like text.
   The same rule is applied at every depth, so recursion is automatic.
4. A field that occurs more than once inside one message is ``repeated``.
   Unknown fields get synthetic ``field_<n>`` names; ``--names`` overrides.
5. Two messages with an identical structural signature share one declaration,
   which keeps the output small and makes self-similar shapes terminate.

Quick start
-----------
>>> from miwear.protobuf import encode_field_bytes, encode_field_varint
>>> payload = (encode_field_varint(1, 7)
...            + encode_field_bytes(2, b"user-42")
...            + encode_field_bytes(3, encode_field_varint(1, 1)))
>>> text = generate([payload, payload], message_name="Auth")
>>> 'syntax = "proto3";' in text
True
>>> "int32 field_1 = 1;" in text
True
>>> "string field_2 = 2;" in text
True
>>> "AuthField3 field_3 = 3;" in text
True

Command line::

    python -m miwear.protogen payload.hex -o schema.proto
    cat session.hex | python -m miwear.protogen - -o schema.proto
    python -m miwear.protogen a.hex b.hex --json
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import struct
import sys
from dataclasses import dataclass, field as dc_field
from typing import Callable, Iterable, Iterator, Sequence

from . import __version__
from .protobuf import (
    WIRE_BYTES,
    WIRE_FIXED32,
    WIRE_FIXED64,
    WIRE_VARINT,
    ProtoError,
    ProtoField,
    decode as proto_decode,
    encode_field_bytes,
    encode_field_varint,
    encode_varint,
)

__all__ = [
    "ProtoGenError",
    "Field",
    "Message",
    "infer_schema",
    "render_proto",
    "generate",
    "schema_to_dict",
    "load_payloads",
    "parse_hex",
    "main",
]

#: ``protoc`` rejects field numbers in this range.
RESERVED_FIELD_MIN = 19000
RESERVED_FIELD_MAX = 19999

#: Largest legal field number (2**29 - 1).
MAX_FIELD_NUMBER = (1 << 29) - 1

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_NON_IDENT = re.compile(r"[^A-Za-z0-9_]")
_HEX_JUNK = re.compile(r"[\s:_-]+")


class ProtoGenError(ValueError):
    """Raised when no schema can be inferred from the supplied input."""


# ---------------------------------------------------------------------------
# Strict decoding helpers
# ---------------------------------------------------------------------------

def _tag(number: int, wire: int) -> bytes:
    return encode_varint((number << 3) | wire)


def _reencode(fields: list[ProtoField]) -> bytes:
    """Serialise decoded fields back to bytes (used as a parse self-check)."""
    out = bytearray()
    for item in fields:
        if item.wire == WIRE_VARINT:
            out += encode_field_varint(item.number, item.value)
        elif item.wire == WIRE_FIXED64:
            out += _tag(item.number, WIRE_FIXED64) + struct.pack("<Q", item.value)
        elif item.wire == WIRE_FIXED32:
            out += _tag(item.number, WIRE_FIXED32) + struct.pack("<I", item.value)
        elif item.wire == WIRE_BYTES:
            out += encode_field_bytes(item.number, item.raw)
        else:                                   # pragma: no cover - decode guards
            return b"\x00"                      # sentinel: never matches
    return bytes(out)


def parse_message(buf: bytes) -> list[ProtoField] | None:
    """Parse *buf* as one protobuf message, or return ``None``.

    Stricter than :func:`miwear.protobuf.decode`: the buffer must consume
    exactly, every field number must be legal, and the round-trip re-encode
    must reproduce the original bytes.  That last check is what rejects a
    string such as ``"\\x01"`` that happens to *parse* as a field.
    """
    if not buf:
        return None
    try:
        fields = proto_decode(buf)
    except ProtoError:
        return None
    if not fields:
        return None
    for item in fields:
        if not 1 <= item.number <= MAX_FIELD_NUMBER:
            return None
    try:
        rebuilt = _reencode(fields)
    except (struct.error, ValueError):          # pragma: no cover - defensive
        return None
    if rebuilt != bytes(buf):
        return None
    return fields


def is_printable_text(buf: bytes) -> bool:
    """True when *buf* is non-empty, valid UTF-8 and printable."""
    if not buf:
        return False
    try:
        text = buf.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return bool(text) and text.isprintable()


# ---------------------------------------------------------------------------
# Schema model
# ---------------------------------------------------------------------------

@dataclass
class Field:
    """One field number, aggregated across every payload that contained it."""

    number: int
    name: str = ""
    wire_counts: dict[int, int] = dc_field(default_factory=dict)
    values: list[int] = dc_field(default_factory=list)
    raws: list[bytes] = dc_field(default_factory=list)
    repeated: bool = False
    #: Scalar type name, or ``""`` when :attr:`child` carries the type.
    proto_type: str = "bytes"
    child: "Message | None" = None
    conflicts: int = 0

    # -- collection --------------------------------------------------------

    @property
    def samples(self) -> int:
        return sum(self.wire_counts.values())

    @property
    def wire(self) -> int:
        """Dominant wire type (majority vote; ties go to the lowest code)."""
        if not self.wire_counts:
            return WIRE_BYTES
        return max(sorted(self.wire_counts), key=lambda w: self.wire_counts[w])

    @property
    def type_name(self) -> str:
        """The ``.proto`` type, following aliases for merged messages."""
        if self.child is None:
            return self.proto_type
        return self.child.declared_name

    def add(self, item: ProtoField) -> None:
        self.wire_counts[item.wire] = self.wire_counts.get(item.wire, 0) + 1
        if item.wire == WIRE_BYTES:
            self.raws.append(bytes(item.raw))
        else:
            self.values.append(int(item.value))

    @property
    def nonempty_raws(self) -> list[bytes]:
        return [raw for raw in self.raws if raw]

    # -- inference ---------------------------------------------------------

    def resolve(self, *, use_bools: bool, max_depth: int, depth: int) -> None:
        """Pick the best ``.proto`` type for this field, recursing if needed."""
        self.conflicts = max(0, len(self.wire_counts) - 1)
        wire = self.wire

        if wire != WIRE_BYTES:
            self.proto_type = _scalar_type(wire, self.values, use_bools)
            return

        nonempty = self.nonempty_raws
        if not nonempty:
            self.proto_type = "bytes"
            return

        # Text wins over "nested message": a message built only from printable
        # bytes is vanishingly unlikely, whereas a name/id string is common.
        if all(is_printable_text(raw) for raw in nonempty):
            self.proto_type = "string"
            return

        if depth >= max_depth:
            self.proto_type = "bytes"
            return

        parsed = [parse_message(raw) for raw in nonempty]
        if any(item is None for item in parsed):
            self.proto_type = "bytes"
            return

        self.child = Message(depth=depth + 1)
        self.child.absorb_parsed(parsed)         # type: ignore[arg-type]
        self.proto_type = ""


def _scalar_type(wire: int, values: list[int], use_bools: bool) -> str:
    if wire == WIRE_FIXED64:
        return "fixed64"
    if wire == WIRE_FIXED32:
        return "fixed32"
    if wire != WIRE_VARINT:                     # pragma: no cover - defensive
        return "bytes"

    if use_bools and values and all(value in (0, 1) for value in values):
        return "bool"
    biggest = max(values) if values else 0
    if biggest <= 0x7FFFFFFF:
        return "int32"
    if biggest <= 0x7FFFFFFFFFFFFFFF:
        return "int64"
    return "uint64"


@dataclass
class Message:
    """One inferred message definition."""

    depth: int = 0
    name: str = ""
    fields: dict[int, Field] = dc_field(default_factory=dict)
    payloads: int = 0
    #: Set by :func:`_dedupe` when this node shares a declaration.
    alias: "Message | None" = None

    # -- collection --------------------------------------------------------

    def absorb_parsed(self, parsed: list[list[ProtoField]]) -> None:
        """Fold already-parsed payloads of this message into the model."""
        for fields in parsed:
            self.payloads += 1
            seen: dict[int, int] = {}
            for item in fields:
                seen[item.number] = seen.get(item.number, 0) + 1
                node = self.fields.get(item.number)
                if node is None:
                    node = self.fields[item.number] = Field(item.number)
                node.add(item)
            for number, count in seen.items():
                if count > 1:
                    self.fields[number].repeated = True

    def resolve(self, *, use_bools: bool, max_depth: int) -> None:
        """Resolve every field breadth first, recursing into nested messages."""
        pending: list[Message] = [self]
        seen: set[int] = set()
        while pending:
            message = pending.pop(0)
            if id(message) in seen:              # pragma: no cover - defensive
                continue
            seen.add(id(message))
            for node in message.ordered_fields():
                node.resolve(use_bools=use_bools, max_depth=max_depth,
                             depth=message.depth)
                if node.child is not None:
                    pending.append(node.child)

    # -- views -------------------------------------------------------------

    def ordered_fields(self) -> list[Field]:
        return [self.fields[number] for number in sorted(self.fields)]

    @property
    def declared_name(self) -> str:
        """Name of the message that actually gets a declaration."""
        return self.alias.name if self.alias is not None else self.name

    def walk(self) -> Iterator["Message"]:
        """Yield this message and every nested one, breadth first."""
        queue: list[Message] = [self]
        seen: set[int] = set()
        while queue:
            message = queue.pop(0)
            if id(message) in seen:              # pragma: no cover - defensive
                continue
            seen.add(id(message))
            yield message
            for node in message.ordered_fields():
                if node.child is not None:
                    queue.append(node.child)

    def declarations(self) -> list["Message"]:
        """Every message that needs a ``message`` block, in stable order."""
        return [m for m in self.walk() if m.alias is None]

    def describe(self) -> dict:
        return {
            "payloads": self.payloads,
            "fields": [
                {
                    "number": node.number,
                    "name": node.name,
                    "type": node.type_name,
                    "wire": node.wire,
                    "samples": node.samples,
                    "repeated": node.repeated,
                    "nested": node.child is not None,
                    "wire_conflicts": node.conflicts,
                    "reserved_number": (RESERVED_FIELD_MIN
                                        <= node.number <= RESERVED_FIELD_MAX),
                }
                for node in self.ordered_fields()
            ],
        }


def _raw_signature(field: Field) -> tuple:
    """Signature component for one field: its child's shape, or its type."""
    if field.child is not None:
        return tuple(
            (node.number, node.wire, node.repeated, _raw_signature(node))
            for node in field.child.ordered_fields()
        )
    return (field.proto_type,)


def _signature(message: Message) -> tuple:
    return tuple(
        (node.number, node.wire, node.repeated, _raw_signature(node))
        for node in message.ordered_fields()
    )


# ---------------------------------------------------------------------------
# Naming
# ---------------------------------------------------------------------------

def _pascal(value: str) -> str:
    parts = [part for part in _NON_IDENT.split(value) if part]
    out = "".join(part[:1].upper() + part[1:] for part in parts) or "Message"
    if not _IDENT.match(out):
        out = "M" + out
    return out


def _snake(value: str) -> str:
    """Convert an arbitrary label into a legal ``snake_case`` field name."""
    text = _NON_IDENT.sub("_", value.strip())
    # Split camelCase / PascalCase and acronym boundaries before lowering.
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", text)
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", text)
    text = re.sub(r"_+", "_", text).strip("_").lower()
    if not text:
        return "field"
    if not _IDENT.match(text):
        text = "_" + text
    return text


NameHint = Callable[[Message, Field], "str | None"]


def _assign_names(root: Message, *, message_name: str,
                  hint: NameHint | None = None) -> None:
    """Give every message and field a unique, legal identifier."""
    used: dict[str, int] = {}

    def unique(base: str) -> str:
        base = base or "Message"
        count = used.get(base, 0)
        used[base] = count + 1
        return base if count == 0 else f"{base}{count + 1}"

    root.name = unique(_pascal(message_name))

    # Messages first, so field hints keyed on the parent name resolve.
    queue: list[Message] = [root]
    while queue:
        message = queue.pop(0)
        for node in message.ordered_fields():
            if node.child is None:
                continue
            child_hint = hint(message, node) if hint else None
            base = _pascal(child_hint) if child_hint else f"{message.name}Field{node.number}"
            node.child.name = unique(base)
            queue.append(node.child)

    for message in root.walk():
        if message.alias is not None:            # names already assigned
            continue
        for node in message.ordered_fields():
            field_hint = hint(message, node) if hint else None
            node.name = _snake(field_hint) if field_hint else f"field_{node.number}"


def _dedupe(root: Message) -> None:
    """Point structurally identical messages at the first declaration."""
    representatives: dict[tuple, Message] = {}
    for message in root.walk():
        signature = _signature(message)
        first = representatives.get(signature)
        if first is None:
            representatives[signature] = message
        elif first is not message:
            message.alias = first


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_proto(root: Message, *,
                 package: str | None = "miwear.gen",
                 header: str | None = None) -> str:
    """Render the inferred schema as ``.proto`` source text."""
    _dedupe(root)

    lines: list[str] = [
        "// Generated by miwear.protogen - do not edit by hand.",
        f"// miwear {__version__}; schema inferred from "
        f"{root.payloads} payload(s).",
    ]
    if header:
        for text in header.splitlines():
            lines.append(f"// {text}")
    lines.extend([
        "//",
        "// Field names are synthetic (field_<n>) unless --names supplied them.",
        "// Types are inferred; verify against a second capture before trusting.",
        "",
        'syntax = "proto3";',
        "",
    ])
    if package:
        lines.extend([f"package {package};", ""])

    for message in root.declarations():
        lines.append(f"message {message.declared_name} {{")
        if message.payloads:
            lines.append(f"  // seen in {message.payloads} payload(s)")
        if not message.fields:
            lines.append("  // no fields observed")
        for node in message.ordered_fields():
            lines.extend(_render_field(node))
        lines.append("}")
        lines.append("")

    return "\n".join(lines).rstrip("\n") + "\n"


def _render_field(node: Field) -> list[str]:
    label = "repeated " if node.repeated else ""
    detail = f"{node.samples} sample(s), wire {node.wire}"
    if node.conflicts:
        detail += f", {node.conflicts} conflicting wire type(s)"
    if RESERVED_FIELD_MIN <= node.number <= RESERVED_FIELD_MAX:
        detail += " - RESERVED number, protoc will reject this"
    return [
        f"  // {detail}",
        f"  {label}{node.type_name} {node.name} = {node.number};",
    ]


def schema_to_dict(root: Message) -> dict:
    """Machine readable summary of the inferred schema (for ``--json``)."""
    _dedupe(root)
    return {
        "payloads": root.payloads,
        "messages": [
            dict(name=message.declared_name, **message.describe())
            for message in root.declarations()
        ],
    }


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def infer_schema(payloads: Iterable[bytes], *,
                 message_name: str = "Payload",
                 max_depth: int = 8,
                 use_bools: bool = False,
                 name_hints: dict[str, str] | None = None) -> Message:
    """Infer a :class:`Message` tree from a batch of payloads."""
    buffers = [bytes(item) for item in payloads]
    if not buffers:
        raise ProtoGenError("no payloads supplied - nothing to infer")

    parsed: list[list[ProtoField]] = []
    for index, buf in enumerate(buffers):
        fields = parse_message(buf)
        if fields is None:
            preview = buf[:16].hex() + ("..." if len(buf) > 16 else "")
            raise ProtoGenError(
                f"payload #{index} is not valid protobuf wire data "
                f"({len(buf)} bytes: {preview})")
        parsed.append(fields)

    root = Message(depth=0)
    root.absorb_parsed(parsed)
    root.resolve(use_bools=use_bools, max_depth=max(0, max_depth))

    hints = {str(key): str(value) for key, value in (name_hints or {}).items()}

    def lookup(message: Message, node: Field) -> str | None:
        for key in (f"{message.name}.{node.number}", f"*.{node.number}",
                    str(node.number)):
            if key in hints:
                return hints[key]
        return None

    _assign_names(root, message_name=message_name, hint=lookup)
    return root


def generate(payloads: Iterable[bytes], *, message_name: str = "Payload",
             package: str | None = "miwear.gen", max_depth: int = 8,
             use_bools: bool = False,
             name_hints: dict[str, str] | None = None,
             header: str | None = None) -> str:
    """All-in-one: payloads in, ``.proto`` source out."""
    root = infer_schema(payloads, message_name=message_name, max_depth=max_depth,
                        use_bools=use_bools, name_hints=name_hints)
    return render_proto(root, package=package, header=header)


# ---------------------------------------------------------------------------
# Input plumbing
# ---------------------------------------------------------------------------

def parse_hex(value: str) -> bytes:
    """Parse a hex blob, tolerating whitespace, colons, dashes and ``0x``."""
    cleaned = _HEX_JUNK.sub("", value.strip())
    if cleaned[:2].lower() == "0x":
        cleaned = cleaned[2:]
    if not cleaned:
        raise ProtoGenError("empty hex string")
    if len(cleaned) % 2:
        raise ProtoGenError(
            f"hex string has an odd number of digits ({len(cleaned)}); "
            "each byte needs two")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ProtoGenError(f"invalid hex string: {exc}") from exc


def _payloads_from_text(text: str, origin: str) -> Iterator[bytes]:
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//")):
            continue
        try:
            yield parse_hex(stripped)
        except ProtoGenError as exc:
            raise ProtoGenError(f"{origin}:{lineno}: {exc}") from exc


def load_payloads(sources: Sequence[str]) -> list[bytes]:
    """Turn CLI arguments into payloads.

    ``-`` reads standard input; an existing path is read as a file with one
    hex payload per line; anything else must be a hex string.
    """
    payloads: list[bytes] = []
    for source in sources:
        if source == "-":
            payloads.extend(_payloads_from_text(sys.stdin.read(), "<stdin>"))
            continue
        path = pathlib.Path(source)
        try:
            is_file = path.is_file()
        except OSError:                          # pragma: no cover - odd path
            is_file = False
        if is_file:
            payloads.extend(_payloads_from_text(
                path.read_text(encoding="utf-8", errors="replace"), str(path)))
        else:
            try:
                payloads.append(parse_hex(source))
            except ProtoGenError as exc:
                raise ProtoGenError(
                    f"{source!r} is neither a readable file nor a hex payload "
                    f"({exc})") from exc
    return payloads


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="miwear-protogen",
        description="Infer a compilable .proto from captured protobuf payloads.",
    )
    parser.add_argument("sources", nargs="+", metavar="HEX|FILE",
                        help="hex payload, file of hex lines, or - for stdin")
    parser.add_argument("--name", default="Payload",
                        help="name of the root message (default: Payload)")
    parser.add_argument("--package", default="miwear.gen",
                        help="proto package (empty string to omit)")
    parser.add_argument("--max-depth", type=int, default=8,
                        help="how deep to recurse into nested messages")
    parser.add_argument("--bools", action="store_true",
                        help="type all-0/1 varint fields as bool")
    parser.add_argument("--names", metavar="JSON",
                        help="JSON mapping 'Message.<n>' or '*.<n>' to a name")
    parser.add_argument("--header", help="extra comment text for the header")
    parser.add_argument("-o", "--out", metavar="FILE",
                        help="write the .proto here instead of stdout")
    parser.add_argument("--json", action="store_true",
                        help="print a schema summary as JSON instead")
    parser.add_argument("--strict", action="store_true",
                        help="abort on the first invalid payload")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Console entry point (``miwear-protogen``); wired into ``miwear`` too."""
    parser = build_parser()
    args = parser.parse_args(argv)

    hints: dict[str, str] = {}
    if args.names:
        try:
            hints = json.loads(pathlib.Path(args.names).read_text("utf-8"))
        except (OSError, ValueError) as exc:
            print(f"error: cannot read --names {args.names}: {exc}",
                  file=sys.stderr)
            return 2
        if not isinstance(hints, dict):
            print("error: --names must contain a JSON object", file=sys.stderr)
            return 2

    try:
        payloads = load_payloads(list(args.sources))
    except (ProtoGenError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not payloads:
        print("error: no payloads found in the supplied input", file=sys.stderr)
        return 2

    good: list[bytes] = []
    skipped = 0
    for index, payload in enumerate(payloads):
        if parse_message(payload) is None:
            skipped += 1
            print(f"warning: payload #{index} is not valid protobuf; skipped "
                  f"({payload[:12].hex()}...)", file=sys.stderr)
            if args.strict:
                return 2
            continue
        good.append(payload)

    if not good:
        print("error: none of the payloads are valid protobuf", file=sys.stderr)
        return 2

    try:
        root = infer_schema(good, message_name=args.name,
                            max_depth=args.max_depth, use_bools=args.bools,
                            name_hints=hints)
    except ProtoGenError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        text = json.dumps(schema_to_dict(root), ensure_ascii=False, indent=2)
    else:
        text = render_proto(root, package=args.package or None,
                            header=args.header)

    if args.out:
        pathlib.Path(args.out).write_text(text, encoding="utf-8")
        print(f"# wrote {args.out} "
              f"({len(text.splitlines())} lines, {len(good)} payload(s), "
              f"{skipped} skipped)", file=sys.stderr)
    else:
        sys.stdout.write(text)
        if skipped:
            print(f"\n# {skipped} invalid payload(s) skipped", file=sys.stderr)
        elif not text.endswith("\n"):            # pragma: no cover
            sys.stdout.write("\n")
    return 0


if __name__ == "__main__":                      # pragma: no cover
    raise SystemExit(main())
