"""Human readable rendering of decoded frames."""

from __future__ import annotations

from .protobuf import to_json
from .session import DecodedFrame

__all__ = ["format_frame", "format_frames"]


def format_frame(entry: DecodedFrame, *, verbose: bool = True) -> str:
    """Render one decoded frame as text."""
    frame = entry.frame
    crc_mark = "OK " if frame.crc_ok else "BAD"
    lines = [
        f"[@{frame.offset:04x}] {entry.direction:<9} "
        f"{frame.type_name:<4} seq={frame.seq:<3} "
        f"len={frame.data_length:<5} crc={frame.crc:04x}({crc_mark})"
        + (f" frx={frame.frx}" if frame.frx else "")
    ]

    if not verbose:
        lines.append(f"    payload: {frame.payload.hex()}")
        return "\n".join(lines)

    if entry.cmd is not None:
        lines.append(f"    cmd: {entry.cmd['cmd_name']}")
        for cfg in entry.cmd["config"]:
            extra = cfg.get("u16", cfg.get("version", cfg.get("text", "")))
            lines.append(
                f"    - {cfg['name']:<24} len={cfg['len']:<2} "
                f"value={cfg['value']} {extra}"
            )
        if "trailing" in entry.cmd:
            lines.append(f"    - trailing {entry.cmd['trailing']}")

    elif entry.l2_channel is not None:
        lines.append(
            f"    L2 channel={entry.l2_channel}({entry.l2_channel_name}) "
            f"opcode={entry.l2_opcode}({entry.l2_opcode_name}) "
            f"dataLen={len(entry.l2_payload)}"
        )
        lines.append(f"    data: {entry.l2_payload.hex()}")

        if entry.is_encrypted:
            lines.append("    payload is encrypted (opcode=2) — "
                         "use `miwear decrypt` with the session key")
        elif entry.proto_fields:
            lines.append(f"    proto: {to_json(entry.proto_fields)}")
        elif entry.proto_error:
            lines.append(f"    proto: <not protobuf> ({entry.proto_error})")

    elif frame.payload:
        lines.append(f"    payload: {frame.payload.hex()}")

    return "\n".join(lines)


def format_frames(entries: list[DecodedFrame], *, verbose: bool = True) -> str:
    """Render a list of frames, one block each."""
    return "\n".join(format_frame(e, verbose=verbose) for e in entries)
