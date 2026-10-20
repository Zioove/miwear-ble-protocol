"""Command line interface for the miwear BLE protocol toolkit.

Run ``python -m miwear --help`` (or the ``miwear`` console script) for the
full command list.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from . import constants as C
from .capture import (
    CaptureError,
    DIR_DEVICE_TO_HOST,
    DIR_HOST_TO_DEVICE,
    extract_att_values,
    open_capture,
)
from .crypto import aes_ctr_crypt, build_v1_nonce, decrypt_v2_payload, derive_v2_keys
from .format import format_frames
from .layer_l1 import build_frame, default_start_config, iter_frames
from .legacy_v1 import iter_v1_frames
from .protobuf import decode as proto_decode, to_json
from .session import decode_att_values, decode_stream, summarise

_DIR_CHOICES = {
    "host2dev": DIR_HOST_TO_DEVICE,
    "dev2host": DIR_DEVICE_TO_HOST,
}


class HexError(ValueError):
    """Raised when a user supplied hex string cannot be parsed."""


def _read_hex(value: str) -> bytes:
    cleaned = "".join(value.split())          # drop all whitespace/newlines
    cleaned = cleaned.replace(":", "").replace("-", "").replace("_", "")
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) % 2:
        raise HexError(
            f"hex string has an odd number of digits ({len(cleaned)}); "
            "each byte needs two")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise HexError(f"invalid hex string: {exc}") from exc


#: argparse ``type`` for hex arguments — reports cleanly instead of a traceback.
def hex_arg(value: str) -> str:
    _read_hex(value)          # validate eagerly so argparse prints the message
    return value


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_decode(args: argparse.Namespace) -> int:
    data = _read_hex(args.hex)
    frames = decode_stream(data)
    if not frames:
        print("no SAR frames found", file=sys.stderr)
        return 1
    print(format_frames(frames, verbose=not args.brief))
    print(f"\n# {summarise(frames)}", file=sys.stderr)
    return 0


def cmd_decode_file(args: argparse.Namespace) -> int:
    total = 0
    with open(args.path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                data = _read_hex(line)
            except argparse.ArgumentTypeError as exc:
                print(f"{args.path}:{lineno}: {exc}", file=sys.stderr)
                continue
            print(f"# line {lineno}: {line}")
            frames = decode_stream(data)
            print(format_frames(frames, verbose=not args.brief))
            total += len(frames)
    print(f"\n# decoded {total} frame(s)", file=sys.stderr)
    return 0 if total else 1


def cmd_capture(args: argparse.Namespace) -> int:
    packets = open_capture(args.path)
    direction = _DIR_CHOICES.get(args.dir) if args.dir else None
    handle = int(args.handle, 16) if args.handle else None

    values = extract_att_values(packets, direction=direction, handle=handle)
    if not values:
        print("no ATT values found — is this a BLE capture of service 0xFE95?",
              file=sys.stderr)
        return 1

    print(f"# {len(values)} ATT value(s) extracted", file=sys.stderr)
    if args.verbose:
        for value in values:
            print(f"# {value.timestamp_us:>16} {value.direction_name:<8} "
                  f"h=0x{value.handle:04x} {value.att_op:<28} "
                  f"{value.value.hex()}")

    frames = decode_att_values(values, split_directions=not args.merge)
    print(format_frames(frames, verbose=not args.brief))
    print(f"\n# {summarise(frames)}", file=sys.stderr)
    return 0


def cmd_build(args: argparse.Namespace) -> int:
    if args.kind == "start":
        cfg = default_start_config()
        print(f"# CMD_L1START_REQ config TLV ({len(cfg)} bytes)")
        print(cfg.hex())
        frame = build_frame(C.TYPE_CMD, 0, bytes([C.CMD_L1START_REQ]) + cfg)
        print(f"# full frame ({len(frame)} bytes)")
        print(frame.hex())
    elif args.kind == "ack":
        frame = build_frame(C.TYPE_ACK, int(args.seq, 0), b"")
        print(frame.hex())
    elif args.kind == "nak":
        frame = build_frame(C.TYPE_NAK, int(args.seq, 0), b"")
        print(frame.hex())
    else:  # pragma: no cover - argparse restricts values
        raise AssertionError(args.kind)
    return 0


def cmd_legacy(args: argparse.Namespace) -> int:
    data = _read_hex(args.hex)
    count = 0
    for frame in iter_v1_frames(data):
        print(f"[@{frame.offset:04x}] ch={frame.channel_type} "
              f"resp={int(frame.need_response)} flag={int(frame.flag)} "
              f"op=0x{frame.opcode:02x} sn={frame.opcode_sn} "
              f"type={frame.data_type_name} len={len(frame.payload)}")
        print(f"    payload: {frame.payload.hex()}")
        count += 1
    if not count:
        print("no legacy frames found (expected BA DC FE ... EF)",
              file=sys.stderr)
        return 1
    return 0


def cmd_keys(args: argparse.Namespace) -> int:
    token = _read_hex(args.token)
    keys = derive_v2_keys(token, _read_hex(args.app), _read_hex(args.dev))
    print(f"deviceKey: {keys.device_key.hex()}")
    print(f"appKey:    {keys.app_key.hex()}")
    print(f"deviceIV:  {keys.device_iv.hex()}")
    print(f"appIV:     {keys.app_iv.hex()}")
    if args.json:
        print(json.dumps({
            "deviceKey": keys.device_key.hex(),
            "appKey": keys.app_key.hex(),
            "deviceIV": keys.device_iv.hex(),
            "appIV": keys.app_iv.hex(),
        }))
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    key = _read_hex(args.key)
    payload = _read_hex(args.data)
    if len(key) != 16:
        print("key must be 16 bytes (V2 session key)", file=sys.stderr)
        return 2

    if args.mode == "v2":
        plain = decrypt_v2_payload(key, payload)
    else:
        plain = aes_ctr_crypt(key, key, int(args.counter, 0), payload)
    print(f"plaintext: {plain.hex()}")

    try:
        text = plain.decode("utf-8")
        if text.isprintable():
            print(f"text:      {text}")
    except UnicodeDecodeError:
        pass

    try:
        fields = proto_decode(plain)
    except Exception as exc:  # noqa: BLE001 - report, do not crash
        print(f"proto:     <not protobuf> ({exc})")
    else:
        print(f"proto:     {to_json(fields)}")
    return 0


def cmd_proto(args: argparse.Namespace) -> int:
    data = _read_hex(args.hex)
    try:
        fields = proto_decode(data)
    except Exception as exc:  # noqa: BLE001
        print(f"not valid protobuf: {exc}", file=sys.stderr)
        return 1
    print(to_json(fields, indent=2 if args.pretty else None))
    return 0


def cmd_selftest(args: argparse.Namespace) -> int:
    from .selftest import run_all
    return run_all(verbose=not args.quiet)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="miwear",
        description="Decode and build the Xiaomi Mi Wear (mihealth) BLE protocol.",
    )
    parser.add_argument("--version", action="version",
                        version=f"miwear {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("decode", help="decode a hex string containing SAR frames")
    p.add_argument("hex", type=hex_arg, help="hex bytes, spaces/colons allowed")
    p.add_argument("--brief", action="store_true", help="headers only")
    p.set_defaults(func=cmd_decode)

    p = sub.add_parser("decode-file", help="decode a file with one hex frame per line")
    p.add_argument("path")
    p.add_argument("--brief", action="store_true")
    p.set_defaults(func=cmd_decode_file)

    p = sub.add_parser("capture", help="decode an HCI capture (btsnoop or pcap)")
    p.add_argument("path")
    p.add_argument("--dir", choices=("host2dev", "dev2host"),
                   help="keep only one direction")
    p.add_argument("--handle", help="keep only this ATT handle (hex, e.g. 5e)")
    p.add_argument("--merge", action="store_true",
                   help="merge both directions into one stream")
    p.add_argument("--verbose", action="store_true", help="dump every ATT value")
    p.add_argument("--brief", action="store_true")
    p.set_defaults(func=cmd_capture)

    p = sub.add_parser("build", help="build standard frames")
    p.add_argument("kind", choices=("start", "ack", "nak"))
    p.add_argument("--seq", default="0", help="sequence number (ack/nak)")
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("legacy", help="decode legacy V1 frames (BA DC FE ... EF)")
    p.add_argument("hex")
    p.set_defaults(func=cmd_legacy)

    p = sub.add_parser("keys", help="derive V2 session keys (HKDF)")
    p.add_argument("--token", required=True, help="stored auth token, hex")
    p.add_argument("--app", required=True, help="randomApp, 16 bytes hex")
    p.add_argument("--dev", required=True, help="randomDevice, 16 bytes hex")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_keys)

    p = sub.add_parser("decrypt", help="decrypt a V2 payload (AES-CTR, IV=key)")
    p.add_argument("--key", required=True, help="16-byte session key, hex")
    p.add_argument("--data", required=True, help="ciphertext, hex")
    p.add_argument("--mode", choices=("v2", "raw"), default="v2")
    p.add_argument("--counter", default="0", help="block offset for raw mode")
    p.set_defaults(func=cmd_decrypt)

    p = sub.add_parser("proto", help="decode a protobuf wire payload")
    p.add_argument("hex")
    p.add_argument("--pretty", action="store_true")
    p.set_defaults(func=cmd_proto)

    p = sub.add_parser("selftest", help="run the built-in verification suite")
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(func=cmd_selftest)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except HexError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"error: file not found: {exc.filename}", file=sys.stderr)
        return 2
    except CaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
