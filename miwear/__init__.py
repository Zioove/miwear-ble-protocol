"""miwear — Xiaomi Mi Wear (mihealth) BLE protocol toolkit.

Decode, build and decrypt the three-layer Bluetooth Low Energy protocol
spoken between Xiaomi Health and Mi Band / Mi Watch wearables.

Quick start
-----------
>>> from miwear import decode_stream, format_frames
>>> frames = decode_stream(bytes.fromhex("a5a5020016001d4d0101030001000002"
...                                      "020000fc03020020000402001027"))
>>> print(format_frames(frames).splitlines()[0])
[@0000] ?         CMD  seq=0   len=22    crc=4d1d(OK )

Layer overview
--------------
L0  ATT / GATT     service 0xFE95, write 0x005F, notify 0x005E
L1  SAR framing    8-byte header, magic A5 A5, CRC-16/ARC
L2  Channel        channel u8 | opcode u8 | payload (usually protobuf)
"""

from __future__ import annotations

#: Keep this above the submodule imports: ``protogen`` (and any future module)
#: does ``from . import __version__`` at import time, so it must already exist.
__version__ = "1.0.0"

from .capture import (
    AttValue,
    CaptureError,
    DIR_DEVICE_TO_HOST,
    DIR_HOST_TO_DEVICE,
    extract_att_values,
    open_capture,
    read_btsnoop,
    read_pcap,
)
from .crc import crc16_arc, crc32
from .crypto import (
    V2Keys,
    aes_ctr_crypt,
    app_sign_message,
    build_v1_nonce,
    decrypt_v2_payload,
    derive_v2_keys,
    hkdf_salt,
    hkdf_sha256,
    sign_hmac,
    sign_message,
)
from .format import format_frame, format_frames
from .layer_l1 import (
    L1Frame,
    TruncatedFrame,
    build_ack,
    build_cmd,
    build_data,
    build_frame,
    default_start_config,
    iter_frames,
)
from .layer_l2 import L2Packet, build_l2, decode_config_tlv, parse_l2
from .legacy_v1 import V1Frame, build_v1_frame, iter_v1_frames
from .protobuf import ProtoField, decode as proto_decode, to_json
from .protogen import generate as generate_proto, infer_schema, render_proto
from .session import DecodedFrame, decode_att_values, decode_stream, summarise

__all__ = [
    # capture
    "AttValue", "CaptureError", "DIR_DEVICE_TO_HOST", "DIR_HOST_TO_DEVICE",
    "extract_att_values", "open_capture", "read_btsnoop", "read_pcap",
    # checksums
    "crc16_arc", "crc32",
    # crypto
    "V2Keys", "aes_ctr_crypt", "app_sign_message", "build_v1_nonce",
    "decrypt_v2_payload", "derive_v2_keys", "hkdf_salt", "hkdf_sha256",
    "sign_hmac", "sign_message",
    # rendering
    "format_frame", "format_frames",
    # L1
    "L1Frame", "TruncatedFrame", "build_ack", "build_cmd", "build_data",
    "build_frame", "default_start_config", "iter_frames",
    # L2
    "L2Packet", "build_l2", "decode_config_tlv", "parse_l2",
    # legacy
    "V1Frame", "build_v1_frame", "iter_v1_frames",
    # protobuf
    "ProtoField", "proto_decode", "to_json",
    # schema inference
    "generate_proto", "infer_schema", "render_proto",
    # session
    "DecodedFrame", "decode_att_values", "decode_stream", "summarise",
    "__version__",
]
