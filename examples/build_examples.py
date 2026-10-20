"""Build the example frame files.

Run from the repository root::

    python examples/build_examples.py

It writes ``examples/*.hex`` and prints what each file contains. The values
are produced by the library itself, so this doubles as a smoke test.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from miwear import constants as C
from miwear.layer_l1 import build_frame, default_start_config
from miwear.protobuf import (encode_field_bytes, encode_field_varint)
from miwear.crypto import derive_v2_keys, aes_ctr_crypt

OUT = pathlib.Path(__file__).parent


def l2(channel: int, opcode: int, data: bytes) -> bytes:
    return bytes([channel, opcode]) + data


def build_legacy_demo() -> bytes:
    """One legacy ``BA DC FE ... EF`` frame via the library builder."""
    from miwear.legacy_v1 import build_v1_frame
    return build_v1_frame(channel_type=0, opcode=0x01, opcode_sn=0x02,
                          data_type=C.V1_DT_PLAIN, payload=b"hello",
                          need_response=True)


def main() -> int:
    start_req = build_frame(C.TYPE_CMD, 0,
                            bytes([C.CMD_L1START_REQ]) + default_start_config())
    start_rsp = build_frame(C.TYPE_CMD, 0,
                            bytes([C.CMD_L1START_RSP]) + default_start_config(),
                            frx=1)
    ack = build_frame(C.TYPE_ACK, 5, b"")
    nak = build_frame(C.TYPE_NAK, 5, b"")

    # A V1 auth verify carrying a user id in pyt/va0 field 7.
    auth = (encode_field_varint(1, 1)
            + encode_field_varint(2, 5)
            + encode_field_bytes(7, b"userid-example"))
    auth_frame = build_frame(C.TYPE_DATA, 0, l2(C.CH_PB, C.OP_WRITE, auth))

    # Larger-than-one-write frame to illustrate fragmentation (300 bytes).
    big_payload = encode_field_bytes(1, bytes(range(256)) + bytes(38))
    big_frame = build_frame(C.TYPE_DATA, 3,
                            l2(C.CH_FILE_FITNESS, C.OP_WRITE, big_payload))

    # An encrypted V2 payload: AES-CTR with the key as IV.
    key = derive_v2_keys(b"demo-token", b"\x11" * 16, b"\x22" * 16).app_key
    plain = auth
    encrypted = aes_ctr_crypt(key, key, 0, plain)
    enc_frame = build_frame(C.TYPE_DATA, 7,
                            l2(C.CH_LYRA, C.OP_WRITE_ENC, encrypted))

    files = {
        "01_start_request.hex": start_req,
        "02_start_response.hex": start_rsp,
        "03_ack.hex": ack,
        "04_nak.hex": nak,
        "05_auth_verify_plain.hex": auth_frame,
        "06_multi_write_fragment.hex": big_frame,
        "07_encrypted_payload.hex": enc_frame,
        "08_session.hex": start_req + start_rsp + ack + auth_frame,
        "09_legacy_v1.hex": build_legacy_demo(),
    }

    for name, data in files.items():
        path = OUT / name
        path.write_text(data.hex() + "\n", encoding="utf-8")
        print(f"{name:<32} {len(data):>4} bytes  {data.hex()[:64]}"
              + ("..." if len(data) > 32 else ""))

    print(f"\nEncryption demo key (appKey): {key.hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
