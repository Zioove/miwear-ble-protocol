"""Built-in verification suite.

Every check is anchored to an external, published test vector so the
implementation is validated against something other than itself.
"""

from __future__ import annotations

import hashlib

from . import constants as C
from .crc import crc16_arc, crc32
from .crypto import aes_ctr_crypt, derive_v2_keys, hkdf_sha256, sign_hmac
from .layer_l1 import build_frame, default_start_config, iter_frames
from .layer_l2 import decode_config_tlv, parse_l2
from .protobuf import decode as proto_decode, encode_field_bytes, encode_field_varint
from .session import decode_stream

__all__ = ["run_all"]


class _Suite:
    def __init__(self, verbose: bool = True) -> None:
        self.verbose = verbose
        self.passed = 0
        self.failed: list[str] = []

    def check(self, name: str, got, expected) -> None:
        ok = got == expected
        if ok:
            self.passed += 1
        else:
            self.failed.append(f"{name}: got {got!r}, expected {expected!r}")
        if self.verbose:
            status = "PASS" if ok else "FAIL"
            print(f"  [{status}] {name}")

    def section(self, title: str) -> None:
        if self.verbose:
            print(f"\n{title}")


def _check_crc(s: _Suite) -> None:
    s.section("CRC")
    # Published check value for CRC-16/ARC with input "123456789".
    s.check("crc16_arc('123456789') == 0xBB3D", crc16_arc(b"123456789"), 0xBB3D)
    s.check("crc16_arc(empty) == 0", crc16_arc(b""), 0)
    # zlib's CRC-32 and the APK's CRC32 must agree on the standard vector.
    s.check("crc32('123456789') == 0xCBF43926", crc32(b"123456789"), 0xCBF43926)


def _check_aes(s: _Suite) -> None:
    s.section("AES-128")
    # FIPS-197 Appendix C.1
    from .crypto import _AES128  # local import: private helper
    cipher = _AES128(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    got = cipher.encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff"))
    s.check("FIPS-197 C.1 block encryption",
            got.hex(), "69c4e0d86a7b0430d8cdb78070b4c55a")

    # NIST SP 800-38A F.5.1 CTR-AES128
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"
                          "ae2d8a571e03ac9c9eb76fac45af8e51")
    expected = ("874d6191b620e3261bef6864990db6ce"
                "9806f66b7970fdff8617187bb9fffdff")
    s.check("SP 800-38A F.5.1 CTR encryption",
            aes_ctr_crypt(key, iv, 0, plain).hex(), expected)


def _check_hkdf(s: _Suite) -> None:
    s.section("HKDF-SHA256")
    # RFC 5869 Appendix A.1
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expected = ("3cb25f25faacd57a90434f64d0362f2a"
                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                "34007208d5b887185865")
    s.check("RFC 5869 test case 1",
            hkdf_sha256(ikm, salt, info, 42).hex(), expected)

    keys = derive_v2_keys(b"token", b"\x01" * 16, b"\x02" * 16)
    s.check("V2 key material is 40 bytes", len(keys.raw), 40)
    s.check("deviceKey is 16 bytes", len(keys.device_key), 16)
    s.check("appIV is 4 bytes", len(keys.app_iv), 4)

    # HMAC-SHA256 RFC 4231 test case 1
    s.check("RFC 4231 HMAC case 1",
            sign_hmac(b"\x0b" * 20, b"Hi There").hex(),
            "b0344c61d8db38535ca8afceaf0bf12b"
            "881dc200c9833da726e9376c2e32cff7")


def _check_l1(s: _Suite) -> None:
    s.section("L1 SAR framing")
    s.check("default_start_config() matches CMDPacket.createCmdData()",
            default_start_config().hex(),
            "01030001000002020000fc03020020000402001027")

    frame = build_frame(C.TYPE_CMD, 0,
                        bytes([C.CMD_L1START_REQ]) + default_start_config())
    s.check("START_REQ frame bytes",
            frame.hex(),
            "a5a5020016001d4d0101030001000002020000fc03020020000402001027")

    parsed = list(iter_frames(frame))
    s.check("START_REQ parses back to one frame", len(parsed), 1)
    s.check("START_REQ CRC validates", parsed[0].crc_ok, True)
    s.check("START_REQ type is CMD", parsed[0].type_name, "CMD")
    s.check("START_REQ payload round-trips", parsed[0].payload, frame[8:])

    session = decode_stream(frame)
    s.check("decoded command id", session[0].cmd["cmd"], C.CMD_L1START_REQ)
    mps = [c for c in session[0].cmd["config"] if c["type"] == C.CONFIG_MPS][0]
    s.check("decoded MPS", mps["u16"], C.SAR_DEFAULT_MPS)
    win = [c for c in session[0].cmd["config"] if c["type"] == C.CONFIG_TX_WIN][0]
    s.check("decoded TX window", win["u16"], C.SAR_DEFAULT_TX_WIN)

    # A corrupted payload must fail the CRC check but still parse structurally.
    broken = bytearray(frame)
    broken[-1] ^= 0xFF
    s.check("corrupted frame fails CRC", list(iter_frames(bytes(broken)))[0].crc_ok,
            False)

    # Resynchronisation: junk before a valid frame must be skipped.
    recovered = list(iter_frames(b"\x00\x11\x22" + frame))
    s.check("resync after junk finds the frame", len(recovered), 1)
    s.check("resync keeps its offset", recovered[0].offset, 3)


def _check_l2(s: _Suite) -> None:
    s.section("L2 channel layer")
    l2 = parse_l2(bytes([C.CH_PB, C.OP_WRITE]) + b"\x08\x01")
    s.check("channel parsed", l2.channel, C.CH_PB)
    s.check("channel name", l2.channel_name, "PB")
    s.check("opcode parsed", l2.opcode, C.OP_WRITE)
    s.check("not encrypted", l2.is_encrypted, False)

    enc = parse_l2(bytes([C.CH_LYRA, C.OP_WRITE_ENC]) + b"\x00" * 8)
    s.check("encrypted flag", enc.is_encrypted, True)

    s.check("short payload returns None", parse_l2(b"\x01"), None)


def _check_proto(s: _Suite) -> None:
    s.section("protobuf wire format")
    encoded = (encode_field_varint(1, 1) + encode_field_varint(2, 5)
               + encode_field_bytes(7, b"abc"))
    fields = proto_decode(encoded)
    s.check("field count", len(fields), 3)
    s.check("field 1 value", fields[0].value, 1)
    s.check("field 2 value", fields[1].value, 5)
    s.check("field 7 text", fields[2].text, "abc")
    s.check("field 7 round-trips", encoded, bytes([0x08, 0x01, 0x10, 0x05,
                                                   0x3A, 0x03]) + b"abc")

    # Nested message detection (auth `pyt` envelope shape).
    inner = encode_field_varint(1, 1) + encode_field_varint(2, 26)
    envelope = encode_field_varint(1, 1) + encode_field_bytes(3, inner)
    parsed = proto_decode(envelope)
    s.check("nested message parsed", parsed[1].message is not None, True)
    s.check("nested field 2", parsed[1].message[1].value, 26)


def _check_vectors(s: _Suite) -> None:
    s.section("End-to-end sample session")
    # CMD START_REQ -> CMD START_RSP -> ACK -> DATA(PB, protobuf v1 auth)
    start = build_frame(C.TYPE_CMD, 0,
                        bytes([C.CMD_L1START_REQ]) + default_start_config())
    rsp = build_frame(C.TYPE_CMD, 0,
                      bytes([C.CMD_L1START_RSP]) + default_start_config(), frx=1)
    ack = build_frame(C.TYPE_ACK, 0, b"")
    auth = encode_field_varint(1, 1) + encode_field_varint(2, 5) \
        + encode_field_bytes(7, b"userid-example")
    data = build_frame(C.TYPE_DATA, 0, bytes([C.CH_PB, C.OP_WRITE]) + auth)

    stream = start + rsp + ack + data
    frames = decode_stream(stream)
    s.check("all four frames decoded", len(frames), 4)
    s.check("frame order preserved",
            [f.type_name for f in frames], ["CMD", "CMD", "ACK", "DATA"])
    s.check("all CRCs valid", all(f.frame.crc_ok for f in frames), True)
    s.check("DATA carries PB channel", frames[3].l2_channel, C.CH_PB)
    s.check("DATA protobuf field 7",
            frames[3].proto_fields[2].text, "userid-example")


def run_all(verbose: bool = True) -> int:
    """Run every check and return a process exit code."""
    suite = _Suite(verbose)
    _check_crc(suite)
    _check_aes(suite)
    _check_hkdf(suite)
    _check_l1(suite)
    _check_l2(suite)
    _check_proto(suite)
    _check_vectors(suite)

    total = suite.passed + len(suite.failed)
    if suite.failed:
        print(f"\n{len(suite.failed)} of {total} checks FAILED:")
        for line in suite.failed:
            print(f"  - {line}")
        return 1
    print(f"\nAll {total} checks passed.")
    return 0
