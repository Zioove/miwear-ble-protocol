"""Test suite for the miwear protocol toolkit.

Run with::

    python -m pytest tests/ -v
    python -m miwear selftest
"""

from __future__ import annotations

import pytest

from miwear import constants as C
from miwear.crc import crc16_arc, crc32
from miwear.crypto import (aes_ctr_crypt, build_v1_nonce, decrypt_v2_payload,
                           derive_v2_keys, hkdf_sha256, sign_hmac)
from miwear.layer_l1 import (build_ack, build_frame, default_start_config,
                             iter_frames, TruncatedFrame)
from miwear.layer_l2 import build_l2, decode_config_tlv, parse_l2
from miwear.legacy_v1 import build_v1_frame, iter_v1_frames
from miwear.protobuf import (ProtoError, decode as proto_decode,
                             encode_field_bytes, encode_field_varint)
from miwear.session import decode_stream, summarise


# ---------------------------------------------------------------------------
# Checksums
# ---------------------------------------------------------------------------

class TestChecksums:
    def test_crc16_check_value(self):
        assert crc16_arc(b"123456789") == 0xBB3D

    def test_crc16_empty(self):
        assert crc16_arc(b"") == 0

    def test_crc32_check_value(self):
        assert crc32(b"123456789") == 0xCBF43926


# ---------------------------------------------------------------------------
# Cryptography
# ---------------------------------------------------------------------------

class TestCrypto:
    def test_rfc5869_case1(self):
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        expected = ("3cb25f25faacd57a90434f64d0362f2a"
                    "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                    "34007208d5b887185865")
        assert hkdf_sha256(ikm, salt, info, 42).hex() == expected

    def test_rfc4231_case1(self):
        assert sign_hmac(b"\x0b" * 20, b"Hi There").hex() == (
            "b0344c61d8db38535ca8afceaf0bf12b"
            "881dc200c9833da726e9376c2e32cff7")

    def test_hkdf_rejects_zero_salt_as_empty(self):
        # Empty salt must behave like a zero-filled salt of hash length.
        a = hkdf_sha256(b"x", b"", b"info", 32)
        b = hkdf_sha256(b"x", b"\x00" * 32, b"info", 32)
        assert a == b

    def test_hkdf_length_guard(self):
        with pytest.raises(ValueError):
            hkdf_sha256(b"x", b"", b"info", 255 * 32 + 1)

    def test_derive_v2_keys_layout(self):
        keys = derive_v2_keys(b"token", b"\x01" * 16, b"\x02" * 16)
        assert len(keys.raw) == 40
        assert keys.device_key == keys.raw[0:16]
        assert keys.app_key == keys.raw[16:32]
        assert keys.device_iv == keys.raw[32:36]
        assert keys.app_iv == keys.raw[36:40]

    def test_salt_is_the_nonce_pair(self):
        """Swapping the HKDF salt/IKM must change the output."""
        keys_a = derive_v2_keys(b"token", b"\x01" * 16, b"\x02" * 16)
        keys_b = derive_v2_keys(b"\x01" * 32, b"token", b"")  # wrong order
        assert keys_a.raw != keys_b.raw

    def test_ctr_roundtrip(self):
        key = bytes(range(16))
        plain = b"the quick brown fox jumps over"
        ct = aes_ctr_crypt(key, key, 0, plain)
        assert ct != plain
        assert aes_ctr_crypt(key, key, 0, ct) == plain

    def test_v2_decrypt_uses_key_as_iv(self):
        key = bytes(range(16))
        plain = b"A" * 20
        ct = aes_ctr_crypt(key, key, 0, plain)
        assert decrypt_v2_payload(key, ct) == plain

    def test_ctr_counter_advance(self):
        key = bytes(range(16))
        iv = b"\x00" * 12 + b"\x00\x00\x00\x00"
        one = aes_ctr_crypt(key, iv, 0, b"\x00" * 16)
        two = aes_ctr_crypt(key, iv, 1, b"\x00" * 16)
        assert one != two

    def test_v1_nonce_layout(self):
        # tp5.c() emits {low & 0xFF, low >> 8, high & 0xFF, high >> 8} and the
        # ByteBuffer in CipherApiCall.encryptData is little-endian, so the
        # trailing counter is little-endian, not big-endian.
        nonce = build_v1_nonce(b"\xaa\xbb\xcc\xdd", 0x01020304)
        assert nonce == b"\xaa\xbb\xcc\xdd" + b"\x00" * 4 + b"\x04\x03\x02\x01"
        assert len(nonce) == 12

    def test_v1_nonce_counter_matches_tp5(self):
        # counter 1 -> low=1 high=0 -> {01 00 00 00}
        assert build_v1_nonce(b"\x01\x02\x03\x04", 1)[8:] == b"\x01\x00\x00\x00"
        # 0x00010002 -> low=0x0002 high=0x0001 -> {02 00 01 00}
        assert build_v1_nonce(b"\x01\x02\x03\x04", 0x00010002)[8:] == b"\x02\x00\x01\x00"


# ---------------------------------------------------------------------------
# L1 framing
# ---------------------------------------------------------------------------

class TestLayerL1:
    def test_start_config_bytes(self):
        assert default_start_config().hex() == (
            "01030001000002020000fc03020020000402001027")

    def test_start_frame_bytes(self):
        frame = build_frame(C.TYPE_CMD, 0,
                            bytes([C.CMD_L1START_REQ]) + default_start_config())
        assert frame.hex() == (
            "a5a5020016001d4d0101030001000002020000fc03020020000402001027")

    def test_roundtrip(self):
        payload = b"\x01\x02\x03\x04"
        frame = build_frame(C.TYPE_DATA, 9, payload)
        parsed = list(iter_frames(frame))
        assert len(parsed) == 1
        assert parsed[0].crc_ok
        assert parsed[0].seq == 9
        assert parsed[0].payload == payload

    def test_empty_payload_has_zero_crc(self):
        frames = list(iter_frames(build_ack(3)))
        assert frames[0].crc == 0
        assert frames[0].crc_ok

    def test_corruption_detected(self):
        frame = bytearray(build_frame(C.TYPE_DATA, 1, b"\x01\x02"))
        frame[-1] ^= 0xFF
        assert list(iter_frames(bytes(frame)))[0].crc_ok is False

    def test_resync_skips_junk(self):
        frame = build_frame(C.TYPE_DATA, 0, b"\x55")
        frames = list(iter_frames(b"\x00\x01\x02" + frame))
        assert len(frames) == 1
        assert frames[0].offset == 3

    def test_multiple_frames(self):
        stream = (build_frame(C.TYPE_CMD, 0, b"\x01")
                  + build_frame(C.TYPE_ACK, 1, b"")
                  + build_frame(C.TYPE_DATA, 2, b"\x01\x02"))
        assert [f.type_name for f in iter_frames(stream)] == ["CMD", "ACK", "DATA"]

    def test_truncated_frame_reported(self):
        frame = build_frame(C.TYPE_DATA, 0, b"\x00" * 10)
        frames = list(iter_frames(frame[:-4]))
        assert isinstance(frames[-1], TruncatedFrame)
        assert frames[-1].missing == 4

    def test_frx_encoding(self):
        frame = build_frame(C.TYPE_ACK, 0, b"", frx=1)
        assert frame[2] & 0x10
        assert list(iter_frames(frame))[0].frx == 1

    def test_invalid_seq_rejected(self):
        with pytest.raises(ValueError):
            build_frame(C.TYPE_DATA, 256, b"")


# ---------------------------------------------------------------------------
# L2 multiplexing
# ---------------------------------------------------------------------------

class TestLayerL2:
    def test_parse(self):
        packet = parse_l2(bytes([C.CH_PB, C.OP_WRITE, 0xAA]))
        assert packet.channel == C.CH_PB
        assert packet.opcode == C.OP_WRITE
        assert packet.data == b"\xaa"
        assert packet.is_encrypted is False

    def test_encrypted_flag(self):
        packet = parse_l2(bytes([C.CH_LYRA, C.OP_WRITE_ENC]))
        assert packet.is_encrypted is True

    def test_too_short(self):
        assert parse_l2(b"\x01") is None

    def test_build_roundtrip(self):
        raw = build_l2(C.CH_MASS, C.OP_WRITE, b"\xde\xad")
        assert raw == b"\x02\x01\xde\xad"
        assert parse_l2(raw).channel == C.CH_MASS

    def test_config_tlv(self):
        info = decode_config_tlv(bytes([C.CMD_L1START_REQ]) + default_start_config())
        assert info["cmd"] == C.CMD_L1START_REQ
        assert len(info["config"]) == 4
        mps = [c for c in info["config"] if c["type"] == C.CONFIG_MPS][0]
        assert mps["u16"] == 64512
        version = [c for c in info["config"] if c["type"] == C.CONFIG_VERSION][0]
        assert version["version"] == "1.0.0"

    def test_config_tlv_trailing_detected(self):
        # cmd=1, one complete TLV (type 2, len 2, value 01 AA), then a stray byte.
        info = decode_config_tlv(bytes([1, 2, 2, 0, 1, 0xAA, 0xFF]))
        assert info["trailing"] == "ff"


# ---------------------------------------------------------------------------
# protobuf
# ---------------------------------------------------------------------------

class TestProtobuf:
    def test_roundtrip(self):
        encoded = (encode_field_varint(1, 300)
                   + encode_field_bytes(2, b"hello"))
        fields = proto_decode(encoded)
        assert fields[0].value == 300
        assert fields[1].text == "hello"

    def test_nested(self):
        inner = encode_field_varint(1, 1) + encode_field_varint(2, 26)
        outer = encode_field_bytes(3, inner)
        fields = proto_decode(outer)
        assert fields[0].message is not None
        assert fields[0].message[1].value == 26

    def test_negative_varint(self):
        encoded = encode_field_varint(1, -1)
        assert proto_decode(encoded)[0].value == 0xFFFFFFFFFFFFFFFF

    def test_invalid_field_zero(self):
        with pytest.raises(ProtoError):
            proto_decode(b"\x00\x01")

    def test_overrun(self):
        with pytest.raises(ProtoError):
            proto_decode(b"\x3a\x05abc")

    def test_unsupported_wire_type(self):
        with pytest.raises(ProtoError):
            proto_decode(b"\x0f")


# ---------------------------------------------------------------------------
# Legacy V1
# ---------------------------------------------------------------------------

class TestLegacy:
    def test_roundtrip(self):
        raw = build_v1_frame(channel_type=0, opcode=0x01, opcode_sn=0x02,
                             data_type=C.V1_DT_PLAIN, payload=b"hello",
                             need_response=True)
        frames = list(iter_v1_frames(raw))
        assert len(frames) == 1
        frame = frames[0]
        assert frame.channel_type == 0
        assert frame.need_response is True
        assert frame.payload == b"hello"
        assert frame.data_type_name == "PLAIN"

    def test_garbage_skipped(self):
        good = build_v1_frame(0, 1, 0, 0, b"x")
        assert len(list(iter_v1_frames(b"\x00" * 5 + good))) == 1

    def test_missing_terminator_rejected(self):
        raw = build_v1_frame(0, 1, 0, 0, b"x")[:-1]
        assert list(iter_v1_frames(raw)) == []


# ---------------------------------------------------------------------------
# Session decoding
# ---------------------------------------------------------------------------

class TestSession:
    def _session(self) -> bytes:
        start = build_frame(C.TYPE_CMD, 0,
                            bytes([C.CMD_L1START_REQ]) + default_start_config())
        rsp = build_frame(C.TYPE_CMD, 0,
                          bytes([C.CMD_L1START_RSP]) + default_start_config(),
                          frx=1)
        ack = build_frame(C.TYPE_ACK, 0, b"")
        auth = (encode_field_varint(1, 1) + encode_field_varint(2, 5)
                + encode_field_bytes(7, b"userid-example"))
        data = build_frame(C.TYPE_DATA, 0,
                           bytes([C.CH_PB, C.OP_WRITE]) + auth)
        return start + rsp + ack + data

    def test_full_session(self):
        frames = decode_stream(self._session())
        assert len(frames) == 4
        assert [f.type_name for f in frames] == ["CMD", "CMD", "ACK", "DATA"]
        assert all(f.frame.crc_ok for f in frames)
        assert frames[3].proto_fields[2].text == "userid-example"

    def test_summary(self):
        summary = summarise(decode_stream(self._session()))
        assert summary["frames"] == 4
        assert summary["by_type"] == {"CMD": 2, "ACK": 1, "DATA": 1}
        assert summary["crc_failures"] == 0

    def test_encrypted_payload_not_decoded(self):
        data = build_frame(C.TYPE_DATA, 0,
                           bytes([C.CH_LYRA, C.OP_WRITE_ENC]) + b"\x00" * 8)
        frames = decode_stream(data)
        assert frames[0].is_encrypted
        assert frames[0].proto_fields is None


# ---------------------------------------------------------------------------
# Round trip through encryption
# ---------------------------------------------------------------------------

class TestEndToEnd:
    def test_derive_encrypt_decrypt(self):
        keys = derive_v2_keys(b"secret-token", b"\xaa" * 16, b"\xbb" * 16)
        plain = encode_field_varint(1, 1) + encode_field_bytes(2, b"payload")
        cipher = aes_ctr_crypt(keys.app_key, keys.app_key, 0, plain)

        frame = build_frame(C.TYPE_DATA, 0,
                            bytes([C.CH_LYRA, C.OP_WRITE_ENC]) + cipher)
        decoded = decode_stream(frame)
        assert decoded[0].is_encrypted

        recovered = decrypt_v2_payload(keys.app_key, decoded[0].l2_payload)
        assert recovered == plain
        assert proto_decode(recovered)[1].text == "payload"
