"""Tests for :mod:`miwear.verify` — the capture verifier.

There is no real BLE capture in this repository (and no phone paired to the
machine that runs these tests), so the tests synthesise one: a writer for the
btsnoop container builds a byte-exact log, and the frames inside it are
produced by the same builders the rest of the package uses
(:func:`miwear.layer_l1.build_frame` etc.).  That exercises the whole path
capture → ATT → L1 → L2 → AES-CTR → protobuf without needing hardware.

Run with::

    python tests/run_tests.py
    python -m pytest tests/test_verify.py -v
    python tests/test_verify.py          # standalone, no pytest required
"""

from __future__ import annotations

import inspect
import io
import json
import os
import struct
import sys
import tempfile
import traceback

# Running this file directly (`python tests/test_verify.py`) puts tests/ on
# sys.path, not the repository root; add the root so `import miwear` works.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

try:  # pytest is optional in this repository
    import pytest
except ImportError:  # pragma: no cover - exercised on the bare-Python runner
    class _Raises:
        def __init__(self, exc):
            self.exc = exc

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            if exc_type is None:
                raise AssertionError(f"DID NOT RAISE {self.exc}")
            return issubclass(exc_type, self.exc)

    class _Mark:
        def __getattr__(self, name):
            def decorator(*_a, **_kw):
                def wrap(fn):
                    return fn
                return wrap
            return decorator

    class _PytestShim:
        """The tiny slice of pytest this module uses."""

        @staticmethod
        def raises(exc, *a, **kw):
            return _Raises(exc)

        mark = _Mark()

        @staticmethod
        def fixture(*a, **kw):
            return lambda fn: fn

        @staticmethod
        def skip(*a, **kw):
            return None

    pytest = _PytestShim()  # noqa: F811 - intentional fallback

from miwear import constants as C
from miwear.crypto import aes_ctr_crypt, derive_v2_keys, sign_hmac, sign_message
from miwear.layer_l1 import (
    build_ack,
    build_cmd,
    build_data,
    build_frame,
    default_start_config,
)
from miwear.layer_l2 import build_l2
from miwear.protobuf import encode_field_bytes, encode_field_varint
from miwear.verify import (
    MIN_CIPHERTEXT_LEN,
    CaptureReport,
    VerifyError,
    analyse_acks,
    analyse_capture,
    analyse_fragmentation,
    build_ctr_variants,
    check_protobuf,
    diagnose_ctr,
    find_auth_nonces,
    main as verify_main,
    parse_token,
    render_report,
    select_sar_streams,
    shape_score,
    split_frames,
    v2_ctr_variants,
)
from miwear.capture import AttValue, extract_att_values, open_capture


# ---------------------------------------------------------------------------
# btsnoop writer
# ---------------------------------------------------------------------------
#
# Format (libpcap/pcap-bt-monitor, the format btsnoop_hci.log uses):
#
#   file header, 16 bytes
#     0   8  magic  b"btsnoop\0"
#     8   4  version, big-endian                          -> 1
#    12   4  datalink type, big-endian
#           1002 = HCI UART (H4), 1001 = HCI unencapsulated
#
#   record header, 24 bytes, all big-endian
#     0   4  original packet length
#     4   4  included packet length
#     8   4  flags:  bit0 direction (0 = sent/host->controller,
#                                    1 = received/controller->host)
#                   bits 16-31 drops
#    12   4  cumulative drops
#    16   8  timestamp, microseconds since 0 AD
#            (the top 16 bits carry the timezone offset in minutes)
#
#   record body: the HCI packet, starting with its H4 packet-type byte
#     (0x02 = ACL data), which miwear.capture.read_btsnoop expects.

BTSNOOP_MAGIC = b"btsnoop\x00"
BTSNOOP_VERSION = 1
DATALINK_HCI_UART_H4 = 1002

HCI_ACLDATA = 0x02

#: 2024-01-01T00:00:00Z in microseconds since 0 AD (the value btsnoop uses).
EPOCH_2024_US = 1_704_067_200 * 1_000_000


def btsnoop_file(packets) -> bytes:
    """Serialise ``(timestamp_us, direction, acl_bytes)`` records."""
    out = bytearray(BTSNOOP_MAGIC)
    out += struct.pack(">II", BTSNOOP_VERSION, DATALINK_HCI_UART_H4)
    for timestamp_us, direction, acl in packets:
        body = bytes([HCI_ACLDATA]) + acl
        flags = 1 if direction else 0
        out += struct.pack(">IIIIq", len(body), len(body), flags, 0,
                           timestamp_us)
        out += body
    return bytes(out)


def att_write(handle: int, value: bytes, *, notify: bool = False,
              write_cmd: bool = True) -> bytes:
    """Wrap an ATT characteristic value in an L2CAP/ATT PDU."""
    if notify:
        pdu = bytes([C.ATT_OP_HANDLE_VALUE_NTF]) + struct.pack("<H", handle) + value
    elif write_cmd:
        pdu = bytes([C.ATT_OP_WRITE_CMD]) + struct.pack("<H", handle) + value
    else:
        pdu = bytes([C.ATT_OP_WRITE_REQ]) + struct.pack("<H", handle) + value
    return struct.pack("<HH", len(pdu), C.L2CAP_CID_ATT) + pdu


def hci_acl(l2cap_pdu: bytes) -> bytes:
    """Wrap an L2CAP PDU in an HCI ACL data packet.

    HCI ACL header (little-endian): ``handle | PB flag`` then ``data_len``,
    followed by the L2CAP PDU.  ``miwear.capture`` reads the length from
    offset 2, so the field order matters.
    """
    return struct.pack("<HH", 0x0040, len(l2cap_pdu)) + l2cap_pdu


class SnoopBuilder:
    """Accumulate ATT writes into a btsnoop file with sane timestamps."""

    def __init__(self, *, handle_write: int = 0x0012,
                 handle_notify: int = 0x0011) -> None:
        self.packets: list[tuple[int, int, bytes]] = []
        self.now = EPOCH_2024_US
        self.handle_write = handle_write
        self.handle_notify = handle_notify

    # -- low level ------------------------------------------------------
    def raw(self, direction: int, payload: bytes, *, advance_us: int = 1000) -> None:
        self.now += advance_us
        self.packets.append((self.now, direction, hci_acl(payload)))

    def host(self, frame: bytes, *, advance_us: int = 1000) -> None:
        """Write a frame host → device on the SAR write characteristic."""
        self.raw(0, att_write(self.handle_write, frame), advance_us=advance_us)

    def device(self, frame: bytes, *, advance_us: int = 1000) -> None:
        """Notify a frame device → host on the SAR notify characteristic."""
        self.raw(1, att_write(self.handle_notify, frame, notify=True),
                 advance_us=advance_us)

    def host_fragmented(self, frame: bytes, chunk: int,
                        *, advance_us: int = 1000) -> None:
        for pos in range(0, len(frame), chunk):
            self.host(frame[pos:pos + chunk], advance_us=advance_us)

    def device_fragmented(self, frame: bytes, chunk: int,
                          *, advance_us: int = 1000) -> None:
        for pos in range(0, len(frame), chunk):
            self.device(frame[pos:pos + chunk], advance_us=advance_us)

    def to_bytes(self) -> bytes:
        return btsnoop_file(self.packets)

    def write(self, path: str) -> str:
        with open(path, "wb") as fh:
            fh.write(self.to_bytes())
        return path


# ---------------------------------------------------------------------------
# Session fixtures (shared by several test classes)
# ---------------------------------------------------------------------------

#: Deliberately different lengths, like a real pairing token.
TOKEN = bytes.fromhex("00112233445566778899aabbccddeeff")
RANDOM_APP = bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
RANDOM_DEVICE = bytes.fromhex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf")


def _plain_business_message() -> bytes:
    """A protobuf that looks like a real miwear business message.

    ``pyt{type=1, cmd=300, ...}`` — several fields, mixed wire types, so it
    cannot be mistaken for noise.
    """
    return (encode_field_varint(1, 1)
            + encode_field_varint(2, 300)
            + encode_field_bytes(3, bytes(range(20)))
            + encode_field_bytes(7, b"miwear-verify-test"))


def _second_business_message() -> bytes:
    return (encode_field_varint(1, 2)
            + encode_field_varint(2, 401)
            + encode_field_bytes(5, b"\x08\x96\x01")
            + encode_field_bytes(9, bytes(range(11, 40))))


def _auth_request(value: bytes, cmd: int = C.AUTH_CMD_V2_VERIFY,
                  app: bytes = RANDOM_APP) -> bytes:
    """``pyt{type=1, cmd=26, va0{bb0{randomApp, appDeviceId}}}``."""
    bb0 = (encode_field_bytes(1, app)
           + encode_field_bytes(2, b"app-device-id")
           + encode_field_varint(3, 0))
    va0 = encode_field_bytes(C.VA0_FIELD_VERIFY_REQ, bb0)
    return (encode_field_varint(1, 1) + encode_field_varint(2, cmd)
            + encode_field_bytes(3, va0))


def _auth_response(cmd: int = C.AUTH_CMD_V2_VERIFY,
                   dev: bytes = RANDOM_DEVICE,
                   sign: bytes | None = None) -> bytes:
    """``pyt{type=1, cmd=26, va0{hb0{randomDevice, deviceSign}}}``."""
    hb0 = encode_field_bytes(1, dev) + encode_field_bytes(2, sign or b"")
    va0 = encode_field_bytes(C.VA0_FIELD_VERIFY_RSP, hb0)
    return (encode_field_varint(1, 1) + encode_field_varint(2, cmd)
            + encode_field_bytes(3, va0))


def _keys(token: bytes = TOKEN):
    return derive_v2_keys(token, RANDOM_APP, RANDOM_DEVICE)


def _encrypt(key: bytes, plain: bytes) -> bytes:
    """V2 payload encryption: AES-CTR with the key as IV."""
    return aes_ctr_crypt(key, key, 0, plain)


def standard_session(*, token: bytes = TOKEN, with_signature: bool = True,
                     encrypted_payloads: int = 2,
                     fragment: int | None = None) -> SnoopBuilder:
    """Build a realistic capture: handshake, auth, then encrypted traffic."""
    builder = SnoopBuilder()

    # --- L1 handshake ---------------------------------------------------
    builder.host(build_cmd(C.CMD_L1START_REQ, default_start_config()))
    builder.device(build_frame(C.TYPE_CMD, 0,
                               bytes([C.CMD_L1START_RSP]) + default_start_config(),
                               frx=1))

    # --- V2 auth (plaintext protobuf) ------------------------------------
    builder.host(build_data(build_l2(C.CH_PB, C.OP_WRITE,
                                     _auth_request(token)), seq=0))
    keys = derive_v2_keys(token, RANDOM_APP, RANDOM_DEVICE)
    # deviceSign covers randomDevice || randomApp — the reverse of the HKDF
    # salt — see miwear.crypto.sign_message.
    sign = sign_hmac(keys.device_key,
                     sign_message(RANDOM_APP, RANDOM_DEVICE)) \
        if with_signature else b"\x00" * 32
    builder.device(build_data(build_l2(C.CH_PB, C.OP_WRITE,
                                       _auth_response(sign=sign)),
                              seq=0))

    # --- encrypted business traffic --------------------------------------
    plaintexts = [_plain_business_message(), _second_business_message()]
    for index in range(max(0, encrypted_payloads)):
        plain = plaintexts[index % len(plaintexts)]
        cipher = _encrypt(keys.app_key, plain)
        frame = build_data(build_l2(C.CH_PB, C.OP_WRITE_ENC, cipher),
                           seq=index + 1)
        if fragment:
            builder.host_fragmented(frame, fragment)
        else:
            builder.host(frame)

    # Device answers with deviceKey-encrypted traffic.
    if encrypted_payloads:
        cipher = _encrypt(keys.device_key, _second_business_message())
        frame = build_data(build_l2(C.CH_PB, C.OP_WRITE_ENC, cipher), seq=1)
        if fragment:
            builder.device_fragmented(frame, fragment)
        else:
            builder.device(frame)
    return builder


class _TempCapture:
    """Context manager yielding a path to a written capture."""

    def __init__(self, data: bytes, suffix: str = ".log") -> None:
        self.data = data
        self.suffix = suffix
        self._path: str | None = None

    def __enter__(self) -> str:
        handle, path = tempfile.mkstemp(prefix="miwear-verify-",
                                        suffix=self.suffix)
        with os.fdopen(handle, "wb") as fh:
            fh.write(self.data)
        self._path = path
        return path

    def __exit__(self, *_exc) -> None:
        if self._path:
            try:
                os.unlink(self._path)
            except OSError:  # pragma: no cover - best effort cleanup
                pass


# ---------------------------------------------------------------------------
# btsnoop container + ATT extraction
# ---------------------------------------------------------------------------

class TestBtsnoopWriter:
    """Validate the test helper itself, so failures point at the right layer."""

    def test_file_header_is_exact(self):
        data = btsnoop_file([])
        assert data[:8] == b"btsnoop\x00"
        assert struct.unpack(">I", data[8:12])[0] == 1
        assert struct.unpack(">I", data[12:16])[0] == 1002
        assert len(data) == 16

    def test_record_header_is_24_bytes(self):
        acl = hci_acl(att_write(0x0012, b"\xaa\xbb"))
        data = btsnoop_file([(EPOCH_2024_US, 0, acl)])
        assert len(data) == 16 + 24 + 1 + len(acl)
        orig, incl, flags, drops, ts = struct.unpack(">IIIIq", data[16:40])
        assert orig == incl == 1 + len(acl)
        assert flags & 0x01 == 0
        assert drops == 0
        assert ts == EPOCH_2024_US

    def test_direction_bit(self):
        acl = hci_acl(att_write(0x0011, b"\x01", notify=True))
        data = btsnoop_file([(EPOCH_2024_US, 1, acl)])
        assert struct.unpack(">I", data[24:28])[0] & 1 == 1

    def test_miwear_capture_reads_what_we_wrote(self):
        builder = SnoopBuilder()
        builder.host(b"\xa5\xa5\x03\x00")
        builder.device(b"\xa5\xa5\x03\x01", advance_us=500)
        with _TempCapture(builder.to_bytes()) as path:
            packets = open_capture(path)
            assert len(packets) == 2
            assert packets[0].direction == 0
            assert packets[1].direction == 1
            values = extract_att_values(packets)
            assert [v.value for v in values] == [b"\xa5\xa5\x03\x00",
                                                 b"\xa5\xa5\x03\x01"]
            assert packets[1].timestamp_us - packets[0].timestamp_us == 500

    def test_handle_and_opcode_survive_the_round_trip(self):
        builder = SnoopBuilder()
        builder.host(b"\x00\x01")
        builder.device(b"\x00\x02")
        with _TempCapture(builder.to_bytes()) as path:
            values = extract_att_values(open_capture(path))
        assert values[0].handle == 0x0012
        assert values[0].att_op == "Write Command"
        assert values[1].handle == 0x0011
        assert values[1].att_op == "Handle Value Notification"


def pcap_file(packets, *, link_type: int = 201) -> bytes:
    """Serialise the same records into a classic pcap file.

    Link type 201 is HCI H4 with a 4-byte pseudo-header carrying the
    direction; link type 187 is bare H4 with no direction at all.
    """
    out = bytearray(b"\xd4\xc3\xb2\xa1")           # little-endian, usec
    out += struct.pack("<HHiiii", 2, 4, 0, 0, 65535, link_type)
    for timestamp_us, direction, acl in packets:
        body = b""
        if link_type == C.DLT_BLUETOOTH_HCI_H4_WITH_PHDR:
            body += struct.pack("<I", direction)
        body += bytes([HCI_ACLDATA]) + acl
        out += struct.pack("<IIII", timestamp_us // 1_000_000,
                           timestamp_us % 1_000_000, len(body), len(body))
        out += body
    return bytes(out)


# ---------------------------------------------------------------------------
# Container formats
# ---------------------------------------------------------------------------

class TestCaptureFormats:
    def test_pcap_with_pseudo_header_gives_the_same_verdict(self):
        builder = standard_session(encrypted_payloads=1)
        with _TempCapture(pcap_file(builder.packets), suffix=".pcap") as path:
            report = analyse_capture(path, TOKEN)
        assert report.verdict == "confirmed-iv-is-key"
        assert len(report.adequate_payloads) == 2
        directions = {p.direction for p in report.adequate_payloads}
        assert directions == {"MTU->DEV", "DEV->MTU"}

    def test_pcap_without_direction_warns(self):
        builder = standard_session(encrypted_payloads=1)
        raw = pcap_file(builder.packets,
                        link_type=C.DLT_BLUETOOTH_HCI_H4)
        with _TempCapture(raw, suffix=".pcap") as path:
            report = analyse_capture(path, TOKEN)
        assert any("no packet direction" in w for w in report.warnings)
        # Merged directions must never be reported as a clean confirmation.
        assert report.verdict != "confirmed-iv-is-key"

    def test_pcapng_is_reported_clearly(self):
        data = b"\x0a\x0d\x0d\x0a" + b"\x00" * 60
        with _TempCapture(data, suffix=".pcapng") as path:
            try:
                analyse_capture(path, TOKEN)
            except Exception as exc:      # noqa: BLE001 - must be a clear error
                assert "pcapng" in str(exc)
            else:                          # pragma: no cover - defensive
                raise AssertionError("pcapng should not parse as a capture")

    def test_non_short_uuid_handles_still_work(self):
        """Real GATT attribute handles are not the 0x005E/0x005F UUIDs."""
        builder = standard_session(encrypted_payloads=1)
        # Re-wrap each ACL packet with the ATT handles a real capture shows.
        # Layout: HCI header(4) | L2CAP len+cid(4) | ATT op(1) | handle(2)
        handle_offset = 4 + 4 + 1
        rewrapped = []
        for timestamp_us, direction, acl in builder.packets:
            body = bytearray(acl)
            handle = struct.unpack_from("<H", body, handle_offset)[0]
            new_handle = (0x0027 if handle == builder.handle_write else 0x0026)
            struct.pack_into("<H", body, handle_offset, new_handle)
            rewrapped.append((timestamp_us, direction, bytes(body)))
        with _TempCapture(btsnoop_file(rewrapped)) as path:
            report = analyse_capture(path, TOKEN)
        assert report.verdict == "confirmed-iv-is-key"
        assert any("0x0027" in w for w in report.warnings)
        assert any("0x0026" in w for w in report.warnings)

class TestCheckProtobuf:
    def test_real_message_accepted(self):
        check = check_protobuf(_plain_business_message())
        assert check.ok
        assert check.fields
        assert check.coverage == 1.0

    def test_empty_rejected(self):
        check = check_protobuf(b"")
        assert not check.ok
        assert "empty" in check.reason

    def test_field_zero_rejected(self):
        assert not check_protobuf(b"\x00\x01").ok

    def test_wire_type_six_rejected(self):
        # key = (1 << 3) | 6 -> wire type 6 never existed
        assert not check_protobuf(b"\x0e\x00\x00\x00").ok

    def test_length_overrun_rejected(self):
        # field 7, wire 2, length 5, only 3 bytes follow
        assert not check_protobuf(b"\x3a\x05abc").ok

    def test_truncated_varint_rejected(self):
        # field 1, varint, continuation bit set, then end of buffer
        assert not check_protobuf(b"\x08\x80").ok

    def test_degenerate_single_varint_rejected(self):
        assert not check_protobuf(b"\x08\x01").ok

    def test_degenerate_accepted_when_not_strict(self):
        assert check_protobuf(b"\x08\x01", strict=False).ok

    def test_random_bytes_mostly_rejected(self):
        """A sanity bound: random data usually fails the plausibility test.

        Seeded and deterministic — no reliance on timing or os.urandom.
        """
        import random
        rng = random.Random(0xC0FFEE)
        accepted = 0
        for _ in range(64):
            blob = bytes(rng.randrange(256) for _ in range(24))
            if check_protobuf(blob).ok:
                accepted += 1
        assert accepted <= 8, f"{accepted}/64 random buffers looked like protobuf"


# ---------------------------------------------------------------------------
# CTR variants
# ---------------------------------------------------------------------------

class TestCtrVariants:
    def test_primary_variant_is_iv_equals_key(self):
        key = bytes(range(16))
        variants = v2_ctr_variants(key)
        assert variants[0].name == "iv=key"
        assert variants[0].iv == key
        assert variants[0].family == "v2"

    def test_ccm_layouts_are_labelled_legacy(self):
        variants = v2_ctr_variants(bytes(range(16)))
        legacy = {v.name for v in variants if v.family == "v1-legacy"}
        assert legacy, "the V1-CCM hypotheses must stay in the list"
        assert not any(v.family == "v2" for v in variants[1:]
                       if "ccm" in v.name)

    def test_variants_are_unique(self):
        variants = v2_ctr_variants(bytes(16))
        signatures = {(v.iv, v.counter, v.counter_little_endian)
                      for v in variants}
        assert len(signatures) == len(variants)

    def test_explicit_iv(self):
        key = bytes(range(16))
        iv = bytes(range(16, 32))
        variants = build_ctr_variants(key, iv)
        assert variants[0].name == "iv=explicit"
        assert variants[0].iv == iv

    def test_legacy_iv4_plugs_in(self):
        key = bytes(range(16))
        variants = build_ctr_variants(key, legacy_iv4=b"\xde\xad\xbe\xef")
        names = [v.name for v in variants]
        assert "iv4/left+counter0" in names
        assert "iv4/right-le" in names

    def test_wrong_key_size_rejected(self):
        with pytest.raises(VerifyError):
            v2_ctr_variants(b"\x00" * 8)

    def test_primary_decrypts_what_we_encrypted(self):
        keys = _keys()
        plain = _plain_business_message()
        cipher = _encrypt(keys.app_key, plain)
        diagnostics = diagnose_ctr([("appKey", keys.app_key)], cipher)
        winners = [d for d in diagnostics if d.ok and d.is_source_derived]
        assert len(winners) == 1
        assert winners[0].plaintext == plain

    def test_wrong_key_does_not_produce_valid_protobuf(self):
        keys = _keys()
        cipher = _encrypt(keys.app_key, _plain_business_message())
        diagnostics = diagnose_ctr([("deviceKey", keys.device_key)], cipher)
        assert not any(d.ok for d in diagnostics)

    def test_short_ciphertext_is_not_judged(self):
        assert diagnose_ctr([("k", bytes(16))], b"\x01\x02") == []


# ---------------------------------------------------------------------------
# Token parsing
# ---------------------------------------------------------------------------

class TestParseToken:
    def test_plain_hex(self):
        assert parse_token("0011223344556677") == bytes.fromhex(
            "0011223344556677")

    def test_separators_and_prefix(self):
        assert parse_token("0x00:11 22-33_44,55 66 77 88") == bytes.fromhex(
            "001122334455667788")

    def test_odd_length_rejected(self):
        with pytest.raises(VerifyError):
            parse_token("abc")

    def test_non_hex_rejected(self):
        with pytest.raises(VerifyError):
            parse_token("zzzzzzzzzzzzzzzz")

    def test_empty_rejected(self):
        with pytest.raises(VerifyError):
            parse_token("   ")

    def test_too_short_rejected(self):
        with pytest.raises(VerifyError):
            parse_token("0011")


# ---------------------------------------------------------------------------
# ATT stream selection
# ---------------------------------------------------------------------------

class TestStreamSelection:
    def _value(self, handle: int, payload: bytes, direction: int = 0,
               timestamp: int = 0) -> AttValue:
        return AttValue(timestamp_us=timestamp, direction=direction,
                        handle=handle, value=payload, att_op="Write Command")

    def test_picks_the_handle_with_valid_frames(self):
        frame = build_data(build_l2(C.CH_PB, C.OP_WRITE, b"\x08\x01"), seq=1)
        values = [
            self._value(0x0003, b"garbage-not-a-frame"),
            self._value(0x0012, frame),
            self._value(0x0012, build_ack(1)),
        ]
        selected, warnings = select_sar_streams(values)
        assert {v.handle for v in selected} == {0x0012}
        # The garbage handle must be reported as ignored.
        assert any("0x0003" in w for w in warnings)

    def test_selection_is_per_direction(self):
        """Writes and notifications live on different handles."""
        host_frame = build_data(build_l2(C.CH_PB, C.OP_WRITE, b"\x08\x01"), seq=1)
        dev_frame = build_ack(1)
        values = [
            self._value(0x0012, host_frame, direction=0),
            self._value(0x0011, dev_frame, direction=1, timestamp=1),
        ]
        selected, _warnings = select_sar_streams(values)
        assert len(selected) == 2, "both directions must survive selection"

    def test_falls_back_to_everything(self):
        values = [self._value(0x0099, b"not a frame")]
        selected, warnings = select_sar_streams(values)
        assert len(selected) == 1
        assert warnings and "CRC-valid" in warnings[0]

    def test_empty_input_warns(self):
        selected, warnings = select_sar_streams([])
        assert selected == []
        assert warnings


# ---------------------------------------------------------------------------
# Frame splitting and fragmentation
# ---------------------------------------------------------------------------

class TestFraming:
    def test_split_frames_maps_att_values(self):
        builder = SnoopBuilder()
        frame = build_data(build_l2(C.CH_PB, C.OP_WRITE, b"\x08\x01"), seq=3)
        builder.host(frame)
        with _TempCapture(builder.to_bytes()) as path:
            values = extract_att_values(open_capture(path))
        records, truncated = split_frames(values, "MTU->DEV")
        assert not truncated
        assert len(records) == 1
        assert records[0].frame.seq == 3
        assert records[0].att_values == values

    def test_frame_spanning_several_att_writes(self):
        builder = standard_session(encrypted_payloads=1, fragment=7)
        with _TempCapture(builder.to_bytes()) as path:
            values = extract_att_values(open_capture(path))
        records, _truncated = split_frames(values, "MTU->DEV")
        health = analyse_fragmentation(records, values)
        assert health["cross_att_frames"] >= 1
        assert health["max_writes_per_frame"] >= 2

    def test_one_att_write_holding_several_frames(self):
        builder = SnoopBuilder()
        two = build_ack(1) + build_ack(2)
        builder.host(two)
        with _TempCapture(builder.to_bytes()) as path:
            values = extract_att_values(open_capture(path))
        records, _ = split_frames(values, "MTU->DEV")
        health = analyse_fragmentation(records, values)
        assert len(records) == 2
        assert health["writes_carrying_multiple_frames"] == 1


# ---------------------------------------------------------------------------
# Auth nonce recovery
# ---------------------------------------------------------------------------

class TestAuthNonces:
    def test_structured_recovery(self):
        builder = standard_session(encrypted_payloads=0)
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path)
        assert report.nonces.random_app == RANDOM_APP
        assert report.nonces.random_device == RANDOM_DEVICE
        assert report.nonces.complete

    def test_device_sign_verifies(self):
        builder = standard_session(encrypted_payloads=0)
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, TOKEN)
        assert report.signature["status"] == "ok"
        assert report.signature["present"]

    def test_wrong_token_makes_signature_fail(self):
        builder = standard_session(encrypted_payloads=0)
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, b"\xff" * 16)
        assert report.signature["status"] == "mismatch"
        assert any("deviceSign" in w for w in report.warnings)

    def test_device_sign_uses_reversed_operand_order(self):
        """deviceSign covers randomDevice||randomApp, not app-first.

        This is the trap in WearAuthV2.k(): the HKDF salt is app-first but
        the signed message is device-first. A verifier that reuses one
        buffer order for both rejects every real capture.
        """
        keys = _keys()
        device_first = sign_hmac(
            keys.device_key, sign_message(RANDOM_APP, RANDOM_DEVICE))
        app_first = sign_hmac(keys.device_key, RANDOM_APP + RANDOM_DEVICE)
        assert device_first != app_first

        builder = standard_session(encrypted_payloads=0)  # uses sign_message
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, TOKEN)
        assert report.signature["status"] == "ok"

    def test_truncated_signature_is_prefix_only_not_ok(self):
        """ByteUtil.equals() compares min(len) bytes — do not inherit that bug."""
        keys = _keys()
        full = sign_hmac(keys.device_key,
                         sign_message(RANDOM_APP, RANDOM_DEVICE))
        builder = SnoopBuilder()
        builder.host(build_data(build_l2(C.CH_PB, C.OP_WRITE,
                                         _auth_request(TOKEN)), seq=1))
        builder.device(build_data(build_l2(C.CH_PB, C.OP_WRITE,
                                           _auth_response(sign=full[:8])),
                                  seq=1))
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, TOKEN)
        assert report.signature["status"] == "prefix-only"
        assert report.signature["captured_len"] == 8
        assert any("prefix" in w for w in report.warnings)

    def test_full_length_comparison_rejects_a_short_signature(self):
        """A 1-byte signature must never count as verified."""
        keys = _keys()
        full = sign_hmac(keys.device_key,
                         sign_message(RANDOM_APP, RANDOM_DEVICE))
        builder = SnoopBuilder()
        builder.host(build_data(build_l2(C.CH_PB, C.OP_WRITE,
                                         _auth_request(TOKEN)), seq=1))
        builder.device(build_data(build_l2(C.CH_PB, C.OP_WRITE,
                                           _auth_response(sign=full[:1])),
                                  seq=1))
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, TOKEN)
        assert report.signature["status"] == "prefix-only"
        assert report.signature["status"] != "ok"

    def test_signature_never_upgrades_an_undetermined_verdict(self):
        """A verified deviceSign alone must not confirm the CTR hypothesis."""
        keys = _keys()
        builder = standard_session(encrypted_payloads=0)
        # Encrypt with a completely unrelated key: signature still passes.
        builder.host(build_data(build_l2(C.CH_PB, C.OP_WRITE_ENC,
                                         _encrypt(b"\x42" * 16,
                                                  _plain_business_message())),
                                seq=9))
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, TOKEN)
        assert report.signature["status"] == "ok"
        assert report.verdict != "confirmed-iv-is-key"

    def test_missing_nonces_reported(self):
        builder = SnoopBuilder()
        builder.host(build_cmd(C.CMD_L1START_REQ, default_start_config()))
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, TOKEN)
        assert not report.nonces.complete
        assert any("auth nonces not found" in w for w in report.warnings)


# ---------------------------------------------------------------------------
# The headline verdict
# ---------------------------------------------------------------------------

class TestVerdict:
    def test_confirmed_when_everything_decrypts(self):
        builder = standard_session(encrypted_payloads=2)
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, TOKEN)
        assert report.verdict == "confirmed-iv-is-key"
        assert len(report.adequate_payloads) == 3
        assert all(p.resolved_source_derived for p in report.adequate_payloads)
        assert "deviceSign also verified" in report.verdict_note

    def test_app_and_device_keys_are_direction_specific(self):
        builder = standard_session(encrypted_payloads=1)
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, TOKEN)
        by_direction = {p.direction: p for p in report.adequate_payloads}
        assert by_direction["MTU->DEV"].winning.variant.name == "iv=key"
        assert by_direction["DEV->MTU"].winning.variant.name == "iv=key"
        assert by_direction["MTU->DEV"].key_label.startswith("appKey")
        assert by_direction["DEV->MTU"].key_label.startswith("deviceKey")

    def test_plaintext_round_trips_through_the_capture(self):
        builder = standard_session(encrypted_payloads=2)
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, TOKEN)
        plaintexts = [p.plaintext for p in report.adequate_payloads]
        assert _plain_business_message() in plaintexts

    def test_no_token_is_insufficient_data(self):
        builder = standard_session(encrypted_payloads=1)
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path)
        assert report.verdict == "insufficient-data"
        assert any("no --token" in w for w in report.warnings)

    def test_wrong_token_is_undetermined(self):
        builder = standard_session(encrypted_payloads=1)
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, b"\x99" * 16)
        assert report.verdict in ("undetermined", "insufficient-data")
        assert report.verdict != "confirmed-iv-is-key"

    def test_no_encrypted_traffic(self):
        builder = standard_session(encrypted_payloads=0)
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, TOKEN)
        assert report.verdict == "no-encrypted-traffic"

    def test_explicit_key_works_without_a_token(self):
        key = bytes.fromhex("5f" * 16)
        builder = SnoopBuilder()
        cipher = _encrypt(key, _plain_business_message())
        builder.host(build_data(build_l2(C.CH_PB, C.OP_WRITE_ENC, cipher), seq=1))
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, explicit_keys=[("--key[0]", key)])
        assert report.verdict == "confirmed-iv-is-key"
        assert report.adequate_payloads[0].key_label.startswith("--key[0]")

    def test_partial_evidence_is_not_a_confirmation(self):
        """One good payload and one undecryptable one must not add up to a win."""
        keys = _keys()
        builder = SnoopBuilder()
        builder.host(build_data(build_l2(C.CH_PB, C.OP_WRITE,
                                         _auth_request(TOKEN)), seq=1))
        builder.device(build_data(build_l2(C.CH_PB, C.OP_WRITE,
                                           _auth_response()), seq=1))
        cipher = _encrypt(keys.app_key, _plain_business_message())
        builder.host(build_data(build_l2(C.CH_PB, C.OP_WRITE_ENC, cipher), seq=2))
        builder.host(build_data(build_l2(C.CH_PB, C.OP_WRITE_ENC,
                                         bytes(range(40))), seq=3))
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, TOKEN)
        assert report.verdict == "partial"
        assert report.adequate_payloads[0].resolved
        assert not report.adequate_payloads[1].resolved

    def test_fallback_layout_produces_contradiction(self):
        """If a capture used a different CTR layout we must say so, loudly."""
        keys = _keys()
        # Encrypt the way the (wrong) 12-byte-CCM hypothesis would, using
        # the 4-byte appIV that the V2 key material also carries.
        legacy = next(v for v in build_ctr_variants(
            keys.app_key, legacy_iv4=keys.app_iv)
            if v.name == "ccm-nonce-style/be")
        cipher = legacy.apply(keys.app_key, _plain_business_message())
        builder = SnoopBuilder()
        builder.host(build_data(build_l2(C.CH_PB, C.OP_WRITE,
                                         _auth_request(TOKEN)), seq=1))
        builder.device(build_data(build_l2(C.CH_PB, C.OP_WRITE,
                                           _auth_response()), seq=1))
        builder.host(build_data(build_l2(C.CH_PB, C.OP_WRITE_ENC, cipher), seq=2))
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, TOKEN)
        payload = report.adequate_payloads[0]
        assert payload.resolved
        assert not payload.resolved_source_derived
        assert report.verdict == "contradicts-source"
        assert legacy.name in report.verdict_note

    def test_key_direction_mixup_is_reported(self):
        """Traffic decrypted with the wrong side's key must be called out.

        The IV rule still holds (the payload *did* decrypt), but a user
        swapping deviceKey/appKey needs to see it rather than assume the
        capture is broken.
        """
        keys = _keys()
        builder = SnoopBuilder()
        builder.host(build_data(build_l2(C.CH_PB, C.OP_WRITE,
                                         _auth_request(TOKEN)), seq=1))
        builder.device(build_data(build_l2(C.CH_PB, C.OP_WRITE,
                                           _auth_response()), seq=1))
        # App traffic encrypted with deviceKey — the mix-up.
        cipher = _encrypt(keys.device_key, _plain_business_message())
        builder.host(build_data(build_l2(C.CH_PB, C.OP_WRITE_ENC, cipher), seq=2))
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, TOKEN)
        payload = report.adequate_payloads[0]
        assert payload.resolved
        assert payload.winning.key_label == "deviceKey"
        assert not payload.primary_diagnostics[0].ok
        assert "key↔direction" in report.verdict_note

    def test_source_derived_wins_over_a_coincidental_fallback(self):
        """A fallback that also "works" must never outrank IV=key."""
        keys = _keys()
        cipher = _encrypt(keys.app_key, _plain_business_message())
        payload = analyse_capture.__globals__  # keep linters quiet
        del payload
        from miwear.verify import analyse_payloads, FrameRecord
        frame = build_data(build_l2(C.CH_PB, C.OP_WRITE_ENC, cipher), seq=1)
        att = AttValue(timestamp_us=1, direction=0, handle=0x12,
                       value=frame, att_op="Write Command")
        record = FrameRecord(frame=list(split_frames([att], "MTU->DEV")[0])[0].frame,
                             direction="MTU->DEV", att_values=[att])
        reports = analyse_payloads([record], {"appKey": keys.app_key,
                                              "deviceKey": keys.device_key})
        assert reports[0].winning.is_source_derived


# ---------------------------------------------------------------------------
# Health checks
# ---------------------------------------------------------------------------

class TestHealthChecks:
    def test_crc_pass_rate(self):
        builder = standard_session(encrypted_payloads=1)
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, TOKEN)
        assert report.l1_health["crc_bad"] == 0
        assert report.l1_health["crc_pass_rate"] == 1.0

    def test_corrupt_frame_is_counted(self):
        builder = SnoopBuilder()
        broken = bytearray(build_data(build_l2(C.CH_PB, C.OP_WRITE, b"\x08\x01"),
                                       seq=1))
        broken[-1] ^= 0xFF
        builder.host(bytes(broken))
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, TOKEN)
        assert report.l1_health["crc_bad"] == 1
        assert report.l1_health["bad_crc_offsets"] == [0]

    def test_sequence_gap_detected(self):
        builder = SnoopBuilder()
        builder.host(build_data(build_l2(C.CH_PB, C.OP_WRITE, b"\x08\x01"), seq=1))
        builder.host(build_data(build_l2(C.CH_PB, C.OP_WRITE, b"\x08\x02"), seq=5))
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, TOKEN)
        assert report.l1_health["seq_gap_count"] >= 1
        assert report.l1_health["seq_gaps"][0]["expected"] == 2
        assert report.l1_health["seq_gaps"][0]["got"] == 5

    def test_retransmission_detected(self):
        builder = SnoopBuilder()
        builder.host(build_data(build_l2(C.CH_PB, C.OP_WRITE, b"\x08\x01"), seq=1))
        builder.host(build_data(build_l2(C.CH_PB, C.OP_WRITE, b"\x08\x01"), seq=1))
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, TOKEN)
        assert report.l1_health["retransmissions"] == 1

    def test_handshake_window(self):
        builder = standard_session(encrypted_payloads=0)
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, TOKEN)
        assert report.handshake["requests"] == 1
        assert report.handshake["responses"] == 1
        assert report.handshake["negotiated_window"] == C.SAR_DEFAULT_TX_WIN
        assert report.handshake["cum_ack_threshold"] == \
            C.SAR_DEFAULT_TX_WIN * 2 // 3

    def test_ack_within_budget(self):
        builder = SnoopBuilder()
        builder.host(build_data(build_l2(C.CH_PB, C.OP_WRITE, b"\x08\x01"), seq=1))
        builder.device(build_ack(1), advance_us=200_000)
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, TOKEN)
        ack = report.ack_health
        assert ack["acks"] == 1
        assert ack["acked_frames"] == 1
        assert ack["unacked_frames"] == 0
        assert ack["budget_compliant"] is True

    def test_late_ack_violates_the_500ms_budget(self):
        builder = SnoopBuilder()
        builder.host(build_data(build_l2(C.CH_MASS, C.OP_WRITE, b"\x08\x01"), seq=1))
        builder.device(build_ack(1), advance_us=1_400_000)
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, TOKEN)
        ack = report.ack_health
        assert ack["budget_compliant"] is False
        assert ack["budget_violations"]

    def test_unacked_data_frame_is_counted(self):
        builder = SnoopBuilder()
        builder.host(build_data(build_l2(C.CH_PB, C.OP_WRITE, b"\x08\x01"), seq=1))
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, TOKEN)
        assert report.ack_health["unacked_frames"] == 1

    def test_network_channel_needs_no_ack(self):
        builder = SnoopBuilder()
        builder.host(build_data(build_l2(C.CH_NETWORK, C.OP_WRITE, b"\x08\x01"),
                                seq=1))
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, TOKEN)
        ack = report.ack_health
        assert ack["no_ack_channel_frames"] == 1
        assert ack["unacked_frames"] == 0

    def test_analyse_acks_is_pure(self):
        """Calling the helper directly must not depend on a capture file."""
        assert analyse_acks([])["acked_frames"] == 0


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

class TestRender:
    def _report(self) -> CaptureReport:
        builder = standard_session(encrypted_payloads=2)
        with _TempCapture(builder.to_bytes()) as path:
            return analyse_capture(path, TOKEN)

    def test_text_report_contains_the_key_sections(self):
        text = render_report(self._report())
        for heading in ("[verdict]", "[keys]", "[CTR variants]", "[L1 framing]",
                        "[fragmentation]", "[ACKs]", "[handshake]"):
            assert heading in text
        assert "CONFIRMED" in text
        assert "iv=key" in text

    def test_brief_hides_losing_variants(self):
        report = self._report()
        full = render_report(report, show_variants=True)
        brief = render_report(report, show_variants=False)
        assert len(brief.splitlines()) < len(full.splitlines())

    def test_json_is_serialisable(self):
        payload = self._report().to_dict()
        text = json.dumps(payload)
        decoded = json.loads(text)
        assert decoded["verdict"] == "confirmed-iv-is-key"
        assert decoded["nonces"]["randomApp"] == RANDOM_APP.hex()
        assert decoded["payloads"]

    def test_report_of_an_empty_capture(self):
        builder = SnoopBuilder()
        with _TempCapture(builder.to_bytes()) as path:
            report = analyse_capture(path, TOKEN)
        text = render_report(report)
        assert "no value-bearing ATT PDUs" in text
        assert report.verdict == "no-encrypted-traffic"


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
#
# The repository's own runner instantiates test classes with no arguments and
# calls the methods directly, so setup_method/teardown_method/__init__ are not
# available.  Every test therefore owns its temporary file through a context
# manager and cleans up on exit.

class TestCommandLine:
    def _capture(self, payload: bytes) -> "_TempCapture":
        return _TempCapture(payload)

    def _stdout(self, argv):
        import contextlib
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = verify_main(argv)
        return code, buffer.getvalue()

    def test_exit_zero_when_confirmed(self):
        builder = standard_session(encrypted_payloads=1)
        with _TempCapture(builder.to_bytes()) as path:
            code, out = self._stdout([path, "--token", TOKEN.hex()])
        assert code == 0
        assert "CONFIRMED" in out

    def test_json_flag(self):
        builder = standard_session(encrypted_payloads=1)
        with _TempCapture(builder.to_bytes()) as path:
            code, out = self._stdout([path, "--token", TOKEN.hex(), "--json"])
        assert code == 0
        payload = json.loads(out)
        assert payload["verdict"] == "confirmed-iv-is-key"

    def test_bad_token_exits_two(self):
        builder = standard_session(encrypted_payloads=1)
        with _TempCapture(builder.to_bytes()) as path:
            code, _out = self._stdout([path, "--token", "not-hex"])
        assert code == 2

    def test_missing_file_exits_two(self):
        code, _out = self._stdout(["does-not-exist.log", "--token", "00" * 16])
        assert code == 2

    def test_not_a_capture_exits_two(self):
        with _TempCapture(b"this is not a capture file") as path:
            code, _out = self._stdout([path, "--token", TOKEN.hex()])
        assert code == 2

    def test_explicit_key_flag(self):
        key = bytes.fromhex("77" * 16)
        builder = SnoopBuilder()
        cipher = _encrypt(key, _plain_business_message())
        builder.host(build_data(build_l2(C.CH_PB, C.OP_WRITE_ENC, cipher), seq=1))
        with _TempCapture(builder.to_bytes()) as path:
            code, out = self._stdout([path, "--key", key.hex()])
        assert code == 0
        assert "CONFIRMED" in out

    def test_brief_flag_shortens_output(self):
        builder = standard_session(encrypted_payloads=1)
        with _TempCapture(builder.to_bytes()) as path:
            _code, full = self._stdout([path, "--token", TOKEN.hex()])
            _code, brief = self._stdout([path, "--token", TOKEN.hex(),
                                        "--brief"])
        assert len(brief.splitlines()) < len(full.splitlines())

    def test_standalone_parser_accepts_the_same_arguments(self):
        """``python -m miwear.verify`` must understand what cli.py will pass."""
        from miwear.verify import build_parser
        args = build_parser().parse_args(["x.log", "--token", "00" * 16,
                                          "--key", "11" * 16, "--json"])
        assert args.path == "x.log"
        assert args.key == ["11" * 16]
        assert args.json is True


# ---------------------------------------------------------------------------
# Helpers used by the standalone runner below
# ---------------------------------------------------------------------------

def _iter_tests(module):
    """Mirror of :func:`tests.run_tests._iter_tests`, for standalone runs."""
    for name, obj in vars(module).items():
        if name.startswith("test_") and inspect.isfunction(obj):
            yield name, obj
        elif name.startswith("Test") and inspect.isclass(obj):
            for attr in dir(obj):
                if attr.startswith("test_"):
                    yield f"{name}.{attr}", getattr(obj, attr)


def _run_standalone() -> int:
    """Run this module's tests without pytest installed."""
    passed = failed = 0
    failures = []
    for label, fn in _iter_tests(sys.modules[__name__]):
        owner = label.split(".")[0]
        cls = getattr(sys.modules[__name__], owner, None)
        bound = fn
        if cls is not None and inspect.isclass(cls):
            bound = getattr(cls(), fn.__name__)
        try:
            bound()
        except BaseException as exc:  # noqa: BLE001
            failed += 1
            failures.append((label, exc))
            print(f"  [FAIL] {label}")
            traceback.print_exc(limit=2)
        else:
            passed += 1
            print(f"  [PASS] {label}")
    print(f"\n{passed}/{passed + failed} passed")
    for label, exc in failures:
        print(f"  - {label}: {exc!r}")
    return 0 if not failures else 1


if __name__ == "__main__":  # pragma: no cover
    # Ensure `import miwear` works when run as `python tests/test_verify.py`.
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    raise SystemExit(_run_standalone())
