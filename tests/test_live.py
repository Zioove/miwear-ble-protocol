"""Tests for :mod:`miwear.live` — the real-device BLE link.

Two things are special about this suite:

* **No hardware and no ``bleak``.**  Every test drives the session through
  :class:`FakeTransport`, and one test spawns a subprocess to prove that
  ``import miwear.live`` never imports bleak at module level.
* **Framing is the fragile part.**  The majority of the tests here attack
  the L1 reassembly: a frame split at *every* byte boundary, several frames
  inside one ATT write, junk between frames, and a plausible-but-impossible
  header length.
"""

from __future__ import annotations

import asyncio
import pathlib
import subprocess
import sys

import pytest

from miwear import constants as C
from miwear import live
from miwear.crc import crc16_arc
from miwear.crypto import aes_ctr_crypt, derive_v2_keys
from miwear.layer_l1 import build_ack, build_frame, default_start_config
from miwear.layer_l2 import build_l2
from miwear.protobuf import decode as proto_decode
from miwear.protobuf import encode_field_bytes, encode_field_varint

ROOT = pathlib.Path(__file__).resolve().parent.parent
ADDRESS = "AA:BB:CC:DD:EE:FF"


# ---------------------------------------------------------------------------
# A transport that pretends to be a band
# ---------------------------------------------------------------------------

class FakeTransport(live.Transport):
    """In-memory :class:`miwear.live.Transport` used by every test."""

    def __init__(self, *, version: bytes = b"\x01\x00\x00", mtu: int = 23,
                 devices=None) -> None:
        self.firmware = version
        self._mtu = mtu
        self._connected = False
        self.devices = list(devices) if devices is not None else [
            live.DeviceInfo(ADDRESS, "Mi Band", -40, (C.SERVICE_UUID,)),
        ]
        self.written: list[tuple[str, bytes, bool]] = []
        self.read_uuids: list[str] = []
        self.mtu_requests: list[int] = []
        self.notify_started: list[str] = []
        self.notify_stopped: list[str] = []
        self.connect_args: list[str] = []
        self.disconnects = 0
        self.callback = None

    # -- discovery ---------------------------------------------------------

    async def scan(self, *, timeout=5.0, name_filter=None):
        return list(self.devices)

    # -- link --------------------------------------------------------------

    async def connect(self, address, *, timeout=10.0):
        self.connect_args.append(address)
        self._connected = True

    async def disconnect(self):
        self.disconnects += 1
        self._connected = False

    @property
    def is_connected(self):
        return self._connected

    @property
    def mtu(self):
        return self._mtu

    async def request_mtu(self, mtu):
        self.mtu_requests.append(mtu)
        self._mtu = max(self._mtu, mtu)
        return self._mtu

    # -- GATT --------------------------------------------------------------

    async def read(self, uuid):
        self.read_uuids.append(uuid)
        return self.firmware

    async def write(self, uuid, data, *, response=True):
        assert self._connected, "write on a closed link"
        self.written.append((uuid, bytes(data), response))

    async def start_notify(self, uuid, callback):
        self.notify_started.append(uuid)
        self.callback = callback

    async def stop_notify(self, uuid):
        self.notify_stopped.append(uuid)
        self.callback = None

    # -- test helpers ------------------------------------------------------

    @property
    def stream(self) -> bytes:
        """Everything written to 0x005F, concatenated."""
        return b"".join(data for uuid, data, _r in self.written
                        if uuid == C.CHAR_SAR_WRITE)

    def emit(self, data: bytes) -> None:
        """Simulate a device notification."""
        assert self.callback is not None, "notifications are not enabled"
        self.callback(C.CHAR_SAR_NOTIFY, data)


def _data_frame(seq: int, channel: int = C.CH_PB, opcode: int = C.OP_WRITE,
                payload: bytes = b"\x08\x01") -> bytes:
    return build_frame(C.TYPE_DATA, seq, build_l2(channel, opcode, payload))


def _start_rsp(seq: int = 0) -> bytes:
    return build_frame(C.TYPE_CMD, seq,
                       bytes([C.CMD_L1START_RSP]) + default_start_config(),
                       frx=1)


def _open_session(transport=None, **kwargs) -> tuple[live.LiveSession,
                                                     FakeTransport]:
    transport = transport or FakeTransport()
    session = live.LiveSession(transport, **kwargs)
    return session, transport


# ---------------------------------------------------------------------------
# Optional dependency — must never be a hard import
# ---------------------------------------------------------------------------

class TestOptionalDependency:
    def test_import_does_not_import_bleak(self):
        """A fresh interpreter must import the module with bleak absent."""
        code = (
            "import sys\n"
            "import miwear.live as live\n"
            "assert 'bleak' not in sys.modules, sorted(sys.modules)\n"
            "assert hasattr(live, 'main')\n"
            "sys.exit(0)\n"
        )
        proc = subprocess.run([sys.executable, "-c", code], cwd=str(ROOT),
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
        assert proc.returncode == 0, "importing miwear.live pulled in bleak"

    def test_no_module_level_bleak_import(self):
        source = (ROOT / "miwear" / "live.py").read_text(encoding="utf-8")
        offenders = [line for line in source.splitlines()
                     if line.startswith(("import bleak", "from bleak"))]
        assert offenders == [], f"top-level bleak import: {offenders}"

    def test_import_bleak_raises_actionable_error(self):
        if live.BleakTransport.available():
            return                      # bleak installed: nothing to prove here
        try:
            live._import_bleak()
        except live.LiveDependencyError as exc:
            message = str(exc)
        else:
            raise AssertionError("bleak import should have failed")
        assert "bleak" in message and "pip install" in message

    def test_connect_without_bleak_is_a_clean_error(self):
        if live.BleakTransport.available():
            return
        transport = live.BleakTransport()

        async def go():
            await transport.connect(ADDRESS)

        with pytest.raises(live.LiveDependencyError):
            asyncio.run(go())

    def test_available_reports_importability(self):
        assert isinstance(live.BleakTransport.available(), bool)

    def test_cli_reports_missing_dependency(self):
        if live.BleakTransport.available():
            return
        errors = []

        class _Sink:
            def write(self, text):
                errors.append(text)

            def flush(self):
                pass

        import contextlib
        with contextlib.redirect_stderr(_Sink()):
            code = live.main(["scan", "--timeout", "0.1"])
        assert code == 2
        assert "bleak" in "".join(errors)

    def test_bleak_transport_constructs_without_dependency(self):
        transport = live.BleakTransport()
        assert transport.mtu == live.DEFAULT_MTU
        assert transport.is_connected is False


# ---------------------------------------------------------------------------
# L1 reassembly
# ---------------------------------------------------------------------------

class TestFrameAssembler:
    def test_whole_frame_in_one_write(self):
        frame = _data_frame(4)
        frames = live.FrameAssembler().feed(frame)
        assert len(frames) == 1
        assert frames[0].seq == 4
        assert frames[0].crc_ok
        assert frames[0].payload == build_l2(C.CH_PB, C.OP_WRITE, b"\x08\x01")

    def test_frame_split_at_every_boundary(self):
        """A frame may arrive in any number of ATT writes."""
        frame = build_frame(C.TYPE_DATA, 7, build_l2(C.CH_PB, C.OP_WRITE,
                                                     bytes(range(40))))
        for cut in range(len(frame) + 1):
            assembler = live.FrameAssembler()
            first = assembler.feed(frame[:cut])
            second = assembler.feed(frame[cut:])
            total = first + second
            assert len(total) == 1, f"cut at {cut} produced {len(total)} frames"
            assert total[0].payload == frame[8:]
            assert total[0].crc_ok
            assert assembler.buffered == 0

    def test_byte_at_a_time(self):
        frame = _data_frame(9)
        assembler = live.FrameAssembler()
        out = []
        for byte in frame:
            out.extend(assembler.feed(bytes([byte])))
        assert len(out) == 1
        assert assembler.frames_emitted == 1

    def test_several_frames_in_one_write(self):
        stream = build_ack(1) + _data_frame(2) + build_ack(3)
        frames = live.FrameAssembler().feed(stream)
        assert [f.type_name for f in frames] == ["ACK", "DATA", "ACK"]

    def test_tail_and_next_head_in_one_write(self):
        """A write can carry the tail of one frame and the head of the next."""
        one = _data_frame(1)
        two = _data_frame(2)
        assembler = live.FrameAssembler()
        assert assembler.feed(one[:10]) == []
        joined = assembler.feed(one[10:] + two[:6])
        assert [f.seq for f in joined] == [1]
        assert assembler.buffered == 6
        assert [f.seq for f in assembler.feed(two[6:])] == [2]

    def test_partial_frame_is_not_emitted(self):
        frame = build_frame(C.TYPE_DATA, 5, b"0123456789")
        assembler = live.FrameAssembler()
        assert assembler.feed(frame[:-1]) == []
        assert assembler.buffered == len(frame) - 1
        assert assembler.feed(frame[-1:])[0].payload == b"0123456789"

    def test_empty_feed_is_harmless(self):
        assembler = live.FrameAssembler()
        assert assembler.feed(b"") == []

    def test_junk_between_frames_is_skipped(self):
        stream = b"\x00\x11" + build_ack(1) + b"\xa5\x00\x99" + build_ack(2)
        assembler = live.FrameAssembler()
        frames = assembler.feed(stream)
        assert [f.seq for f in frames] == [1, 2]
        assert assembler.skipped_bytes >= 5

    def test_offsets_are_absolute(self):
        stream = b"\x00\x00" + build_ack(1)
        frames = live.FrameAssembler().feed(stream)
        assert frames[0].offset == 2

    def test_offsets_survive_multiple_writes(self):
        first = build_ack(1)
        assembler = live.FrameAssembler()
        assembler.feed(first)
        frames = assembler.feed(build_ack(2))
        assert frames[0].offset == len(first)

    def test_impossible_length_resynchronises(self):
        """A5A5 inside payload noise must not be trusted as a header."""
        bogus = b"\xa5\xa5\xff\xff"                 # data_len would be 65535
        assembler = live.FrameAssembler(max_frame_size=1024)
        frames = assembler.feed(bogus + build_ack(3))
        assert [f.type_name for f in frames] == ["ACK"]
        assert assembler.skipped_bytes == 4

    def test_crc_failure_is_reported_not_hidden(self):
        frame = bytearray(_data_frame(6))
        frame[-1] ^= 0xFF
        assembler = live.FrameAssembler()
        frames = assembler.feed(bytes(frame))
        assert len(frames) == 1
        assert frames[0].crc_ok is False
        assert assembler.crc_failures == 1

    def test_stats_and_reset(self):
        assembler = live.FrameAssembler()
        assembler.feed(build_ack(1) + b"\x00" + build_ack(2)[:4])
        stats = assembler.stats()
        assert stats["frames"] == 1
        assert stats["buffered"] == 5
        assembler.reset()
        assert assembler.buffered == 0

    def test_reassemble_helper(self):
        frame = build_frame(C.TYPE_DATA, 1, bytes(200))
        chunks = live.fragment(frame, 23)
        frames = live.reassemble(chunks)
        assert len(frames) == 1
        assert frames[0].payload == bytes(200)


class TestFragmentation:
    def test_mtu_minus_three(self):
        chunks = live.fragment(bytes(45), 23)
        assert [len(c) for c in chunks] == [20, 20, 5]

    def test_exact_multiple_has_no_empty_tail(self):
        chunks = live.fragment(bytes(40), 23)
        assert [len(c) for c in chunks] == [20, 20]

    def test_empty_frame(self):
        assert live.fragment(b"", 23) == [b""]

    def test_unusable_mtu_rejected(self):
        with pytest.raises(ValueError):
            live.fragment(b"abc", 3)

    def test_roundtrip_through_fragment_and_reassemble(self):
        payload = bytes(range(256)) + b"tail"
        frame = build_frame(C.TYPE_DATA, 11, payload)
        for mtu in (23, 24, 64, 185, 512):
            chunks = live.fragment(frame, mtu)
            assert b"".join(chunks) == frame
            frames = live.reassemble(chunks)
            assert len(frames) == 1
            assert frames[0].payload == payload
            assert frames[0].seq == 11


# ---------------------------------------------------------------------------
# Version characteristic
# ---------------------------------------------------------------------------

class TestDeviceVersion:
    def test_parses_three_bytes(self):
        version = live.DeviceVersion.parse(b"\x01\x02\x03")
        assert (version.major, version.minor, version.build) == (1, 2, 3)
        assert version.text == "1.2.3"

    def test_sar_for_non_zero_major(self):
        version = live.DeviceVersion.parse(b"\x01\x00\x00")
        assert version.protocol == "sar"
        assert version.is_sar is True

    def test_legacy_for_zero_major(self):
        version = live.DeviceVersion.parse(b"\x00\x09\x09")
        assert version.protocol == "legacy"
        assert version.is_sar is False

    def test_short_payload_is_tolerated(self):
        version = live.DeviceVersion.parse(b"\x02")
        assert version.text == "2.0.0"

    def test_empty_payload_rejected(self):
        with pytest.raises(live.LiveError):
            live.DeviceVersion.parse(b"")


# ---------------------------------------------------------------------------
# Session lifecycle (all against FakeTransport)
# ---------------------------------------------------------------------------

class TestSessionLifecycle:
    def test_open_reads_version_and_subscribes(self):
        async def go():
            session, transport = _open_session()
            version = await session.open(ADDRESS)
            assert version.text == "1.0.0"
            assert transport.connect_args == [ADDRESS]
            assert transport.read_uuids == [C.CHAR_VERSION]
            assert transport.notify_started == [C.CHAR_SAR_NOTIFY]
            assert session.version is version
            assert session.mtu == 23
            assert transport.is_connected

        asyncio.run(go())

    def test_open_without_address_scans(self):
        async def go():
            session, transport = _open_session()
            await session.open(None)
            assert transport.connect_args == [ADDRESS]

        asyncio.run(go())

    def test_open_scans_and_fails_cleanly(self):
        async def go():
            transport = FakeTransport(devices=[])
            session = live.LiveSession(transport)
            with pytest.raises(live.LiveError):
                await session.open(None)
            assert transport.connect_args == []

        asyncio.run(go())

    def test_open_requests_mtu(self):
        async def go():
            session, transport = _open_session()
            await session.open(ADDRESS, request_mtu=247)
            assert transport.mtu_requests == [247]
            assert session.mtu == 247

        asyncio.run(go())

    def test_close_is_idempotent(self):
        async def go():
            session, transport = _open_session()
            await session.open(ADDRESS)
            await session.close()
            await session.close()
            assert transport.disconnects == 2
            assert transport.notify_stopped == [C.CHAR_SAR_NOTIFY] * 2

        asyncio.run(go())

    def test_context_manager_closes(self):
        async def go():
            transport = FakeTransport()
            async with live.LiveSession(transport) as session:
                await session.open(ADDRESS)
            assert transport.disconnects == 1

        asyncio.run(go())

    def test_version_can_be_reread(self):
        async def go():
            session, transport = _open_session()
            await session.open(ADDRESS)
            transport.firmware = b"\x02\x05\x00"
            version = await session.read_version()
            assert version.text == "2.5.0"
            assert version.protocol == "sar"

        asyncio.run(go())

    def test_transport_read_failure_propagates(self):
        async def go():
            transport = FakeTransport()

            async def boom(uuid):
                raise live.TransportError("gatt error 133")

            transport.read = boom
            session = live.LiveSession(transport)
            with pytest.raises(live.TransportError):
                await session.open(ADDRESS)

        asyncio.run(go())


# ---------------------------------------------------------------------------
# Handshake
# ---------------------------------------------------------------------------

class TestHandshake:
    def _run(self, version=b"\x01\x00\x00", *, response=None,
             timeout=0.5, force=False, mtu=23):
        transport = FakeTransport(version=version, mtu=mtu)
        session = live.LiveSession(transport, auto_ack=False)

        async def go():
            await session.open(ADDRESS)
            task = asyncio.ensure_future(session.handshake(timeout=timeout,
                                                           force=force))
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            for chunk in (response if response is not None else [_start_rsp()]):
                await session.feed(chunk)
            return await task

        return asyncio.run(go()), transport, session

    def test_start_request_bytes(self):
        result, transport, _ = self._run()
        assert result.request == build_frame(
            C.TYPE_CMD, 0, bytes([C.CMD_L1START_REQ]) + default_start_config())
        assert result.request.hex().startswith(
            "a5a5020016001d4d0101030001000002020000")
        assert transport.stream.startswith(result.request)

    def test_request_is_fragmented_to_mtu(self):
        result, transport, _ = self._run(mtu=23)
        writes = [len(data) for uuid, data, _r in transport.written
                  if uuid == C.CHAR_SAR_WRITE]
        assert all(size <= 20 for size in writes)
        assert sum(writes) == len(result.request)
        assert b"".join(data for uuid, data, _r in transport.written
                        if uuid == C.CHAR_SAR_WRITE).startswith(result.request)

    def test_response_split_across_writes_is_assembled(self):
        response = _start_rsp()
        chunks = [response[:3], response[3:11], response[11:]]
        result, _transport, _session = self._run(response=chunks)
        assert result.ok
        assert result.response is not None
        assert result.response.payload[:1] == bytes([C.CMD_L1START_RSP])
        assert result.response_cmd == C.CMD_L1START_RSP

    def test_response_tlv_is_decoded(self):
        result, _transport, _session = self._run()
        assert result.remote_mps == C.SAR_DEFAULT_MPS
        assert result.remote_tx_window == C.SAR_DEFAULT_TX_WIN
        assert result.remote_send_timeout_ms == C.SAR_SEND_TIMEOUT_MS
        assert len(result.config["config"]) == 4
        assert result.elapsed_ms >= 0.0

    def test_as_dict_is_json_friendly(self):
        result, _transport, _session = self._run()
        payload = result.as_dict()
        assert payload["version"] == "1.0.0"
        assert payload["protocol"] == "sar"
        assert payload["response_name"] == "CMD_L1START_RSP"
        assert payload["remote_mps"] == C.SAR_DEFAULT_MPS

    def test_legacy_device_is_refused(self):
        transport = FakeTransport(version=b"\x00\x01\x00")
        session = live.LiveSession(transport)

        async def go():
            await session.open(ADDRESS)
            try:
                await session.handshake(timeout=0.1)
            except live.LiveError as exc:
                return str(exc)
            raise AssertionError("legacy device should have been refused")

        message = asyncio.run(go())
        assert "legacy" in message
        assert transport.stream == b""       # nothing was transmitted

    def test_force_overrides_the_version_guard(self):
        transport = FakeTransport(version=b"\x00\x01\x00", mtu=23)
        session = live.LiveSession(transport, auto_ack=False)

        async def go():
            await session.open(ADDRESS)
            task = asyncio.ensure_future(session.handshake(timeout=0.5,
                                                           force=True))
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            await session.feed(_start_rsp())
            return await task

        assert asyncio.run(go()).ok

    def test_timeout_raises(self):
        transport = FakeTransport()
        session = live.LiveSession(transport, auto_ack=False)

        async def go():
            await session.open(ADDRESS)
            with pytest.raises(live.LiveTimeout):
                await session.handshake(timeout=0.05)

        asyncio.run(go())

    def test_reads_version_lazily_when_not_cached(self):
        """A session driven without open() must still learn the version."""
        transport = FakeTransport(version=b"\x01\x00\x00")
        session = live.LiveSession(transport, auto_ack=False)

        async def go():
            await transport.connect(ADDRESS)          # bypass open()
            assert session.version is None
            task = asyncio.ensure_future(session.handshake(timeout=0.5))
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            await session.feed(_start_rsp())
            return await task

        result = asyncio.run(go())
        assert result.ok
        assert session.version is not None
        assert session.version.text == "1.0.0"
        assert transport.read_uuids == [C.CHAR_VERSION]

    def test_cached_version_is_reused_without_a_second_read(self):
        transport = FakeTransport(version=b"\x01\x02\x03")
        session = live.LiveSession(transport, auto_ack=False)

        async def go():
            await session.open(ADDRESS)
            task = asyncio.ensure_future(session.handshake(timeout=0.5))
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            await session.feed(_start_rsp())
            result = await task
            assert result.version.text == "1.2.3"
            assert transport.read_uuids == [C.CHAR_VERSION]

        asyncio.run(go())


# ---------------------------------------------------------------------------
# Receive path: decode, ACK, dispatch
# ---------------------------------------------------------------------------

class TestReceivePath:
    def _session(self, **kwargs):
        transport = FakeTransport(mtu=23)
        return live.LiveSession(transport, **kwargs), transport

    def test_plaintext_data_is_decoded(self):
        session, transport = self._session(auto_ack=False)

        async def go():
            await session.open(ADDRESS)
            payload = encode_field_varint(1, 7) + encode_field_bytes(2, b"hi")
            frames = await session.feed(_data_frame(1, payload=payload))
            assert len(frames) == 1
            frame = frames[0]
            assert frame.type_name == "DATA"
            assert frame.channel == C.CH_PB
            assert frame.opcode == C.OP_WRITE
            assert frame.decoded.proto_fields[1].text == "hi"
            assert frame.crc_ok
            assert session.frames == [frame]

        asyncio.run(go())

    def test_cmd_frame_is_tlv_decoded(self):
        session, _transport = self._session(auto_ack=False)

        async def go():
            await session.open(ADDRESS)
            frames = await session.feed(_start_rsp())
            assert frames[0].decoded.cmd["cmd"] == C.CMD_L1START_RSP
            assert frames[0].needs_ack is False

        asyncio.run(go())

    def test_automatic_ack(self):
        session, transport = self._session()

        async def go():
            await session.open(ADDRESS)
            await session.feed(_data_frame(5))
            assert transport.stream == build_ack(5)
            assert session.stats["acks_sent"] == 1

        asyncio.run(go())

    def test_no_ack_for_channels_without_ack(self):
        session, transport = self._session()

        async def go():
            await session.open(ADDRESS)
            frames = await session.feed(_data_frame(1, channel=C.CH_NETWORK))
            assert frames[0].needs_ack is False
            assert transport.stream == b""
            assert session.stats["acks_sent"] == 0

        asyncio.run(go())

    def test_automatic_ack_can_be_disabled(self):
        session, transport = self._session(auto_ack=False)

        async def go():
            await session.open(ADDRESS)
            await session.feed(_data_frame(1))
            assert transport.stream == b""
            await session.send_ack(1)
            assert transport.stream == build_ack(1)

        asyncio.run(go())

    def test_duplicate_is_acked_but_not_counted_twice(self):
        session, transport = self._session()

        async def go():
            await session.open(ADDRESS)
            await session.feed(_data_frame(5))
            await session.feed(_data_frame(5))
            assert session.stats["duplicates"] == 1
            assert transport.stream == build_ack(5) + build_ack(5)

        asyncio.run(go())

    def test_out_of_order_triggers_nak(self):
        session, transport = self._session()

        async def go():
            await session.open(ADDRESS)
            await session.feed(_data_frame(5))
            await session.feed(_data_frame(7))
            assert session.stats["out_of_order"] == 1
            assert transport.stream == build_ack(5) + build_ack(7, ack=False)
            assert session.stats["naks_sent"] == 1

        asyncio.run(go())

    def test_bad_crc_is_not_acked(self):
        session, transport = self._session()

        async def go():
            await session.open(ADDRESS)
            broken = bytearray(_data_frame(2))
            broken[-1] ^= 0xFF
            frames = await session.feed(bytes(broken))
            assert frames[0].crc_ok is False
            assert transport.stream == b""
            assert session.assembler.crc_failures == 1

        asyncio.run(go())

    def test_encrypted_payload_without_keys_is_reported(self):
        session, _transport = self._session(auto_ack=False)

        async def go():
            await session.open(ADDRESS)
            frames = await session.feed(_data_frame(3, channel=C.CH_LYRA,
                                                   opcode=C.OP_WRITE_ENC,
                                                   payload=b"\x00" * 12))
            assert frames[0].decoded.is_encrypted
            assert frames[0].plaintext is None
            assert "no session key" in frames[0].error
            assert session.stats["encrypted"] == 1

        asyncio.run(go())

    def test_encrypted_payload_is_decrypted_with_installed_keys(self):
        keys = derive_v2_keys(b"token", b"\x01" * 16, b"\x02" * 16)
        session, _transport = self._session(auto_ack=False)
        session.install_keys(keys)
        plain = encode_field_varint(1, 1) + encode_field_bytes(2, b"secret")
        cipher = aes_ctr_crypt(keys.device_key, keys.device_key, 0, plain)

        async def go():
            await session.open(ADDRESS)
            frames = await session.feed(_data_frame(4, channel=C.CH_LYRA,
                                                   opcode=C.OP_WRITE_ENC,
                                                   payload=cipher))
            assert frames[0].plaintext == plain
            assert frames[0].decoded.proto_fields[1].text == "secret"
            assert frames[0].error is None

        asyncio.run(go())

    def test_notification_callback_path(self):
        session, transport = self._session(auto_ack=False)

        async def go():
            await session.open(ADDRESS)
            transport.emit(_data_frame(8))
            await asyncio.sleep(0.05)
            assert [f.seq for f in session.frames] == [8]

        asyncio.run(go())

    def test_next_frame_returns_queued_frame(self):
        session, _transport = self._session(auto_ack=False)

        async def go():
            await session.open(ADDRESS)
            await session.feed(_data_frame(1))
            frame = await session.next_frame(timeout=0.5)
            assert frame.seq == 1

        asyncio.run(go())

    def test_next_frame_times_out(self):
        session, _transport = self._session(auto_ack=False)

        async def go():
            await session.open(ADDRESS)
            with pytest.raises(live.LiveTimeout):
                await session.next_frame(timeout=0.05)

        asyncio.run(go())

    def test_wait_for_scans_backlog(self):
        session, _transport = self._session(auto_ack=False)

        async def go():
            await session.open(ADDRESS)
            await session.feed(_start_rsp())
            await session.feed(_data_frame(2))
            frame = await session.wait_for(lambda f: f.type_name == "DATA",
                                           timeout=0.5)
            assert frame.seq == 2

        asyncio.run(go())

    def test_wait_for_can_skip_the_backlog(self):
        session, _transport = self._session(auto_ack=False)

        async def go():
            await session.open(ADDRESS)
            await session.feed(_data_frame(1))
            task = asyncio.ensure_future(
                session.wait_for(lambda f: True, timeout=0.5,
                                 scan_backlog=False))
            await asyncio.sleep(0)
            await session.feed(_data_frame(2))
            assert (await task).seq == 2

        asyncio.run(go())


# ---------------------------------------------------------------------------
# Send path
# ---------------------------------------------------------------------------

class TestSendPath:
    def _session(self, mtu=23, keys=False):
        transport = FakeTransport(mtu=mtu)
        session = live.LiveSession(transport, auto_ack=False)
        if keys:
            session.install_keys(derive_v2_keys(b"t", b"\x01" * 16, b"\x02" * 16))
        return session, transport

    def test_seq_increments_and_wraps(self):
        session, _transport = self._session()
        session._tx_seq = 254

        async def go():
            await session.open(ADDRESS)
            first = await session.send_l2(C.CH_PB, C.OP_WRITE, b"\x08\x01")
            second = await session.send_l2(C.CH_PB, C.OP_WRITE, b"\x08\x02")
            third = await session.send_l2(C.CH_PB, C.OP_WRITE, b"\x08\x03")
            assert (first.seq, second.seq, third.seq) == (254, 255, 0)

        asyncio.run(go())

    def test_frame_layout(self):
        session, transport = self._session(mtu=247)

        async def go():
            await session.open(ADDRESS)
            result = await session.send_l2(C.CH_MASS, C.OP_WRITE, b"\xde\xad")
            assert result.frame[:2] == b"\xa5\xa5"
            assert result.frame[2] & 0x0F == C.TYPE_DATA
            assert result.l2 == b"\x02\x01\xde\xad"
            assert result.frame[3] == result.seq
            assert result.frame[8:] == result.l2
            assert transport.stream == result.frame

        asyncio.run(go())

    def test_large_payload_is_fragmented(self):
        session, transport = self._session(mtu=23)

        async def go():
            await session.open(ADDRESS)
            await session.send_l2(C.CH_FILE_FITNESS, C.OP_WRITE, bytes(100))
            sizes = [len(data) for _u, data, _r in transport.written]
            assert max(sizes) <= 20
            assert sum(sizes) == 8 + 2 + 100

        asyncio.run(go())

    def test_encrypted_send_uses_app_key(self):
        session, transport = self._session(keys=True)
        plain = encode_field_varint(1, 1)

        async def go():
            await session.open(ADDRESS)
            result = await session.send_l2(C.CH_LYRA, C.OP_WRITE_ENC, plain,
                                           encrypt=True)
            assert result.l2[1] == C.OP_WRITE_ENC
            assert result.l2[2:] != plain
            recovered = aes_ctr_crypt(session.keys.app_key,
                                      session.keys.app_key, 0, result.l2[2:])
            assert recovered == plain

        asyncio.run(go())

    def test_encrypted_send_can_be_explicit(self):
        session, _transport = self._session(keys=True)

        async def go():
            await session.open(ADDRESS)
            result = await session.send_l2(C.CH_PB, C.OP_WRITE, b"\x08\x01",
                                           encrypt=True)
            assert result.l2[1] == C.OP_WRITE_ENC

        asyncio.run(go())

    def test_encrypted_send_without_keys_is_refused(self):
        session, transport = self._session()

        async def go():
            await session.open(ADDRESS)
            with pytest.raises(live.LiveError):
                await session.send_l2(C.CH_LYRA, C.OP_WRITE_ENC, b"\x00")
            assert transport.stream == b""

        asyncio.run(go())

    def test_send_frame_fragments_and_counts(self):
        session, transport = self._session(mtu=23)

        async def go():
            await session.open(ADDRESS)
            await session.send_frame(build_frame(C.TYPE_CMD, 0,
                                                 bytes([C.CMD_L1STOP_REQ])))
            assert session.stats["tx_frames"] == 1
            assert session.stats["tx_writes"] == 1
            assert transport.written[0][2] is True      # write with response

        asyncio.run(go())

    def test_send_ack_helper(self):
        session, transport = self._session()

        async def go():
            await session.open(ADDRESS)
            await session.send_ack(9, ack=False)
            assert transport.stream == build_ack(9, ack=False)

        asyncio.run(go())


# ---------------------------------------------------------------------------
# V2 auth helpers
# ---------------------------------------------------------------------------

class TestAuthHelpers:
    def test_verify_request_shape(self):
        random_app = bytes(range(16))
        payload = live.build_v2_verify_request(random_app, "phone-1")
        fields = proto_decode(payload)
        assert fields[0].value == 1
        assert fields[1].value == C.AUTH_CMD_V2_VERIFY
        va0 = fields[2].message
        assert va0[0].number == C.VA0_FIELD_VERIFY_REQ
        bb0 = va0[0].message
        assert bb0[0].raw == random_app
        assert bb0[1].text == "phone-1"

    def test_verify_request_rejects_bad_nonce(self):
        with pytest.raises(ValueError):
            live.build_v2_verify_request(b"\x00" * 15)

    def test_verify_request_has_oob_flag(self):
        payload = live.build_v2_verify_request(bytes(16), has_oob=True)
        bb0 = proto_decode(payload)[2].message[0].message
        assert [f.value for f in bb0 if f.number == 3] == [1]

    def test_confirm_request_shape(self):
        sign = b"\xaa" * 32
        payload = live.build_v2_confirm_request(sign, b"\x01\x02")
        fields = proto_decode(payload)
        assert fields[1].value == C.AUTH_CMD_V2_CONFIRM
        ya0 = fields[2].message[0]
        assert ya0.number == C.VA0_FIELD_CONFIRM_REQ
        assert ya0.message[0].raw == sign
        assert ya0.message[1].raw == b"\x01\x02"

    def test_parse_verify_response(self):
        random_device = b"\x10" * 16
        device_sign = b"\x20" * 32
        hb0 = (encode_field_bytes(1, random_device)
               + encode_field_bytes(2, device_sign))
        va0 = encode_field_bytes(C.VA0_FIELD_VERIFY_RSP, hb0)
        payload = (encode_field_varint(1, 1)
                   + encode_field_varint(2, C.AUTH_CMD_V2_VERIFY)
                   + encode_field_bytes(3, va0))
        parsed = live.parse_v2_verify_response(payload)
        assert parsed["cmd"] == C.AUTH_CMD_V2_VERIFY
        assert parsed["random_device"] == random_device
        assert parsed["device_sign"] == device_sign

    def test_parse_error_response(self):
        payload = encode_field_varint(1, 1) + encode_field_varint(100, 4)
        parsed = live.parse_v2_verify_response(payload)
        assert parsed["random_device"] is None
        assert parsed["code"] == 4

    def test_parse_verify_response_rejects_garbage(self):
        with pytest.raises(live.LiveError):
            live.parse_v2_verify_response(b"\x00\x01")

    def test_derive_keys_hook_matches_crypto(self):
        app, dev = b"\x01" * 16, b"\x02" * 16
        assert (live.derive_keys_from_nonces(b"token", app, dev).raw
                == derive_v2_keys(b"token", app, dev).raw)

    def test_verify_device_sign(self):
        from miwear.crypto import sign_hmac, sign_message

        keys = derive_v2_keys(b"token", b"\x01" * 16, b"\x02" * 16)
        app, dev = b"\x01" * 16, b"\x02" * 16
        # deviceSign covers randomDevice || randomApp (WearAuthV2.java:181-182),
        # NOT the app-first order used for the HKDF salt.
        good = sign_hmac(keys.device_key, sign_message(app, dev))
        assert live.verify_device_sign(keys, app, dev, good) is True
        assert live.verify_device_sign(keys, app, dev, b"\x00" * 32) is False
        # The app-first ordering must be rejected.
        wrong = sign_hmac(keys.device_key, app + dev)
        assert live.verify_device_sign(keys, app, dev, wrong) is False

    def test_verify_device_sign_includes_oob(self):
        from miwear.crypto import sign_hmac, sign_message

        keys = derive_v2_keys(b"token", b"\x01" * 16, b"\x02" * 16)
        app, dev, oob = b"\x01" * 16, b"\x02" * 16, b"oobbytes"
        good = sign_hmac(keys.device_key, sign_message(app, dev, oob))
        assert live.verify_device_sign(keys, app, dev, good, oob) is True
        # Without oob the digest differs, so the check must fail.
        assert live.verify_device_sign(keys, app, dev, good) is False

    def test_verify_device_sign_rejects_truncated_signature(self):
        from miwear.crypto import sign_hmac, sign_message

        keys = derive_v2_keys(b"token", b"\x01" * 16, b"\x02" * 16)
        app, dev = b"\x01" * 16, b"\x02" * 16
        good = sign_hmac(keys.device_key, sign_message(app, dev))
        # ByteUtil.equals() in the APK only compares min(len) bytes; we must not
        # inherit that, so a correct prefix alone is not enough.
        assert live.verify_device_sign(keys, app, dev, good[:8]) is False

    def test_authenticate_with_nonces_installs_keys(self):
        session = live.LiveSession(FakeTransport(), token=b"token")

        async def go():
            keys = await session.authenticate_with_nonces(b"\x01" * 16,
                                                          b"\x02" * 16)
            assert session.keys is keys
            assert keys.raw == derive_v2_keys(b"token", b"\x01" * 16,
                                              b"\x02" * 16).raw
            return keys

        asyncio.run(go())

    def test_authenticate_without_token_is_refused(self):
        session = live.LiveSession(FakeTransport())

        async def go():
            with pytest.raises(live.LiveError):
                await session.authenticate_with_nonces(b"\x01" * 16,
                                                       b"\x02" * 16)

        asyncio.run(go())

    def test_custom_auth_hook_is_used(self):
        calls = []

        def hook(token, app, dev):
            calls.append((token, app, dev))
            return derive_v2_keys(b"other", app, dev)

        session = live.LiveSession(FakeTransport(), token=b"t", auth_hook=hook)

        async def go():
            keys = await session.authenticate_with_nonces(b"\x01" * 16,
                                                          b"\x02" * 16)
            assert calls == [(b"t", b"\x01" * 16, b"\x02" * 16)]
            assert keys.raw == derive_v2_keys(b"other", b"\x01" * 16,
                                              b"\x02" * 16).raw

        asyncio.run(go())

    def test_check_device_sign_requires_keys(self):
        session = live.LiveSession(FakeTransport())
        with pytest.raises(live.LiveError):
            session.check_device_sign(b"\x01" * 16, b"\x02" * 16, b"\x00" * 32)

    def test_install_keys_validates_length(self):
        session = live.LiveSession(FakeTransport())
        with pytest.raises(ValueError):
            session.install_keys(live.V2Keys(b"\x00" * 39))
        session.install_keys(live.V2Keys(bytes(40)))
        assert session.keys is not None


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------

class TestCommandLine:
    def test_parser_has_all_commands(self):
        parser = live.build_parser()
        for command in ("scan", "version", "handshake", "dump"):
            assert command in parser.format_help()

    def test_main_exists_for_the_lead_to_wire_in(self):
        assert callable(live.main)
        assert live.main.__module__ == "miwear.live"

    def test_scan_with_unavailable_bleak(self):
        if live.BleakTransport.available():
            return
        import contextlib
        import io

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = live.main(["scan", "--timeout", "0.1"])
        assert code == 2
        assert "pip install" in err.getvalue()


# ---------------------------------------------------------------------------
# Reassembly through the session (integration of the two halves)
# ---------------------------------------------------------------------------

class TestSessionReassembly:
    def test_session_survives_arbitrary_att_boundaries(self):
        transport = FakeTransport(mtu=23)
        session = live.LiveSession(transport, auto_ack=False)
        stream = (_start_rsp() + _data_frame(1)
                  + build_frame(C.TYPE_DATA, 2, build_l2(C.CH_PB, C.OP_WRITE,
                                                         bytes(120))))

        async def go():
            await session.open(ADDRESS)
            for index in range(0, len(stream), 7):       # deliberately odd size
                await session.feed(stream[index:index + 7])
            return list(session.frames)

        frames = asyncio.run(go())
        assert [f.seq for f in frames] == [0, 1, 2]
        assert all(f.crc_ok for f in frames)
        assert frames[2].payload == stream[-122:]
        assert session.assembler.buffered == 0

    def test_crc_of_every_emitted_frame_is_checked(self):
        transport = FakeTransport(mtu=23)
        session = live.LiveSession(transport, auto_ack=False)
        payload = bytes(range(64))
        frame = build_frame(C.TYPE_DATA, 1, build_l2(C.CH_PB, C.OP_WRITE, payload))
        assert crc16_arc(frame[8:]) == int.from_bytes(frame[6:8], "little")

        async def go():
            await session.open(ADDRESS)
            await session.feed(frame)

        asyncio.run(go())
        assert session.frames[0].frame.crc == crc16_arc(frame[8:])
