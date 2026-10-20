"""Live BLE link for the miwear SAR protocol.

This module is the "talk to a real band" half of the toolkit.  Everything
above L0 works offline (see :mod:`miwear.session`); this module adds the
missing piece: a working GATT link that speaks the same L1/L2 framing the
captures contain.

Design notes
------------
*bleak is optional.*  :mod:`bleak` is **not** imported at module import
time.  ``import miwear.live`` succeeds on a bare Python install, and only
:class:`BleakTransport` touches the dependency — raising
:class:`LiveDependencyError` with an actionable message when it is missing.
That keeps the "standard library only" promise of the rest of the package.

*All hardware I/O goes through* :class:`Transport`.  The session logic
(:class:`LiveSession`, :class:`FrameAssembler`) never touches bleake; it only
awaits an abstract transport.  Tests therefore drive the whole handshake with
an in-memory fake.

Reassembly is the part that is easy to get wrong
------------------------------------------------
``TransportL0.performSendPacket`` splits a frame into ``MTU-3`` byte writes and
the peer does the same, so **an ATT write boundary carries no protocol
meaning**:

* one SAR frame can arrive spread over several notifications, and
* one notification can carry several complete SAR frames (or a tail plus the
  beginning of the next one).

:class:`FrameAssembler` therefore keeps a *byte stream* per direction and
re-runs the L1 header parse over it, exactly like
:func:`miwear.layer_l1.iter_frames` does for a capture, but incrementally:

* a complete frame is emitted as soon as its last byte arrives,
* a partial frame stays buffered (nothing is lost, nothing is guessed),
* a corrupt header is skipped byte-by-byte until the next ``A5 A5``.

Quick start
-----------
>>> from miwear import live
>>> transport = live.BleakTransport()             # no bleak import yet
>>> session = live.LiveSession(transport)         # doctest: +SKIP
>>> await session.open("AA:BB:CC:DD:EE:FF")       # doctest: +SKIP
>>> await session.handshake()                     # doctest: +SKIP

Command line::

    python -m miwear.live scan
    python -m miwear.live version  --address AA:BB:CC:DD:EE:FF
    python -m miwear.live handshake --address AA:BB:CC:DD:EE:FF
    python -m miwear.live dump      --address AA:BB:CC:DD:EE:FF --seconds 10
"""

from __future__ import annotations

import abc
import argparse
import asyncio
import contextlib
import json
import sys
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

from . import constants as C
from .crc import crc16_arc
from .crypto import V2Keys, aes_ctr_crypt, derive_v2_keys
from .layer_l1 import L1Frame, build_ack, build_frame, default_start_config
from .layer_l2 import build_l2, decode_config_tlv
from .protobuf import ProtoError, decode as proto_decode
from .protobuf import encode_field_bytes, encode_field_varint
from .session import DecodedFrame, decode_stream

__all__ = [
    # errors
    "LiveError", "LiveDependencyError", "LiveTimeout", "TransportError",
    # L0
    "DeviceInfo", "Transport", "BleakTransport", "ATT_OVERHEAD",
    # reassembly / fragmentation
    "FrameAssembler", "fragment", "reassemble",
    # protocol helpers
    "DeviceVersion", "LiveFrame", "HandshakeResult", "SendResult",
    "build_v2_verify_request", "parse_v2_verify_response",
    "build_v2_confirm_request", "derive_keys_from_nonces", "verify_device_sign",
    # session
    "LiveSession",
    # cli
    "main",
]

#: ATT header (opcode + handle) eats 3 of the negotiated MTU bytes.
ATT_OVERHEAD = 3

#: Byte counts allowed per ATT write when no MTU was negotiated yet.
DEFAULT_MTU = 23

DIR_DEVICE_TO_HOST = "DEV->MTU"
DIR_HOST_TO_DEVICE = "MTU->DEV"

#: Install hint reused by every bleak-missing error path.
BLEAK_HINT = (
    "live BLE support requires the optional 'bleak' package: "
    "pip install \"miwear[live]\"  (or: pip install bleak>=0.20)"
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class LiveError(RuntimeError):
    """Base class for every live-link failure."""


class LiveDependencyError(LiveError):
    """Raised when the optional ``bleak`` dependency is needed but absent."""


class LiveTimeout(LiveError):
    """Raised when the device did not answer within the allotted time."""


class TransportError(LiveError):
    """Raised when the underlying transport reports a failure."""


# ---------------------------------------------------------------------------
# L0 — transport abstraction
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DeviceInfo:
    """A device returned by :meth:`Transport.scan`."""

    address: str
    name: str | None = None
    rssi: int | None = None
    service_uuids: tuple[str, ...] = ()

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        rssi = f"{self.rssi} dBm" if self.rssi is not None else "?"
        return f"{self.address}  {self.name or '<unnamed>':<24} {rssi}"


#: Signature of the notification callback, mirroring bleak's own.
NotifyCallback = Callable[[str, bytes], None]


class Transport(abc.ABC):
    """Everything the session needs from the platform.

    Implementations only have to move bytes: scan, connect, read, write and
    subscribe.  Framing, ACKs and retransmission live one layer up so the
    same code drives a real band and an in-memory fake.
    """

    # -- discovery ---------------------------------------------------------

    @abc.abstractmethod
    async def scan(self, *, timeout: float = 5.0,
                   name_filter: str | None = None) -> list[DeviceInfo]:
        """Return the devices advertising the miwear service."""

    # -- link --------------------------------------------------------------

    @abc.abstractmethod
    async def connect(self, address: str, *, timeout: float = 10.0) -> None:
        """Open the GATT link."""

    @abc.abstractmethod
    async def disconnect(self) -> None:
        """Close the GATT link (must be safe to call twice)."""

    @property
    @abc.abstractmethod
    def is_connected(self) -> bool:
        """Whether the link is currently up."""

    @property
    @abc.abstractmethod
    def mtu(self) -> int:
        """Negotiated ATT MTU in bytes (23 until negotiated)."""

    @abc.abstractmethod
    async def request_mtu(self, mtu: int) -> int:
        """Ask for a larger MTU; return what the device agreed to."""

    # -- GATT --------------------------------------------------------------

    @abc.abstractmethod
    async def read(self, uuid: str) -> bytes:
        """Read a characteristic value."""

    @abc.abstractmethod
    async def write(self, uuid: str, data: bytes, *, response: bool = True) -> None:
        """Write a characteristic value."""

    @abc.abstractmethod
    async def start_notify(self, uuid: str, callback: NotifyCallback) -> None:
        """Subscribe to a characteristic's notifications."""

    @abc.abstractmethod
    async def stop_notify(self, uuid: str) -> None:
        """Unsubscribe (must be safe to call when not subscribed)."""


class BleakTransport(Transport):
    """The real thing: a thin adapter over ``bleak``.

    Constructing this object never imports bleak, so tools can build a
    session, list their options and only fail when they actually connect.
    """

    def __init__(self, *, write_uuid: str = C.CHAR_SAR_WRITE,
                 notify_uuid: str = C.CHAR_SAR_NOTIFY) -> None:
        self.write_uuid = write_uuid
        self.notify_uuid = notify_uuid
        self._client = None
        self._mtu = DEFAULT_MTU

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def available() -> bool:
        """True when the optional dependency can be imported."""
        try:
            _import_bleak()
        except LiveDependencyError:
            return False
        return True

    def _require_client(self):
        if self._client is None:
            raise TransportError("not connected: call connect() first")
        return self._client

    # -- discovery ---------------------------------------------------------

    async def scan(self, *, timeout: float = 5.0,
                   name_filter: str | None = None) -> list[DeviceInfo]:
        bleak = _import_bleak()
        target = C.SERVICE_UUID.lower()
        try:
            found = await bleak.BleakScanner.discover(timeout=timeout,
                                                      return_adv=True)
        except TypeError:                          # bleak < 0.20
            devices = await bleak.BleakScanner.discover(timeout=timeout)
            found = {d.address: (d, None) for d in devices}

        out: list[DeviceInfo] = []
        for address, entry in found.items():
            device, adv = entry if isinstance(entry, tuple) else (entry, None)
            uuids = tuple(u.lower() for u in
                          (getattr(adv, "service_uuids", None) or ()))
            if uuids and target not in uuids:
                continue
            name = getattr(device, "name", None)
            if name_filter and (not name or name_filter.lower() not in name.lower()):
                continue
            out.append(DeviceInfo(
                address=address,
                name=name,
                rssi=getattr(adv, "rssi", None),
                service_uuids=uuids,
            ))
        out.sort(key=lambda d: (-(d.rssi or -999), d.address))
        return out

    # -- link --------------------------------------------------------------

    async def connect(self, address: str, *, timeout: float = 10.0) -> None:
        bleak = _import_bleak()
        self._client = bleak.BleakClient(address, timeout=timeout)
        await self._client.connect()
        self._mtu = int(getattr(self._client, "mtu_size", DEFAULT_MTU) or DEFAULT_MTU)

    async def disconnect(self) -> None:
        client, self._client = self._client, None
        if client is None:
            return
        with contextlib.suppress(Exception):        # already gone
            await client.disconnect()

    @property
    def is_connected(self) -> bool:
        client = self._client
        return bool(client is not None and getattr(client, "is_connected", False))

    @property
    def mtu(self) -> int:
        return self._mtu

    async def request_mtu(self, mtu: int) -> int:
        client = self._require_client()
        try:
            agreed = await client.request_mtu(mtu)
        except Exception as exc:                    # noqa: BLE001 - platform quirk
            # BlueZ/macOS may refuse or not implement the request; the link
            # simply keeps its current MTU, which is not fatal.
            agreed = getattr(client, "mtu_size", self._mtu)
            if not agreed:
                raise TransportError(f"MTU negotiation failed: {exc}") from exc
        self._mtu = int(agreed or DEFAULT_MTU)
        return self._mtu

    # -- GATT --------------------------------------------------------------

    async def read(self, uuid: str) -> bytes:
        return bytes(await self._require_client().read_gatt_char(uuid))

    async def write(self, uuid: str, data: bytes, *, response: bool = True) -> None:
        await self._require_client().write_gatt_char(uuid, data, response=response)

    async def start_notify(self, uuid: str, callback: NotifyCallback) -> None:
        await self._require_client().start_notify(uuid, callback)

    async def stop_notify(self, uuid: str) -> None:
        client = self._client
        if client is None:
            return
        with contextlib.suppress(Exception):
            await client.stop_notify(uuid)


def _import_bleak():
    """Import bleak lazily and turn the ImportError into an actionable one.

    This is the *only* place in the package that refers to the optional
    dependency, which is what keeps ``import miwear.live`` dependency-free.
    """
    try:
        import bleak  # noqa: PLC0415 - deliberately lazy
    except ImportError as exc:                      # pragma: no cover - env
        raise LiveDependencyError(BLEAK_HINT) from exc
    return bleak


# ---------------------------------------------------------------------------
# Reassembly — the part that must be right
# ---------------------------------------------------------------------------

class FrameAssembler:
    """Incrementally rebuild L1 frames from an arbitrary ATT write stream.

    Feed it every notification (or write) payload in arrival order; it returns
    the frames that became complete.  Partial bytes stay buffered until the
    rest of the frame arrives, and a single feed may return several frames.

    >>> asm = FrameAssembler()
    >>> frame = build_frame(C.TYPE_ACK, 0, b"")
    >>> len(asm.feed(frame))          # a whole frame in one write
    1
    >>> asm.feed(frame[:3])           # a split frame yields nothing yet
    []
    >>> len(asm.feed(frame[3:]))
    1
    """

    def __init__(self, *, max_frame_size: int | None = C.SAR_DEFAULT_MPS,
                 start_offset: int = 0) -> None:
        self.max_frame_size = max_frame_size
        self._buf = bytearray()
        self._base = int(start_offset)
        self.skipped_bytes = 0
        self.crc_failures = 0
        self.frames_emitted = 0

    # -- introspection -----------------------------------------------------

    @property
    def buffered(self) -> int:
        """Bytes held back waiting for the rest of a frame."""
        return len(self._buf)

    @property
    def next_offset(self) -> int:
        """Stream offset of the first buffered byte."""
        return self._base

    def stats(self) -> dict:
        return {
            "cursor": self._base,
            "buffered": self.buffered,
            "frames": self.frames_emitted,
            "skipped_bytes": self.skipped_bytes,
            "crc_failures": self.crc_failures,
        }

    def reset(self) -> None:
        self._buf.clear()

    # -- the reassembly proper --------------------------------------------

    def feed(self, chunk: bytes | bytearray | memoryview) -> list[L1Frame]:
        """Append bytes and return every frame that is now complete."""
        if chunk:
            self._buf += chunk
        return self._drain()

    def _drain(self) -> list[L1Frame]:
        buf = self._buf
        total = len(buf)
        pos = 0
        out: list[L1Frame] = []

        while pos + C.L1_HEADER_SIZE <= total:
            if buf[pos] != 0xA5 or buf[pos + 1] != 0xA5:
                pos += 1
                self.skipped_bytes += 1
                continue

            flags = buf[pos + 2]
            seq = buf[pos + 3]
            data_len = buf[pos + 4] | (buf[pos + 5] << 8)
            crc = buf[pos + 6] | (buf[pos + 7] << 8)

            # A plausible header was found but the length is impossible: the
            # "magic" was payload noise, so resynchronise one byte further.
            if self.max_frame_size is not None and data_len > self.max_frame_size:
                pos += 1
                self.skipped_bytes += 1
                continue

            end = pos + C.L1_HEADER_SIZE + data_len
            if end > total:
                break                              # wait for the next write

            payload = bytes(buf[pos + C.L1_HEADER_SIZE:end])
            crc_ok = crc16_arc(payload) == crc
            self.frames_emitted += 1
            if not crc_ok:
                self.crc_failures += 1
            out.append(L1Frame(
                offset=self._base + pos,
                type_raw=flags & 0x0F,
                seq=seq,
                data_length=data_len,
                crc=crc,
                crc_ok=crc_ok,
                frx=(flags >> 4) & 1,
                payload=payload,
            ))
            pos = end

        if pos:
            del buf[:pos]
            self._base += pos
        return out


def fragment(frame: bytes, mtu: int) -> list[bytes]:
    """Split *frame* into ``MTU-3`` byte writes (``TransportL0.performSendPacket``).

    >>> len(fragment(bytes(185), 23))     # 20-byte payloads
    10
    """
    if mtu <= ATT_OVERHEAD:
        raise ValueError(
            f"MTU {mtu} is unusable: need more than {ATT_OVERHEAD} bytes of header")
    size = mtu - ATT_OVERHEAD
    return [frame[i:i + size] for i in range(0, len(frame), size)] or [b""]


def reassemble(chunks: Iterable[bytes], *,
               max_frame_size: int | None = C.SAR_DEFAULT_MPS) -> list[L1Frame]:
    """Convenience wrapper: run a whole chunk list through a fresh assembler."""
    asm = FrameAssembler(max_frame_size=max_frame_size)
    out: list[L1Frame] = []
    for chunk in chunks:
        out.extend(asm.feed(chunk))
    return out


# ---------------------------------------------------------------------------
# Version characteristic
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DeviceVersion:
    """Three-byte firmware version from characteristic ``0x0050``.

    ``defpackage.d13.newTaskQueue()`` chooses the whole stack from this
    string: anything starting with ``"0"`` is the legacy V1 channel protocol,
    everything else is the SAR / V2 stack.
    """

    raw: bytes

    @classmethod
    def parse(cls, raw: bytes) -> "DeviceVersion":
        if not raw:
            raise LiveError("version characteristic 0x0050 returned no data")
        return cls(bytes(raw))

    @property
    def major(self) -> int:
        return self.raw[0] if len(self.raw) > 0 else 0

    @property
    def minor(self) -> int:
        return self.raw[1] if len(self.raw) > 1 else 0

    @property
    def build(self) -> int:
        return self.raw[2] if len(self.raw) > 2 else 0

    @property
    def text(self) -> str:
        return f"{self.major}.{self.minor}.{self.build}"

    @property
    def protocol(self) -> str:
        """``"legacy"`` for 0.x firmware, ``"sar"`` for everything newer."""
        return "legacy" if self.text.startswith("0") else "sar"

    @property
    def is_sar(self) -> bool:
        return self.protocol == "sar"

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"{self.text} ({self.protocol})"


# ---------------------------------------------------------------------------
# Received frames
# ---------------------------------------------------------------------------

@dataclass
class LiveFrame:
    """One inbound L1 frame with its L2 (and, if possible, protobuf) peeled."""

    decoded: DecodedFrame
    plaintext: bytes | None = None
    error: str | None = None

    @property
    def frame(self) -> L1Frame:
        return self.decoded.frame

    @property
    def seq(self) -> int:
        return self.decoded.frame.seq

    @property
    def type_name(self) -> str:
        return self.decoded.frame.type_name

    @property
    def payload(self) -> bytes:
        return self.decoded.frame.payload

    @property
    def crc_ok(self) -> bool:
        return self.decoded.frame.crc_ok

    @property
    def channel(self) -> int | None:
        return self.decoded.l2_channel

    @property
    def opcode(self) -> int | None:
        return self.decoded.l2_opcode

    @property
    def data(self) -> bytes:
        """Application payload, decrypted when a session key is installed."""
        if self.plaintext is not None:
            return self.plaintext
        return self.decoded.l2_payload

    @property
    def needs_ack(self) -> bool:
        return (self.frame.type_raw == C.TYPE_DATA
                and self.crc_ok
                and self.channel not in C.CHANNELS_WITHOUT_ACK)

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (f"<LiveFrame {self.type_name} seq={self.seq} "
                f"ch={self.channel} len={len(self.payload)}>")


@dataclass
class HandshakeResult:
    """Outcome of the L1 ``CMD_L1START_REQ`` exchange."""

    version: DeviceVersion
    response_cmd: int | None
    request: bytes
    response: LiveFrame | None
    config: dict | None
    elapsed_ms: float
    remote_mps: int | None = None
    remote_tx_window: int | None = None
    remote_send_timeout_ms: int | None = None

    @property
    def ok(self) -> bool:
        return self.response is not None

    def as_dict(self) -> dict:
        return {
            "version": self.version.text,
            "protocol": self.version.protocol,
            "response_cmd": self.response_cmd,
            "response_name": C.CMD_NAMES.get(self.response_cmd or -1),
            "elapsed_ms": round(self.elapsed_ms, 3),
            "remote_mps": self.remote_mps,
            "remote_tx_window": self.remote_tx_window,
            "remote_send_timeout_ms": self.remote_send_timeout_ms,
        }


@dataclass
class SendResult:
    """Bookkeeping for one transmitted L1 frame."""

    seq: int
    frame: bytes
    l2: bytes

    def __len__(self) -> int:  # pragma: no cover - convenience
        return len(self.frame)


# ---------------------------------------------------------------------------
# V2 authentication helpers (field numbers from docs/PROTOCOL.md)
# ---------------------------------------------------------------------------

def build_v2_verify_request(random_app: bytes, app_device_id: str = "",
                            *, has_oob: bool = False) -> bytes:
    """Serialise ``pyt{type=1, cmd=26, va0{bb0{randomApp, …}}}``.

    Field numbers: ``pyt`` 1/2/3, ``va0`` 30 = ``bb0``, ``bb0`` 1/2/3.
    """
    if len(random_app) != 16:
        raise ValueError("randomApp must be 16 bytes")
    bb0 = encode_field_bytes(1, random_app)
    if app_device_id:
        bb0 += encode_field_bytes(2, app_device_id.encode("utf-8"))
    if has_oob:
        bb0 += encode_field_varint(3, 1)
    return _pyt(C.AUTH_CMD_V2_VERIFY, encode_field_bytes(C.VA0_FIELD_VERIFY_REQ, bb0))


def build_v2_confirm_request(app_sign: bytes, enc_app_info: bytes = b"") -> bytes:
    """Serialise ``pyt{type=1, cmd=27, va0{ya0{appSign, encAppInfo}}}``."""
    ya0 = encode_field_bytes(1, app_sign)
    if enc_app_info:
        ya0 += encode_field_bytes(2, enc_app_info)
    return _pyt(C.AUTH_CMD_V2_CONFIRM, encode_field_bytes(C.VA0_FIELD_CONFIRM_REQ, ya0))


def _pyt(cmd: int, va0: bytes) -> bytes:
    return (encode_field_varint(1, 1)
            + encode_field_varint(2, cmd)
            + encode_field_bytes(3, va0))


def _child(fields, number: int):
    """Return the first length-delimited child message for *number*."""
    for candidate in fields:
        if candidate.number == number and candidate.message is not None:
            return candidate.message
    return None


def _varint(fields, number: int, default=None):
    for candidate in fields:
        if candidate.number == number and candidate.message is None:
            return candidate.value
    return default


def parse_v2_verify_response(payload: bytes) -> dict:
    """Pull ``randomDevice`` / ``deviceSign`` out of a verify response.

    Returns ``{"cmd", "random_device", "device_sign"}``; values are ``None``
    when the device answered with something else (an error code, for
    instance), which the caller should treat as a failed handshake.
    """
    try:
        pyt = proto_decode(payload)
    except ProtoError as exc:
        raise LiveError(f"auth response is not valid protobuf: {exc}") from exc

    out: dict = {"cmd": _varint(pyt, 2), "random_device": None, "device_sign": None,
                 "code": None}
    va0 = _child(pyt, 3)
    if va0 is not None:
        hb0 = _child(va0, C.VA0_FIELD_VERIFY_RSP)
        if hb0 is not None:
            for item in hb0:
                if item.number == 1 and item.raw:
                    out["random_device"] = item.raw
                elif item.number == 2 and item.raw:
                    out["device_sign"] = item.raw
    if out["cmd"] is None:
        out["code"] = _varint(pyt, 100)
    return out


def derive_keys_from_nonces(token: bytes, random_app: bytes,
                            random_device: bytes) -> V2Keys:
    """Default auth hook: HKDF over ``randomApp ‖ randomDevice``."""
    return derive_v2_keys(token, random_app, random_device)


def verify_device_sign(keys: V2Keys, random_app: bytes,
                       random_device: bytes, device_sign: bytes,
                       oob: bytes = b"") -> bool:
    """Check ``HMAC-SHA256(deviceKey, randomDevice ‖ randomApp [‖ oob])``.

    The operand order for deviceSign is the **reverse** of the HKDF salt; see
    :func:`miwear.crypto.sign_message` and ``WearAuthV2.java:181-182``.
    """
    from .crypto import sign_hmac, sign_message
    expected = sign_hmac(keys.device_key, sign_message(random_app, random_device, oob))
    # Compare in full: ByteUtil.equals() only checks min(len) bytes, which is a
    # trap we do not want to reproduce here.
    return len(expected) == len(device_sign) and expected == device_sign


# ---------------------------------------------------------------------------
# The session
# ---------------------------------------------------------------------------

class LiveSession:
    """Drive one band: discovery, GATT setup, L1 handshake and framing.

    The class owns no I/O of its own — it awaits a :class:`Transport`, which
    makes the whole state machine testable without hardware.
    """

    def __init__(self, transport: Transport, *,
                 auto_ack: bool = True,
                 token: bytes | None = None,
                 auth_hook: Callable[[bytes, bytes, bytes], V2Keys] | None = None,
                 write_gap: float = 0.0,
                 max_frame_size: int | None = C.SAR_DEFAULT_MPS) -> None:
        self.transport = transport
        self.auto_ack = auto_ack
        self.token = token
        self.auth_hook = auth_hook or derive_keys_from_nonces
        self.write_gap = write_gap

        self.assembler = FrameAssembler(max_frame_size=max_frame_size)
        self.keys: V2Keys | None = None
        self.version: DeviceVersion | None = None

        self.frames: list[LiveFrame] = []
        self._new_frame = asyncio.Event()

        self._tx_seq = 0
        self._rx_expected: int | None = None
        self._read_cursor = 0
        self._loop: asyncio.AbstractEventLoop | None = None
        self._tasks: set[asyncio.Task] = set()

        self.stats: dict = {
            "tx_frames": 0, "tx_writes": 0, "tx_bytes": 0,
            "rx_frames": 0, "rx_writes": 0, "rx_bytes": 0,
            "acks_sent": 0, "naks_sent": 0,
            "duplicates": 0, "out_of_order": 0,
            "encrypted": 0, "decrypt_failures": 0,
        }

    # -- lifecycle ---------------------------------------------------------

    async def open(self, address: str | None = None, *,
                   scan_timeout: float = 5.0,
                   connect_timeout: float = 10.0,
                   request_mtu: int | None = None,
                   enable_notify: bool = True) -> DeviceVersion:
        """Connect, optionally widen the MTU, read the version, subscribe.

        Passing ``address=None`` scans first and takes the first device that
        advertises service ``0xFE95``.
        """
        self._loop = asyncio.get_running_loop()
        if address is None:
            address = await self._pick_device(scan_timeout)

        await self.transport.connect(address, timeout=connect_timeout)
        if request_mtu is not None:
            with contextlib.suppress(LiveError):
                await self.transport.request_mtu(request_mtu)
        if enable_notify:
            await self.transport.start_notify(C.CHAR_SAR_NOTIFY, self._on_notify)
        self.version = await self.read_version()
        return self.version

    async def _pick_device(self, timeout: float) -> str:
        devices = await self.transport.scan(timeout=timeout)
        if not devices:
            raise LiveError(
                "no device advertising service 0xFE95 was found; make sure the "
                "band is awake and not connected to the phone app")
        return devices[0].address

    async def close(self) -> None:
        """Unsubscribe and disconnect, ignoring a link that is already down."""
        for task in list(self._tasks):
            task.cancel()
        self._tasks.clear()
        with contextlib.suppress(Exception):
            await self.transport.stop_notify(C.CHAR_SAR_NOTIFY)
        await self.transport.disconnect()

    async def __aenter__(self) -> "LiveSession":
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()

    # -- GATT helpers ------------------------------------------------------

    @property
    def mtu(self) -> int:
        return self.transport.mtu

    async def read_version(self) -> DeviceVersion:
        """Read ``0x0050`` and decide which protocol stack the device speaks."""
        raw = await self.transport.read(C.CHAR_VERSION)
        self.version = DeviceVersion.parse(raw)
        return self.version

    # -- receive path ------------------------------------------------------

    def _on_notify(self, sender: str, data: bytes) -> None:
        """bleak notification callback (sync, possibly another thread)."""
        loop = self._loop
        if loop is None or loop.is_closed():
            return

        def schedule() -> None:
            task = loop.create_task(self._dispatch(bytes(data)))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            schedule()
        else:
            loop.call_soon_threadsafe(schedule)

    async def _dispatch(self, data: bytes) -> None:
        try:
            await self.feed(data)
        except Exception as exc:                    # noqa: BLE001 - callback
            self.stats["callback_errors"] = self.stats.get("callback_errors", 0) + 1
            self.last_error = exc

    async def feed(self, data: bytes) -> list[LiveFrame]:
        """Absorb raw notification bytes; return the frames that completed.

        This is the whole receive path: reassemble, decode, auto-ACK.  It is
        a public coroutine so tests (and scripted replays) can drive it
        without a radio.
        """
        self.stats["rx_writes"] += 1
        self.stats["rx_bytes"] += len(data)
        completed = self.assembler.feed(data)

        out: list[LiveFrame] = []
        for frame in completed:
            live = self._wrap(frame)
            self.frames.append(live)
            self.stats["rx_frames"] += 1
            out.append(live)
            if self.auto_ack:
                await self._ack(live)
        if out:
            self._new_frame.set()
        return out

    def _wrap(self, frame: L1Frame) -> LiveFrame:
        """Decode one L1 frame into the same structure the offline tools use."""
        live = LiveFrame(decoded=DecodedFrame(frame=frame, direction=DIR_DEVICE_TO_HOST))

        # Reuse the offline decoder for CMD TLVs and plaintext protobuf, then
        # restore the original frame so the absolute offset survives.
        try:
            rebuilt = build_frame(frame.type_raw, frame.seq, frame.payload,
                                  frx=frame.frx)
            decoded = decode_stream(rebuilt, direction=DIR_DEVICE_TO_HOST)[0]
        except Exception as exc:                    # noqa: BLE001 - defensive
            live.error = f"decode failed: {exc}"
            return live

        decoded.frame = frame
        live.decoded = decoded

        if decoded.is_encrypted:
            self.stats["encrypted"] += 1
            live.plaintext, live.error = self._decrypt(decoded.l2_payload)
            if live.plaintext is not None:
                try:
                    decoded.proto_fields = proto_decode(live.plaintext)
                except ProtoError as exc:
                    decoded.proto_error = str(exc)
        return live

    def _decrypt(self, data: bytes) -> tuple[bytes | None, str | None]:
        if self.keys is None:
            return None, "encrypted payload: no session key installed"
        try:
            return aes_ctr_crypt(self.keys.device_key, self.keys.device_key,
                                 0, data), None
        except Exception as exc:                    # noqa: BLE001 - report
            self.stats["decrypt_failures"] += 1
            return None, f"decrypt failed: {exc}"

    async def _ack(self, live: LiveFrame) -> None:
        """Sequence bookkeeping plus the ACK/NAK the peer expects."""
        if live.frame.type_raw != C.TYPE_DATA:
            return
        if not live.crc_ok:
            return                                  # let the peer retransmit

        seq = live.seq
        expected = self._rx_expected
        if expected is None:
            self._rx_expected = (seq + 1) & 0xFF
        elif seq == expected:
            self._rx_expected = (seq + 1) & 0xFF
        elif seq == (expected - 1) & 0xFF:
            self.stats["duplicates"] += 1
            await self._send_ack(seq, ack=True)
            return
        else:
            self.stats["out_of_order"] += 1
            await self._send_ack(seq, ack=False)
            return

        if live.needs_ack:
            await self._send_ack(seq, ack=True)

    async def _send_ack(self, seq: int, *, ack: bool) -> None:
        await self.send_frame(build_ack(seq, ack=ack))
        key = "acks_sent" if ack else "naks_sent"
        self.stats[key] += 1

    # -- send path ---------------------------------------------------------

    def _next_seq(self) -> int:
        seq = self._tx_seq
        self._tx_seq = (self._tx_seq + 1) & 0xFF
        return seq

    async def send_frame(self, frame: bytes, *, response: bool = True) -> None:
        """Fragment one L1 frame over ``0x005F`` and write it."""
        mtu = self.mtu
        chunks = fragment(frame, mtu)
        for index, chunk in enumerate(chunks):
            await self.transport.write(C.CHAR_SAR_WRITE, chunk, response=response)
            self.stats["tx_writes"] += 1
            self.stats["tx_bytes"] += len(chunk)
            if self.write_gap and index + 1 < len(chunks):
                await asyncio.sleep(self.write_gap)
        self.stats["tx_frames"] += 1

    async def send_cmd(self, cmd: int, config: bytes = b"",
                       *, seq: int = 0) -> bytes:
        frame = build_frame(C.TYPE_CMD, seq, bytes([cmd]) + config)
        await self.send_frame(frame)
        return frame

    async def send_l2(self, channel: int, opcode: int, payload: bytes, *,
                      encrypt: bool | None = None) -> SendResult:
        """Encrypt (if asked), wrap in L2 and send as one DATA frame.

        ``encrypt=None`` follows the opcode (``OP_WRITE_ENC`` means
        encrypted).  Forcing ``encrypt=True`` also promotes the opcode, since
        the peer decides whether to decrypt from the opcode alone.
        """
        if encrypt is None:
            encrypt = opcode == C.OP_WRITE_ENC
        data = payload
        if encrypt:
            if self.keys is None:
                raise LiveError(
                    "cannot send an encrypted payload without session keys: "
                    "call authenticate_with_nonces() or install_keys() first")
            data = aes_ctr_crypt(self.keys.app_key, self.keys.app_key, 0, payload)
            opcode = C.OP_WRITE_ENC

        l2 = build_l2(channel, opcode, data)
        seq = self._next_seq()
        frame = build_frame(C.TYPE_DATA, seq, l2)
        await self.send_frame(frame)
        return SendResult(seq=seq, frame=frame, l2=l2)

    async def send_ack(self, seq: int, *, ack: bool = True) -> None:
        """Public ACK/NAK helper for manual (deferred) acknowledgement."""
        await self._send_ack(seq, ack=ack)

    # -- waiting -----------------------------------------------------------

    async def wait_for(self, predicate: Callable[[LiveFrame], bool], *,
                       timeout: float = 10.0,
                       scan_backlog: bool = True) -> LiveFrame:
        """Await the next inbound frame matching *predicate*."""
        index = 0 if scan_backlog else len(self.frames)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout

        while True:
            while index < len(self.frames):
                candidate = self.frames[index]
                index += 1
                if predicate(candidate):
                    return candidate
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise LiveTimeout(
                    f"timed out after {timeout:.1f}s waiting for a frame")
            self._new_frame.clear()
            if index < len(self.frames):           # lost-wakeup guard
                continue
            try:
                await asyncio.wait_for(self._new_frame.wait(), remaining)
            except asyncio.TimeoutError as exc:
                raise LiveTimeout(
                    f"timed out after {timeout:.1f}s waiting for a frame") from exc

    async def next_frame(self, *, timeout: float = 10.0) -> LiveFrame:
        """Return the oldest frame not yet returned by this method.

        Frames that have already been handed out are never repeated, so a
        dump loop can simply call this in a ``while`` and see everything
        exactly once, whether it was queued before or arrives later.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            if self._read_cursor < len(self.frames):
                frame = self.frames[self._read_cursor]
                self._read_cursor += 1
                return frame
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise LiveTimeout(
                    f"timed out after {timeout:.1f}s waiting for a frame")
            self._new_frame.clear()
            if self._read_cursor < len(self.frames):   # lost-wakeup guard
                continue
            try:
                await asyncio.wait_for(self._new_frame.wait(), remaining)
            except asyncio.TimeoutError as exc:
                raise LiveTimeout(
                    f"timed out after {timeout:.1f}s waiting for a frame") from exc

    # -- handshake ---------------------------------------------------------

    async def handshake(self, *, timeout: float = 10.0, seq: int = 0,
                        force: bool = False) -> HandshakeResult:
        """Send ``CMD_L1START_REQ`` (22-byte payload) and wait for the peer.

        Refuses to run on a device that reported a ``0.x`` version unless
        ``force=True``: those speak the completely different V1 channel
        protocol and would just time out here.
        """
        version = self.version or await self.read_version()
        if version.protocol == "legacy" and not force:
            raise LiveError(
                f"device reports firmware {version.text}: it speaks the legacy "
                "V1 protocol (see miwear.legacy_v1), not SAR framing. "
                "Pass force=True to try the L1 handshake anyway.")

        config = default_start_config()
        request = build_frame(C.TYPE_CMD, seq,
                              bytes([C.CMD_L1START_REQ]) + config)
        started = time.monotonic()
        await self.send_frame(request)

        def is_start(frame: LiveFrame) -> bool:
            return (frame.frame.type_raw == C.TYPE_CMD
                    and frame.payload[:1] in (bytes([C.CMD_L1START_REQ]),
                                              bytes([C.CMD_L1START_RSP])))

        response = await self.wait_for(is_start, timeout=timeout,
                                       scan_backlog=False)
        elapsed = (time.monotonic() - started) * 1000.0
        info = decode_config_tlv(response.payload)
        values = {entry["type"]: entry.get("u16")
                  for entry in info.get("config", []) if "u16" in entry}

        result = HandshakeResult(
            version=version,
            response_cmd=info.get("cmd"),
            request=request,
            response=response,
            config=info,
            elapsed_ms=elapsed,
            remote_mps=values.get(C.CONFIG_MPS),
            remote_tx_window=values.get(C.CONFIG_TX_WIN),
            remote_send_timeout_ms=values.get(C.CONFIG_SEND_TIMEOUT),
        )
        return result

    # -- authentication hook ----------------------------------------------

    def install_keys(self, keys: V2Keys) -> None:
        """Install derived session material; later payloads use it."""
        if len(keys.raw) != C.HKDF_OUTPUT_LEN:
            raise ValueError("session keys must be 40 bytes of key material")
        self.keys = keys

    async def authenticate_with_nonces(self, random_app: bytes,
                                       random_device: bytes, *,
                                       token: bytes | None = None) -> V2Keys:
        """Derive keys from the two 16-byte nonces via the auth hook.

        The hook defaults to :func:`derive_keys_from_nonces` and can be
        replaced (constructor argument) to plug in a different derivation.
        """
        secret = token if token is not None else self.token
        if secret is None:
            raise LiveError(
                "no auth token available: pass token= to LiveSession or to this "
                "method (it is the stored DeviceInfo token, as bytes)")
        keys = self.auth_hook(secret, random_app, random_device)
        self.install_keys(keys)
        return keys

    def check_device_sign(self, random_app: bytes, random_device: bytes,
                          device_sign: bytes, oob: bytes = b"") -> bool:
        """Verify the device's HMAC with the derived ``deviceKey``."""
        if self.keys is None:
            raise LiveError("derive the session keys before checking the signature")
        return verify_device_sign(self.keys, random_app, random_device,
                                  device_sign, oob)


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="miwear-live",
        description="Talk to a Xiaomi wearable over BLE (needs the optional "
                    "'bleak' package).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="scan for devices advertising service 0xFE95")
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--name", help="keep only names containing this substring")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("version", help="read the firmware version (0x0050)")
    p.add_argument("address", nargs="?", help="device address; scan if omitted")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_version)

    p = sub.add_parser("handshake", help="connect and run the L1 START exchange")
    p.add_argument("address", nargs="?")
    p.add_argument("--mtu", type=int, default=247, help="MTU to request (0 = skip)")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_handshake)

    p = sub.add_parser("dump", help="stream and decode frames for N seconds")
    p.add_argument("address", nargs="?")
    p.add_argument("--mtu", type=int, default=247)
    p.add_argument("--seconds", type=float, default=10.0)
    p.add_argument("--no-handshake", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument("--brief", action="store_true")
    p.set_defaults(func=cmd_dump)

    return parser


async def cmd_scan(args: argparse.Namespace) -> int:
    transport = BleakTransport()
    devices = await transport.scan(timeout=args.timeout, name_filter=args.name)
    if args.json:
        print(json.dumps([d.__dict__ for d in devices], ensure_ascii=False))
    else:
        if not devices:
            print("no devices advertising 0xFE95 found", file=sys.stderr)
            return 1
        print(f"{'address':<20} {'name':<24} rssi")
        for device in devices:
            print(device)
    return 0


async def _open(args: argparse.Namespace) -> LiveSession:
    session = LiveSession(BleakTransport())
    mtu = getattr(args, "mtu", None)
    await session.open(args.address, request_mtu=mtu or None)
    return session


async def cmd_version(args: argparse.Namespace) -> int:
    session = LiveSession(BleakTransport())
    try:
        version = await session.open(args.address)
    finally:
        await session.close()
    if args.json:
        print(json.dumps({"version": version.text, "protocol": version.protocol,
                          "raw": version.raw.hex()}))
    else:
        print(f"firmware : {version.text}")
        print(f"protocol : {version.protocol}"
              + ("  (SAR / L1 framing)" if version.is_sar
                 else "  (legacy V1 — see miwear.legacy_v1)"))
    return 0


async def cmd_handshake(args: argparse.Namespace) -> int:
    session = await _open(args)
    try:
        result = await session.handshake(timeout=args.timeout)
    finally:
        await session.close()
    if args.json:
        print(json.dumps(result.as_dict(), ensure_ascii=False))
    else:
        print(f"firmware   : {result.version.text} ({result.version.protocol})")
        print(f"response   : {C.CMD_NAMES.get(result.response_cmd or -1)} "
              f"in {result.elapsed_ms:.1f} ms")
        print(f"remote MPS : {result.remote_mps}")
        print(f"remote win : {result.remote_tx_window}")
        print(f"remote t/o : {result.remote_send_timeout_ms} ms")
        for entry in (result.config or {}).get("config", []):
            print(f"  - {entry['name']:<24} len={entry['len']:<2} "
                  f"value={entry['value']}")
    return 0


async def cmd_dump(args: argparse.Namespace) -> int:
    from .format import format_frame

    session = await _open(args)
    try:
        if not args.no_handshake:
            await session.handshake(timeout=args.timeout)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + args.seconds
        seen = 0
        while loop.time() < deadline:
            try:
                frame = await session.next_frame(timeout=max(0.1, deadline - loop.time()))
            except LiveTimeout:
                break
            seen += 1
            if args.json:
                print(json.dumps({
                    "seq": frame.seq,
                    "type": frame.type_name,
                    "channel": frame.channel,
                    "opcode": frame.opcode,
                    "crc_ok": frame.crc_ok,
                    "payload": frame.payload.hex(),
                    "plaintext": frame.plaintext.hex() if frame.plaintext else None,
                }, ensure_ascii=False))
            else:
                print(format_frame(frame.decoded, verbose=not args.brief))
                if frame.plaintext is not None and not args.brief:
                    print(f"    plaintext: {frame.plaintext.hex()}")
    finally:
        await session.close()
    print(f"\n# {seen} frame(s), {session.stats}", file=sys.stderr)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Console entry point (``miwear-live``); wired into ``miwear cli`` too."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return asyncio.run(args.func(args))
    except LiveDependencyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except LiveTimeout as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except LiveError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:                       # pragma: no cover - tty
        return 130


if __name__ == "__main__":                          # pragma: no cover
    raise SystemExit(main())
