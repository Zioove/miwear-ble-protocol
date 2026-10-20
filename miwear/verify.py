"""Capture verifier — turn a btsnoop/pcap into protocol verdicts.

The rest of this package is built on static analysis of the Xiaomi Health
APK.  Nothing in it has been checked against a real device.  This module is
the opposite: you hand it a capture and it tells you *which* of the
outstanding assumptions actually hold on your hardware.

What it answers
---------------
1. **V2 payload ciphertext** — the headline question.  ``CipherApiCall``
   calls ``r1.a(deviceKey, deviceKey, input)`` / ``r1.b(appKey, appKey,
   input)``, i.e. the AES-CTR IV *is* the full 16-byte session key, and
   ``r1`` hands that straight to ``new IvParameterSpec(iv)``.  The verifier
   derives the key from the stored token plus the ``randomApp`` /
   ``randomDevice`` nonces found in the capture and checks whether the
   decrypted bytes are valid protobuf.  Every ``opcode == 2`` payload must
   decode before the verdict is accepted — one lucky packet is not proof.
2. **Framing health** — CRC pass rate, sequence gaps, retransmissions,
   cross-ATT fragmentation, ACK behaviour against the documented 500 ms
   cumulative-ACK rule, and whether non-ACKable channels got ACKed anyway.
3. **Handshake sanity** — the L1 START request/response TLVs (MPS, window,
   send timeout) and whether the negotiated window matches the APK.

Design rules
------------
* Parsing is *reused*, never re-implemented: :mod:`miwear.capture` peels
  HCI/L2CAP/ATT, :mod:`miwear.layer_l1` splits frames, :mod:`miwear.layer_l2`
  splits channels, :mod:`miwear.protobuf` decodes payloads and
  :mod:`miwear.crypto` does the AES.
* The primary verdict is the source-derived one (``IV = key``).  The other
  counter layouts are kept as **diagnostics**: if the primary guess fails we
  say that the capture disagrees with the decompiled code and report which
  layout would have worked.  That is how a firmware generation difference
  shows itself instead of hiding behind a brute-force "success".
* Pure standard library, Python 3.9+.

Wire facts asserted by this module
---------------------------------
Source of each, so a failing verdict is traceable rather than mysterious:

* IV for a V2 payload is the full 16-byte session key
  (``CipherApiCall.java:78/117`` → ``r1.a(key, key, input)`` →
  ``new IvParameterSpec(iv)``).
* ``deviceSign`` is ``HMAC-SHA256(deviceKey, randomDevice||randomApp)`` —
  device-first, the *reverse* of the HKDF salt order
  (``WearAuthV2.java:179-194``).
* ``ByteUtil.equals()`` only compares ``min(len(a), len(b))`` bytes, so a
  truncated signature can pass on-device; this verifier compares in full and
  reports ``prefix-only`` instead of ``ok``.

Command line
------------
``python -m miwear.verify CAPTURE --token TOKEN [--json] [--key HEX ...]``

:func:`main`, :func:`add_arguments` and :func:`cmd` exist so
``miwear/cli.py`` can register this as a sub-command.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from . import constants as C
from .capture import (
    AttValue,
    CaptureError,
    DIR_DEVICE_TO_HOST,
    DIR_HOST_TO_DEVICE,
    extract_att_values,
    open_capture,
)
from .crypto import (
    aes_ctr_crypt,
    derive_v2_keys,
    sign_hmac,
    sign_message,
)
from .layer_l1 import L1Frame, TruncatedFrame, iter_frames
from .layer_l2 import decode_config_tlv, parse_l2
from .protobuf import WIRE_BYTES, ProtoField, ProtoError, decode as proto_decode
from .protobuf import to_json

__all__ = [
    "VerifyError",
    "ProtoCheck",
    "CtrVariant",
    "CtrDiagnostic",
    "PayloadReport",
    "NonceFinding",
    "FrameRecord",
    "CaptureReport",
    "MIN_CIPHERTEXT_LEN",
    "check_protobuf",
    "parse_token",
    "select_sar_streams",
    "group_streams",
    "split_frames",
    "build_ctr_variants",
    "v2_ctr_variants",
    "shape_score",
    "diagnose_ctr",
    "find_auth_nonces",
    "analyse_payloads",
    "analyse_l1_health",
    "analyse_acks",
    "analyse_fragmentation",
    "analyse_handshake",
    "analyse_capture",
    "render_report",
    "add_arguments",
    "cmd",
    "main",
]

#: Shortest ciphertext we are willing to judge.  Below this a "valid
#: protobuf" result carries no information: random bytes produce a
#: two-field message often enough to be meaningless.
MIN_CIPHERTEXT_LEN = 6

#: Channels whose frames never ask for an ACK (``TransportL1.needSendAck``).
_NO_ACK_CHANNELS = C.CHANNELS_WITHOUT_ACK

#: ACK batching budget from ``SAR_CUM_ACK_TIMEOUT_MS`` (500 ms), plus slack
#: for capture scheduling jitter.
_ACK_BATCH_BUDGET_US = C.SAR_CUM_ACK_TIMEOUT_MS * 1000
_ACK_JITTER_US = 150 * 1000

_DIR_NAMES = {DIR_HOST_TO_DEVICE: "MTU->DEV", DIR_DEVICE_TO_HOST: "DEV->MTU"}

_FRAME_TYPES = {C.TYPE_NAK, C.TYPE_ACK, C.TYPE_CMD, C.TYPE_DATA}


class VerifyError(ValueError):
    """Raised for user-facing problems (bad token, unusable capture, ...)."""


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------

_HEX_SEPARATORS = re.compile(r"[\s:_,-]+")


def parse_token(text: str) -> bytes:
    """Parse a hex token, accepting the usual separators.

    ``DeviceInfo.getToken()`` is a hex *string* converted with
    ``ByteUtil.stringToBytes`` — the digits are the bytes, not UTF-8 text —
    so the CLI takes hex and this validates it eagerly.
    """
    if not isinstance(text, str):
        raise VerifyError("token must be a hex string")
    cleaned = _HEX_SEPARATORS.sub("", text.strip())
    if cleaned[:2].lower() == "0x":
        cleaned = cleaned[2:]
    if not cleaned:
        raise VerifyError("token is empty")
    if len(cleaned) % 2:
        raise VerifyError(
            f"token has an odd number of hex digits ({len(cleaned)})")
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise VerifyError(f"token is not valid hex: {exc}") from exc
    if len(raw) < 8:
        raise VerifyError(
            f"token is only {len(raw)} bytes; the stored auth token is at "
            "least 8 bytes (usually 16)")
    return raw


def _read_key_argument(value: str) -> bytes:
    """Parse a ``--key`` argument (16-byte AES-128 key, hex)."""
    try:
        raw = parse_token(value)
    except VerifyError as exc:
        raise VerifyError(f"--key: {exc}") from exc
    if len(raw) != 16:
        raise VerifyError(f"--key must be 16 bytes, got {len(raw)}")
    return raw


# ---------------------------------------------------------------------------
# Protobuf plausibility
# ---------------------------------------------------------------------------

@dataclass
class ProtoCheck:
    """The outcome of "could these bytes be a protobuf message?"."""

    ok: bool
    reason: str = ""
    fields: list[ProtoField] | None = None
    #: True when :mod:`miwear.protobuf` accepted the buffer structurally.
    structural: bool = False
    #: Fraction of bytes covered by declared field lengths.
    coverage: float = 0.0

    @property
    def summary(self) -> str:
        return self.reason or ("valid protobuf" if self.ok else "not protobuf")


def check_protobuf(data: bytes, *, strict: bool = True) -> ProtoCheck:
    """Decide whether *data* is plausibly a protobuf wire message.

    Args:
        data: candidate plaintext.
        strict: when True (the default) the message must also be "rich"
            enough to be evidence — otherwise a lone ``08 01`` is accepted,
            and random 2-byte buffers look like that roughly 1 time in 128.

    This is a *plausibility* test, not a schema test: no ``.proto`` ships
    with the APK.  The rules are exactly the ones the task calls for —
    field numbers > 0, known wire types, lengths inside the buffer, no
    unterminated varint — plus a byte-coverage check, because a decoder
    that stops early on garbage still produces a "valid" prefix.
    """
    if not data:
        return ProtoCheck(False, "empty plaintext")
    try:
        fields = proto_decode(data)
    except ProtoError as exc:
        return ProtoCheck(False, f"wire-format error: {exc}")
    except Exception as exc:  # noqa: BLE001 - malformed input must not crash
        return ProtoCheck(False, f"undecodable: {exc}")

    if not fields:
        return ProtoCheck(False, "no fields decoded", fields, structural=True)

    covered = sum(_field_encoded_size(f) for f in fields)
    coverage = covered / len(data)
    if coverage < 0.999:
        return ProtoCheck(
            False,
            f"only {coverage:.0%} of the buffer is accounted for by fields",
            fields, structural=True, coverage=coverage)

    if strict:
        if (len(fields) == 1 and fields[0].wire == 0
                and fields[0].value <= 0xFF and len(data) <= 3):
            return ProtoCheck(
                False,
                "degenerate single-byte varint (indistinguishable from noise)",
                fields, structural=True, coverage=coverage)
        if len(fields) == 1 and fields[0].wire == WIRE_BYTES \
                and not fields[0].raw:
            return ProtoCheck(False, "single empty length-delimited field",
                              fields, structural=True, coverage=coverage)

    return ProtoCheck(True, "valid protobuf", fields, structural=True,
                      coverage=coverage)


def _varint_size(value: int) -> int:
    if value < 0:
        value &= 0xFFFFFFFFFFFFFFFF
    size = 1
    while value >= 0x80:
        value >>= 7
        size += 1
    return size


def _field_encoded_size(item: ProtoField) -> int:
    """Bytes a decoded field occupies, tag included."""
    tag = _varint_size((item.number << 3) | item.wire)
    if item.wire == WIRE_BYTES:
        return tag + _varint_size(len(item.raw)) + len(item.raw)
    if item.wire == 0:
        return tag + _varint_size(item.value)
    if item.wire == 1:
        return tag + 8
    if item.wire == 5:
        return tag + 4
    return tag


def shape_score(fields: list[ProtoField] | None) -> int:
    """Heuristic "does this look like a miwear business message?" score.

    Used only to *rank* candidates, never to accept one.  Real messages are
    envelopes: a couple of small varints (``pyt.type``, ``pyt.cmd``)
    followed by length-delimited bodies.
    """
    if not fields:
        return 0
    score = 0
    for item in fields:
        if item.wire == WIRE_BYTES:
            score += 2
            if item.message:
                score += 1
        elif item.wire == 0:
            score += 1 if item.value <= 0xFFFF else 0
        if 1 <= item.number <= 200:
            score += 1
    if len(fields) >= 2:
        score += 1
    return score


# ---------------------------------------------------------------------------
# CTR variants
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CtrVariant:
    """One hypothesis about how the AES-CTR IV is assembled."""

    name: str
    iv: bytes
    counter: int = 0
    counter_little_endian: bool = False
    #: ``v2`` = derived from decompiled code; ``v1-legacy`` = CCM-era
    #: assumption that must not be mixed into the V2 verdict; ``extra`` =
    #: speculative, only useful to explain a surprising result.
    family: str = "v2"
    note: str = ""

    def apply(self, key: bytes, data: bytes) -> bytes:
        return aes_ctr_crypt(key, self.iv, self.counter, data,
                             counter_little_endian=self.counter_little_endian)


@dataclass
class CtrDiagnostic:
    """Result of trying one :class:`CtrVariant` on one payload."""

    variant: CtrVariant
    plaintext: bytes
    check: ProtoCheck
    #: Which key produced this attempt (``appKey``, ``deviceKey``, ``--key[0]``…).
    key_label: str = ""

    @property
    def ok(self) -> bool:
        return self.check.ok

    @property
    def score(self) -> int:
        return shape_score(self.check.fields)

    @property
    def is_source_derived(self) -> bool:
        return self.variant.family == "v2" and self.variant.name == "iv=key"


def _pad_left(iv4: bytes) -> bytes:
    return iv4 + b"\x00" * (16 - len(iv4))


def build_ctr_variants(key: bytes, iv: bytes | None = None, *,
                       legacy_iv4: bytes | None = None,
                       include_extra: bool = True,
                       include_legacy: bool = True) -> list[CtrVariant]:
    """Build CTR variants for *key*, optionally overriding the IV.

    ``iv=None`` means "the IV *is* the key", the verified V2 rule.
    *legacy_iv4* plugs a 4-byte IV (``appIV``/``deviceIV``) into the
    CCM-style layouts for comparison against the V1 path.  Passing *iv*
    explicitly turns the primary variant into ``iv=explicit`` and keeps the
    other layouts as diagnostics.

    This is the single source of truth for the variant list;
    :func:`v2_ctr_variants` is a thin wrapper that feeds it key material.
    """
    if len(key) != 16:
        raise VerifyError(f"AES-128 key must be 16 bytes, got {len(key)}")
    if iv is not None and len(iv) > 16:
        raise VerifyError(f"IV must be at most 16 bytes, got {len(iv)}")

    variants = [CtrVariant(
        name="iv=key" if iv is None else "iv=explicit",
        iv=key if iv is None else iv,
        family="v2",
        note="Source-derived: CipherApiCall:78/117 passes the 16-byte "
             "session key as the IV to r1.a/r1.b.",
    )]
    if include_extra:
        variants.append(CtrVariant(
            name="iv=key/counter+1", iv=iv if iv is not None else key,
            counter=1, family="extra",
            note="Same IV, one block later — detects a stream started "
                 "before the first captured payload."))

    if include_legacy:
        # The 12-byte CCM nonce belongs to the V1 path.  V2 sessions still
        # carry appIV/deviceIV (4 bytes each) so we can build the layout
        # without inventing anything, but it is labelled v1-legacy so it can
        # never be mistaken for the V2 answer.
        nonce_iv = legacy_iv4 if legacy_iv4 is not None else b"\x00" * 4
        if len(nonce_iv) != 4:
            raise VerifyError("legacy IV must be 4 bytes")
        variants += [
            CtrVariant(
                name="ccm-nonce-style/be",
                iv=_pad_left(nonce_iv), family="v1-legacy",
                note="12-byte CCM nonce zero-padded to 16, BE counter in "
                     "the last 4 bytes (SunJCE default). V1-CCM legacy "
                     "assumption — listed so it can be ruled out for V2."),
            CtrVariant(
                name="ccm-nonce-style/le",
                iv=_pad_left(nonce_iv), counter_little_endian=True,
                family="v1-legacy",
                note="Same CCM nonce layout, little-endian counter "
                     "(matches the fixed build_v1_nonce packing)."),
            CtrVariant(
                name="iv4/left+counter0", iv=nonce_iv, family="v1-legacy",
                note="4-byte IV left-aligned, zero counter block."),
            CtrVariant(
                name="iv4/right-be", iv=b"",
                counter=int.from_bytes(nonce_iv, "big"), family="v1-legacy",
                note="4-byte IV right-aligned, BE counter."),
            CtrVariant(
                name="iv4/right-le", iv=b"",
                counter=int.from_bytes(nonce_iv, "little"),
                counter_little_endian=True, family="v1-legacy",
                note="4-byte IV right-aligned, LE counter."),
        ]

    if include_extra:
        variants += [
            CtrVariant(name="iv=key[0:4]/left", iv=key[:4], family="extra",
                       note="Speculative: 4-byte IV left-aligned."),
            CtrVariant(name="iv=key[12:16]/right", iv=b"",
                       counter=int.from_bytes(key[12:16], "big"),
                       family="extra",
                       note="Speculative: 4-byte IV right-aligned, pure "
                            "counter block."),
        ]

    return _dedupe_variants(variants)


def v2_ctr_variants(key: bytes,
                    *, legacy_iv4: bytes | None = None) -> list[CtrVariant]:
    """Every IV layout worth trying for a V2 ``opcode == 2`` payload.

    The first entry is the one the decompiled source demands
    (``CipherApiCall:78`` → ``r1.a(key, key, input)``).  The rest exist so
    a capture that *disagrees* produces a diagnosis rather than a silent
    "unknown".  *legacy_iv4* optionally supplies the 4-byte ``appIV`` /
    ``deviceIV`` for the CCM-era layouts; without it they use a zero IV and
    are only there to be ruled out.
    """
    return build_ctr_variants(key, None, legacy_iv4=legacy_iv4)


def _dedupe_variants(variants: Iterable[CtrVariant]) -> list[CtrVariant]:
    seen: set[tuple[bytes, int, bool]] = set()
    unique: list[CtrVariant] = []
    for variant in variants:
        signature = (variant.iv, variant.counter, variant.counter_little_endian)
        if signature in seen:
            continue
        seen.add(signature)
        unique.append(variant)
    return unique


def diagnose_ctr(keys: Sequence[tuple], ciphertext: bytes,
                 *, variants: Sequence[CtrVariant] | None = None,
                 min_len: int = MIN_CIPHERTEXT_LEN,
                 strict: bool = True) -> list[CtrDiagnostic]:
    """Try every ``(key, variant)`` pair against *ciphertext*.

    *keys* is a sequence of ``(label, key)`` or ``(label, key, legacy_iv4)``
    tuples — the optional third element supplies the 4-byte ``appIV`` /
    ``deviceIV`` used by the CCM-era layouts.  Diagnostics keep the input
    order, so the caller decides which key is primary; the renderer sorts by
    success/score but never lets a non-primary key silently win the verdict.
    """
    if len(ciphertext) < min_len:
        return []

    out: list[CtrDiagnostic] = []
    for entry in keys:
        label, key = entry[0], entry[1]
        legacy_iv4 = entry[2] if len(entry) > 2 else None
        if len(key) != 16:
            raise VerifyError(f"key {label!r} must be 16 bytes")
        chosen = (list(variants) if variants is not None
                  else v2_ctr_variants(key, legacy_iv4=legacy_iv4))
        for variant in chosen:
            try:
                plain = variant.apply(key, ciphertext)
            except ValueError:
                continue
            out.append(CtrDiagnostic(variant, plain,
                                     check_protobuf(plain, strict=strict),
                                     key_label=label))
    return out


# ---------------------------------------------------------------------------
# Capture → ATT values → L1 frames
# ---------------------------------------------------------------------------

def _frame_score(stream: list[AttValue]) -> tuple[int, int]:
    """How convincingly does this ATT stream look like SAR framing?

    Returns ``(crc_ok_frames, total_frames)``.  A capture may label handles
    either by short UUID (``0x005E``/``0x005F``, which is what
    ``miwear capture --handle 5e`` assumes) or by the real ATT attribute
    handle (typically ``0x0010``-``0x0040``).  Rather than guess, we score
    each handle group on the bytes it actually carries.
    """
    blob = b"".join(v.value for v in stream)
    ok = total = 0
    for item in iter_frames(blob):
        if isinstance(item, TruncatedFrame):
            continue
        total += 1
        if item.crc_ok and item.type_raw in _FRAME_TYPES:
            ok += 1
    return ok, total


def select_sar_streams(values: Sequence[AttValue]) -> tuple[list[AttValue],
                                                            list[str]]:
    """Pick the ATT values that carry the SAR stream.

    The two directions live on *different* characteristics (writes on
    ``0x005F``, notifications on ``0x005E``), and a capture may label them by
    short UUID or by the real ATT attribute handle, so the choice has to be
    made **per direction**.  Within one direction every handle group is
    scored by how many CRC-valid SAR frames its bytes contain; the best group
    wins.  When nothing scores at all we fall back to every value (with a
    warning) instead of returning an empty report.
    """
    warnings: list[str] = []
    if not values:
        return [], ["no value-bearing ATT PDUs found in the capture"]

    by_direction: dict[int, dict[int, list[AttValue]]] = {}
    for value in values:
        by_direction.setdefault(value.direction, {}) \
                    .setdefault(value.handle, []).append(value)

    selected: list[AttValue] = []
    for direction, groups in by_direction.items():
        scored: list[tuple[tuple[int, int, int], int, list[AttValue]]] = []
        for handle, bucket in groups.items():
            ok, total = _frame_score(bucket)
            uuid_bonus = 1 if handle in (0x005E, 0x005F) else 0
            scored.append(((ok, total, uuid_bonus), handle, bucket))
        scored.sort(key=lambda item: item[0], reverse=True)
        best_score, best_handle, best = scored[0]
        label = _DIR_NAMES.get(direction, f"dir{direction}")

        if best_score[0] == 0:
            warnings.append(
                f"{label}: no ATT handle produced a CRC-valid SAR frame; "
                f"using all {len(groups)} handle(s) for that direction")
            selected.extend(v for bucket in groups.values() for v in bucket)
            continue

        selected.extend(best)
        rivals = [(score, h) for (score, h, _b) in scored[1:] if score[0] > 0]
        dropped = [h for (score, h, _b) in scored[1:] if score[0] == 0]
        if any(score[0] == best_score[0] for score, _h in rivals):
            warnings.append(
                f"{label}: several ATT handles carry valid frames "
                f"({', '.join(f'0x{h:04x}' for h in groups)}); picked "
                f"0x{best_handle:04x} — cross-check with `miwear capture "
                f"--handle {best_handle:04x}`")
        elif rivals:
            warnings.append(
                f"{label}: ignored handles "
                + ", ".join(f"0x{h:04x}" for _s, h in rivals)
                + f" (fewer valid SAR frames); using 0x{best_handle:04x}")
        if dropped:
            warnings.append(
                f"{label}: ignored handles "
                + ", ".join(f"0x{h:04x}" for h in dropped)
                + " (no SAR frames at all); using "
                f"0x{best_handle:04x}")

        if best_handle not in (0x005E, 0x005F):
            warnings.append(
                f"{label}: SAR traffic is on ATT handle 0x{best_handle:04x}, "
                f"not the documented short UUID 0x005E/0x005F — expected, "
                f"a GATT attribute handle is not the characteristic UUID")

    selected.sort(key=lambda v: v.timestamp_us)
    return selected, warnings


def collect_att_values(path: str) -> tuple[list[AttValue], list[str]]:
    """Read *path* and return ``(SAR ATT values, warnings)`` in capture order."""
    packets = open_capture(path)
    values, warnings = select_sar_streams(extract_att_values(packets))
    warnings = capture_format_warnings(path) + warnings
    return values, warnings


def capture_format_warnings(path: str) -> list[str]:
    """Flag capture formats that lose information we rely on.

    A pcap with link type 187 (``DLT_BLUETOOTH_HCI_H4``) has no
    direction field, so every packet looks host→device.  Both directions
    then land in one stream, which corrupts sequence tracking and key
    selection.  Better to say so than to report a confusing verdict.
    """
    warnings: list[str] = []
    try:
        with open(path, "rb") as fh:
            head = fh.read(24)
    except OSError:  # pragma: no cover - open_capture reports this first
        return warnings

    if head[:4] == b"\x0a\x0d\x0d\x0a":
        warnings.append(
            "pcapng detected — convert to pcap first: editcap -F pcap in out")
    elif len(head) >= 24 and head[:4] in (
            b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1",
            b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = "<" if head[0] == 0xD4 or head[1] == 0x3C else ">"
        try:
            link_type = int.from_bytes(
                head[20:24], "little" if endian == "<" else "big")
        except (IndexError, ValueError):
            link_type = None
        if link_type == C.DLT_BLUETOOTH_HCI_H4:
            warnings.append(
                "pcap link type 187 carries no packet direction, so both "
                "traffic directions are merged; use a btsnoop log or a pcap "
                "with link type 201 (H4 + pseudo-header) for a reliable "
                "verdict")
    return warnings


def group_streams(values: Iterable[AttValue]) -> dict[str, list[AttValue]]:
    """Split ATT values into the two per-direction byte streams."""
    streams: dict[str, list[AttValue]] = {"MTU->DEV": [], "DEV->MTU": []}
    for value in values:
        label = _DIR_NAMES.get(value.direction)
        if label is not None:
            streams[label].append(value)
    for bucket in streams.values():
        bucket.sort(key=lambda v: v.timestamp_us)
    return streams


@dataclass
class FrameRecord:
    """One L1 frame plus where it came from."""

    frame: L1Frame
    direction: str
    att_values: list[AttValue] = field(default_factory=list)

    @property
    def timestamp_us(self) -> int:
        return self.att_values[0].timestamp_us if self.att_values else 0

    @property
    def l2(self):
        if self.frame.type_raw != C.TYPE_DATA or not self.frame.payload:
            return None
        return parse_l2(self.frame.payload)

    @property
    def is_encrypted(self) -> bool:
        packet = self.l2
        return bool(packet and packet.is_encrypted)


def split_frames(stream: list[AttValue],
                 direction: str = "?") -> tuple[list[FrameRecord],
                                                list[TruncatedFrame]]:
    """Concatenate one direction's ATT values and parse the L1 frames.

    A frame can span several ATT writes and a write can hold several frames,
    so the only correct approach is to concatenate first (this mirrors
    :func:`miwear.session.decode_att_values`) and then map each frame's byte
    range back to the writes that carried it.
    """
    blob = b"".join(v.value for v in stream)
    spans: list[tuple[int, int, AttValue]] = []
    cursor = 0
    for value in stream:
        spans.append((cursor, cursor + len(value.value), value))
        cursor += len(value.value)

    records: list[FrameRecord] = []
    truncated: list[TruncatedFrame] = []
    for item in iter_frames(blob):
        if isinstance(item, TruncatedFrame):
            truncated.append(item)
            continue
        start = item.offset
        end = item.offset + C.L1_HEADER_SIZE + item.data_length
        carriers = [v for (a, b, v) in spans if b > start and a < end]
        records.append(FrameRecord(item, direction, carriers))
    return records, truncated


def analyse_fragmentation(records: Sequence[FrameRecord],
                          values: Sequence[AttValue]) -> dict:
    """Quantify multi-write frames and multi-frame writes."""
    per_value: dict[int, int] = {id(v): 0 for v in values}
    cross = 0
    max_writes = 0
    for record in records:
        count = len(record.att_values)
        max_writes = max(max_writes, count)
        if count > 1:
            cross += 1
        for value in record.att_values:
            per_value[id(value)] = per_value.get(id(value), 0) + 1
    multi_frame_writes = sum(1 for n in per_value.values() if n > 1)
    return {
        "att_values": len(values),
        "frames": len(records),
        "cross_att_frames": cross,
        "max_writes_per_frame": max_writes,
        "writes_carrying_multiple_frames": multi_frame_writes,
        "bytes": sum(len(v.value) for v in values),
    }


def analyse_l1_health(records: Sequence[FrameRecord],
                      truncated: Sequence[TruncatedFrame]) -> dict:
    """CRC pass rate, frame mix, sequence gaps and retransmissions."""
    by_type: dict[str, int] = {}
    by_direction: dict[str, int] = {}
    crc_ok = 0
    bad_offsets: list[int] = []
    gaps: list[dict] = []
    retransmits = 0

    for record in records:
        frame = record.frame
        by_type[frame.type_name] = by_type.get(frame.type_name, 0) + 1
        by_direction[record.direction] = by_direction.get(record.direction, 0) + 1
        if frame.crc_ok:
            crc_ok += 1
        else:
            bad_offsets.append(frame.offset)

    for direction in ("MTU->DEV", "DEV->MTU"):
        data_frames = [r for r in records
                       if r.direction == direction
                       and r.frame.type_raw == C.TYPE_DATA]
        data_frames.sort(key=lambda r: r.timestamp_us or r.frame.offset)
        seen: set[int] = set()
        expected: int | None = None
        for record in data_frames:
            seq = record.frame.seq
            if expected is not None and seq != expected & 0xFF:
                gaps.append({
                    "direction": direction,
                    "expected": expected & 0xFF,
                    "got": seq,
                })
            expected = seq + 1
            if seq in seen:
                retransmits += 1
            seen.add(seq)

    total = len(records)
    return {
        "frames": total,
        "by_type": by_type,
        "by_direction": by_direction,
        "crc_ok": crc_ok,
        "crc_bad": total - crc_ok,
        "crc_pass_rate": (crc_ok / total) if total else 0.0,
        "bad_crc_offsets": bad_offsets[:16],
        "truncated": len(truncated),
        "seq_gaps": gaps[:16],
        "seq_gap_count": len(gaps),
        "retransmissions": retransmits,
    }


def analyse_acks(records: Sequence[FrameRecord]) -> dict:
    """Check ACK behaviour against the documented rules.

    Sources: ``TransportL1`` ACKs immediately on PB/LYRA, batches a
    cumulative ACK every ``SAR_CUM_ACK_TIMEOUT_MS`` (500 ms) on the file
    channels, NAKs out-of-order frames, and never ACKs NETWORK/MULTI_MODAL.
    A cumulative ACK for sequence *n* covers every DATA frame up to *n*.

    The 500 ms rule is a **batching budget**: an ACK should not be sent later
    than 500 ms after the frame it acknowledges.  ACKs arriving *sooner* than
    that are perfectly legal (an immediate ACK per frame is what channel 1
    does), so only ``ack_latency > budget`` counts as a violation.
    """
    result: dict = {
        "acks": 0,
        "naks": 0,
        "acked_frames": 0,
        "unacked_frames": 0,
        "no_ack_channel_frames": 0,
        "unexpected_acks": 0,
        "ack_latency_us_p50": None,
        "ack_latency_us_max": None,
        "ack_latency_samples": 0,
        "budget_us": _ACK_BATCH_BUDGET_US,
        "budget_compliant": True,
        "budget_violations": [],
        "first_ack_delay_us": None,
        "details": [],
    }
    latencies: list[int] = []

    for direction, peer in (("MTU->DEV", "DEV->MTU"), ("DEV->MTU", "MTU->DEV")):
        data = sorted(
            [r for r in records if r.direction == direction
             and r.frame.type_raw == C.TYPE_DATA],
            key=lambda r: r.timestamp_us)
        acks = sorted(
            [r for r in records if r.direction == peer
             and r.frame.type_raw in (C.TYPE_ACK, C.TYPE_NAK)],
            key=lambda r: r.timestamp_us)
        result["acks"] += sum(1 for a in acks
                              if a.frame.type_raw == C.TYPE_ACK)
        result["naks"] += sum(1 for a in acks
                              if a.frame.type_raw == C.TYPE_NAK)

        acked: set[int] = set()
        acked_any = False
        for ack in acks:
            if ack.frame.type_raw != C.TYPE_ACK:
                continue
            covered_here = 0
            for record in data:
                if id(record) in acked:
                    continue
                channel = record.l2.channel if record.l2 else None
                if channel in _NO_ACK_CHANNELS:
                    continue
                if record.frame.seq > ack.frame.seq:
                    continue
                latency = ack.timestamp_us - record.timestamp_us
                if latency < 0:
                    result["unexpected_acks"] += 1
                    continue
                acked.add(id(record))
                covered_here += 1
                latencies.append(latency)
                if not acked_any:
                    result["first_ack_delay_us"] = latency
                    acked_any = True
                if latency > _ACK_BATCH_BUDGET_US + _ACK_JITTER_US:
                    result["budget_compliant"] = False
                    result["budget_violations"].append(latency)
            if covered_here:
                result["details"].append({
                    "direction": direction,
                    "ack_seq": ack.frame.seq,
                    "covered": covered_here,
                })

        for record in data:
            channel = record.l2.channel if record.l2 else None
            if channel in _NO_ACK_CHANNELS:
                result["no_ack_channel_frames"] += 1
            elif id(record) not in acked:
                result["unacked_frames"] += 1
        result["acked_frames"] += len(acked)

    if latencies:
        result["ack_latency_us_p50"] = int(statistics.median(latencies))
        result["ack_latency_us_max"] = max(latencies)
        result["ack_latency_samples"] = len(latencies)
    result["budget_violations"] = sorted(set(result["budget_violations"]))[:8]
    result["details"] = result["details"][:16]
    return result


def analyse_handshake(records: Sequence[FrameRecord]) -> dict:
    """Inspect the L1 START request/response and derive negotiated params."""
    result: dict = {
        "requests": 0,
        "responses": 0,
        "request": None,
        "response": None,
        "negotiated_window": None,
        "cum_ack_threshold": None,
        "warnings": [],
    }
    for record in records:
        if record.frame.type_raw != C.TYPE_CMD:
            continue
        info = decode_config_tlv(record.frame.payload)
        cmd = info.get("cmd")
        entry = {
            "direction": record.direction,
            "frx": record.frame.frx,
            "cmd": cmd,
            "cmd_name": info.get("cmd_name"),
            "config": {c["type"]: c.get("u16", c.get("version",
                                                       c.get("value")))
                       for c in info.get("config", [])},
            "trailing": info.get("trailing"),
            "timestamp_us": record.timestamp_us,
        }
        if cmd == C.CMD_L1START_REQ:
            result["requests"] += 1
            result["request"] = result["request"] or entry
        elif cmd == C.CMD_L1START_RSP:
            result["responses"] += 1
            result["response"] = result["response"] or entry

    req, rsp = result["request"], result["response"]
    if req and rsp:
        local = req["config"].get(C.CONFIG_TX_WIN)
        remote = rsp["config"].get(C.CONFIG_TX_WIN)
        if isinstance(local, int) and isinstance(remote, int):
            window = min(local, remote)
            result["negotiated_window"] = window
            result["cum_ack_threshold"] = window * 2 // 3
        if not rsp["frx"]:
            result["warnings"].append(
                "START_RSP did not set frx=1 (expected for a response)")
        if req["trailing"] or rsp["trailing"]:
            result["warnings"].append("CMD config TLV had trailing bytes")
    elif req:
        result["warnings"].append(
            "START_REQ seen but no START_RSP — session never established")
    return result


# ---------------------------------------------------------------------------
# Protobuf helpers for the auth exchange
# ---------------------------------------------------------------------------

@dataclass
class NonceFinding:
    """The auth nonces recovered from the plaintext part of the session."""

    random_app: bytes | None = None
    random_device: bytes | None = None
    device_sign: bytes | None = None
    candidates_app: list[bytes] = field(default_factory=list)
    candidates_device: list[bytes] = field(default_factory=list)
    source: str = "none"
    warnings: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return bool(self.random_app and self.random_device)


def _walk_fields(fields: Sequence[ProtoField], path: tuple[int, ...] = ()):
    """Yield ``(path, field)`` for a decoded message, depth first."""
    for item in fields:
        here = path + (item.number,)
        yield here, item
        if item.message:
            yield from _walk_fields(item.message, here)


def _field_at(fields: Sequence[ProtoField], path: tuple[int, ...]):
    """Follow *path* through nested messages and return the field or None."""
    current: Sequence[ProtoField] | None = fields
    found = None
    for number in path:
        if not current:
            return None
        found = next((f for f in current if f.number == number), None)
        if found is None:
            return None
        current = found.message
    return found


def find_auth_nonces(records: Sequence[FrameRecord]) -> NonceFinding:
    """Recover ``randomApp`` / ``randomDevice`` (and ``deviceSign``) from a
    capture.

    Wire layout, from :mod:`miwear.constants` and ``docs/PROTOCOL.md``::

        pyt{ type=1 (field 1), cmd (field 2), va0 (field 3) }
        va0{ bb0 = field 30, hb0 = field 31 }
        bb0{ randomApp = field 1, appDeviceId = field 2, hasOob = field 3 }
        hb0{ randomDevice = field 1, deviceSign = field 2 }

    The structured path is tried first.  If the capture predates the auth
    exchange, or the frame was decrypted by an earlier tool, a generic scan
    for 16-byte length-delimited fields is used as a fallback — the caller
    then tries every ordered pair, so a wrong guess cannot silently win.
    """
    finding = NonceFinding()
    app_candidates: list[bytes] = []
    dev_candidates: list[bytes] = []
    sign: bytes | None = None
    structured_app = structured_dev = False

    for record in records:
        packet = record.l2
        if packet is None or packet.is_encrypted or not packet.data:
            continue
        try:
            fields = proto_decode(packet.data)
        except ProtoError:
            continue

        # 1. Structured: pyt{cmd=26} / va0{30|31} with absolute field ids.
        cmd_field = _field_at(fields, (2,))
        cmd = cmd_field.value if cmd_field and cmd_field.wire == 0 else None
        va0 = _field_at(fields, (3,))
        if va0 is not None and va0.message:
            app_msg = next((f for f in va0.message
                            if f.number == C.VA0_FIELD_VERIFY_REQ), None)
            rsp_msg = next((f for f in va0.message
                            if f.number == C.VA0_FIELD_VERIFY_RSP), None)
            if app_msg is not None and app_msg.message:
                random_app = _field_at(app_msg.message, (1,))
                if (random_app is not None and len(random_app.raw) == 16
                        and random_app.message is None):
                    app_candidates.append(random_app.raw)
                    if finding.random_app is None:
                        finding.random_app = random_app.raw
                        structured_app = True
            if rsp_msg is not None and rsp_msg.message:
                random_device = _field_at(rsp_msg.message, (1,))
                if (random_device is not None and len(random_device.raw) == 16
                        and random_device.message is None):
                    dev_candidates.append(random_device.raw)
                    if finding.random_device is None:
                        finding.random_device = random_device.raw
                        structured_dev = True
                device_sign = _field_at(rsp_msg.message, (2,))
                if device_sign is not None and device_sign.raw:
                    # Deliberately do NOT require a 32-byte length here: a
                    # truncated/oversized signature is exactly the anomaly
                    # ByteUtil.equals() would hide, so it must reach the
                    # comparison and be reported, not silently dropped.
                    sign = sign or device_sign.raw
            if finding.random_app or finding.random_device:
                finding.source = (f"pyt.cmd={cmd} / va0."
                                  + ("bb0.randomApp" if structured_app
                                     else "hb0.randomDevice"))

        # 2. Generic fallback: 16-byte blobs grouped by direction.  A blob
        #    that parses as a nested message is almost certainly not a nonce.
        if finding.random_app is None or finding.random_device is None:
            for _path, item in _walk_fields(fields):
                if item.wire != WIRE_BYTES or len(item.raw) != 16:
                    continue
                if item.message:
                    continue
                if record.direction == "MTU->DEV":
                    app_candidates.append(item.raw)
                else:
                    dev_candidates.append(item.raw)

    if finding.random_app is None and app_candidates:
        finding.random_app = app_candidates[0]
        finding.source = "generic 16-byte scan (MTU->DEV)"
        finding.warnings.append(
            "randomApp taken from a generic 16-byte scan, not the "
            "va0.bb0.randomApp path — confirm with `miwear verify --json`")
    if finding.random_device is None and dev_candidates:
        finding.random_device = dev_candidates[0]
        finding.source = "generic 16-byte scan (DEV->MTU)"
        finding.warnings.append(
            "randomDevice taken from a generic 16-byte scan, not the "
            "va0.hb0.randomDevice path")

    finding.device_sign = sign
    finding.candidates_app = _uniq(app_candidates)
    finding.candidates_device = _uniq(dev_candidates)
    if not finding.complete:
        finding.warnings.append(
            "auth nonces not found — either the capture starts after the "
            "handshake or the auth frames were themselves encrypted")
    return finding


def _uniq(items: Iterable[bytes]) -> list[bytes]:
    seen: set[bytes] = set()
    out: list[bytes] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


# ---------------------------------------------------------------------------
# Payload analysis
# ---------------------------------------------------------------------------

@dataclass
class PayloadReport:
    """One ``opcode == 2`` L2 payload and every decryption attempt."""

    index: int
    direction: str
    seq: int
    channel: int
    ciphertext: bytes
    key_label: str = ""
    diagnostics: list[CtrDiagnostic] = field(default_factory=list)
    skipped: str = ""

    @property
    def length(self) -> int:
        return len(self.ciphertext)

    @property
    def winning(self) -> CtrDiagnostic | None:
        """The accepted plaintext, or ``None``.

        A non-source-derived layout only wins when it is the *only* thing
        that works; the source-derived layout always takes precedence.  This
        is what keeps a lucky guess from being reported as a discovery.
        """
        usable = [d for d in self.diagnostics if d.ok]
        if not usable:
            return None
        for diagnostic in usable:
            if diagnostic.is_source_derived:
                return diagnostic
        usable.sort(key=lambda d: d.score, reverse=True)
        return usable[0]

    @property
    def primary_diagnostics(self) -> list[CtrDiagnostic]:
        """Attempts made with the direction-appropriate key.

        Cross-key attempts (``deviceKey`` tried on app traffic and vice
        versa) stay in :attr:`diagnostics` for the ``--verbose`` view but are
        noise in the main table: they can only ever confirm a key mix-up.
        """
        if not self.diagnostics:
            return []
        first = self.diagnostics[0].key_label
        return [d for d in self.diagnostics if d.key_label == first]

    @property
    def resolved(self) -> bool:
        return self.winning is not None

    @property
    def resolved_source_derived(self) -> bool:
        winner = self.winning
        return bool(winner and winner.is_source_derived)

    @property
    def plaintext(self) -> bytes:
        winner = self.winning
        return winner.plaintext if winner else b""

    def to_dict(self) -> dict:
        winner = self.winning
        return {
            "index": self.index,
            "direction": self.direction,
            "seq": self.seq,
            "channel": self.channel,
            "channel_name": C.CHANNEL_NAMES.get(self.channel, "?"),
            "length": self.length,
            "key": self.key_label,
            "skipped": self.skipped,
            "resolved": self.resolved,
            "via": winner.variant.name if winner else None,
            "plaintext_hex": self.plaintext.hex() if winner else None,
            "proto": to_json(winner.check.fields) if winner and winner.check.fields else None,
            "variants": [
                {
                    "key": self.key_label,
                    "variant": diagnostic.variant.name,
                    "family": diagnostic.variant.family,
                    "valid": diagnostic.ok,
                    "score": diagnostic.score,
                    "plaintext": diagnostic.plaintext.hex(),
                    "reason": diagnostic.check.reason,
                }
                for diagnostic in self.diagnostics
            ],
        }


def _key_candidates(direction: str, keys: dict[str, bytes],
                    explicit: Sequence[tuple] = ()) -> list[tuple]:
    """Order key candidates for one direction.

    The app encrypts with ``appKey`` (``CipherApiCall:117`` → ``r1.b``) and
    decrypts device traffic with ``deviceKey`` (``:78`` → ``r1.a``), so the
    direction-appropriate key goes first.  Each entry is
    ``(label, key, legacy_iv4)`` where the last element is the matching
    4-byte IV for the CCM-era comparison layouts.
    """
    ordered: list[tuple] = []
    preferred = "appKey" if direction == "MTU->DEV" else "deviceKey"
    fallback = "deviceKey" if preferred == "appKey" else "appKey"
    for name in (preferred, fallback):
        if name in keys:
            iv = keys.get("appIV" if name == "appKey" else "deviceIV")
            ordered.append((name, keys[name], iv))
    ordered.extend(entry if len(entry) > 2 else (entry[0], entry[1], None)
                   for entry in explicit)
    seen: set[bytes] = set()
    unique: list[tuple] = []
    for entry in ordered:
        if entry[1] in seen:
            continue
        seen.add(entry[1])
        unique.append(entry)
    return unique


def analyse_payloads(records: Sequence[FrameRecord], keys: dict[str, bytes],
                     *, explicit_keys: Sequence[tuple[str, bytes]] = (),
                     min_len: int = MIN_CIPHERTEXT_LEN) -> list[PayloadReport]:
    """Decrypt every ``opcode == 2`` payload and record all attempts."""
    reports: list[PayloadReport] = []
    index = 0
    for record in records:
        frame = record.frame
        if frame.type_raw != C.TYPE_DATA:
            continue
        packet = parse_l2(frame.payload) if frame.payload else None
        if packet is None or not packet.is_encrypted:
            continue
        candidates = _key_candidates(record.direction, keys, explicit_keys)
        report = PayloadReport(
            index=index, direction=record.direction, seq=frame.seq,
            channel=packet.channel, ciphertext=packet.data,
            key_label=", ".join(entry[0] for entry in candidates) or "-",
        )
        index += 1
        if len(packet.data) < min_len:
            report.skipped = (
                f"shorter than {min_len} bytes — too few degrees of freedom "
                "for a protobuf test")
        elif not candidates:
            report.skipped = "no session key available"
        else:
            report.diagnostics = diagnose_ctr(
                candidates, packet.data, min_len=min_len)
        reports.append(report)
    return reports


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

@dataclass
class CaptureReport:
    """Everything the verifier learned from one capture file."""

    path: str
    token: bytes | None = None
    att_values: list[AttValue] = field(default_factory=list)
    records: list[FrameRecord] = field(default_factory=list)
    truncated: list[TruncatedFrame] = field(default_factory=list)
    payloads: list[PayloadReport] = field(default_factory=list)
    keys: dict[str, bytes] = field(default_factory=dict)
    nonces: NonceFinding = field(default_factory=NonceFinding)
    explicit_keys: list[tuple[str, bytes]] = field(default_factory=list)
    signature: dict = field(default_factory=dict)
    handshake: dict = field(default_factory=dict)
    l1_health: dict = field(default_factory=dict)
    ack_health: dict = field(default_factory=dict)
    fragment_health: dict = field(default_factory=dict)
    verdict: str = "insufficient-data"
    verdict_note: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def encrypted_payloads(self) -> list[PayloadReport]:
        """Payloads that carried ciphertext (including ones we skipped)."""
        return [p for p in self.payloads if p.ciphertext]

    @property
    def adequate_payloads(self) -> list[PayloadReport]:
        """Payloads long enough (and keyed enough) to actually judge."""
        return [p for p in self.payloads if not p.skipped]

    def to_dict(self) -> dict:
        return {
            "capture": self.path,
            "token_len": len(self.token) if self.token else 0,
            "att_values": len(self.att_values),
            "frames": len(self.records),
            "keys": {name: key.hex() for name, key in self.keys.items()},
            "nonces": {
                "randomApp": self.nonces.random_app.hex()
                if self.nonces.random_app else None,
                "randomDevice": self.nonces.random_device.hex()
                if self.nonces.random_device else None,
                "source": self.nonces.source,
                "complete": self.nonces.complete,
            },
            "signature": self.signature,
            "verdict": self.verdict,
            "verdict_note": self.verdict_note,
            "warnings": list(self.warnings),
            "handshake": self.handshake,
            "l1_health": self.l1_health,
            "ack_health": self.ack_health,
            "fragment_health": self.fragment_health,
            "payloads": [p.to_dict() for p in self.payloads],
        }


def _derive_key_candidates(token: bytes, nonces: NonceFinding,
                           ) -> tuple[dict[str, bytes], dict, list[str]]:
    """Derive V2 keys for the plausible nonce orders; verify the signature."""
    keys: dict[str, bytes] = {}
    signature: dict = {"present": False, "status": "absent"}
    warnings: list[str] = []
    if not (token and nonces.random_app and nonces.random_device):
        return keys, signature, warnings

    primary = derive_v2_keys(token, nonces.random_app, nonces.random_device)
    keys["deviceKey"] = primary.device_key
    keys["appKey"] = primary.app_key
    keys["deviceIV"] = primary.device_iv
    keys["appIV"] = primary.app_iv
    signature = {"present": False, "status": "absent",
                 "detail": "no deviceSign in the capture"}

    if nonces.device_sign:
        # deviceSign covers randomDevice || randomApp  (the *reverse* of the
        # HKDF salt order) — see crypto.sign_message / WearAuthV2.java:179-194.
        message = sign_message(nonces.random_app, nonces.random_device)
        expected = sign_hmac(primary.device_key, message)
        candidates = [("as-parsed", primary, expected)]
        if nonces.random_app != nonces.random_device:
            swapped = derive_v2_keys(token, nonces.random_device,
                                     nonces.random_app)
            candidates.append(("swapped-nonces", swapped,
                               sign_hmac(swapped.device_key, message)))

        signature = _judge_device_sign(nonces.device_sign, candidates)
        by_label = {label: candidate for label, candidate, _h in candidates}

        if signature["status"] == "ok-normalised":
            chosen = by_label["swapped-nonces"]
            keys["deviceKey"] = chosen.device_key
            keys["appKey"] = chosen.app_key
            keys["deviceIV"] = chosen.device_iv
            keys["appIV"] = chosen.app_iv
        if signature["status"] == "mismatch":
            warnings.append("deviceSign does not verify: check the auth token")
            swapped = by_label.get("swapped-nonces")
            if swapped is not None:
                keys["deviceKey(swapped)"] = swapped.device_key
                keys["appKey(swapped)"] = swapped.app_key
        if signature["status"] == "prefix-only":
            # ByteUtil.equals() compares min(len) bytes, so a short or
            # truncated capture signature can "pass" the device's real check
            # while being wrong. Never let that count as a confirmation.
            warnings.append(
                "deviceSign is only a prefix of the expected HMAC — the "
                "device's ByteUtil.equals() would accept it, but that is a "
                "known comparison bug, not proof the key is right")
    return keys, signature, warnings


def _judge_device_sign(captured: bytes,
                       candidates: Sequence[tuple[str, object, bytes]]) -> dict:
    """Compare a captured deviceSign against candidate HMACs.

    Uses **full-length** comparison on purpose. The APK's
    ``ByteUtil.equals()`` only compares ``min(len(a), len(b))`` bytes, so a
    truncated signature would pass on-device. Reporting that as a separate
    ``prefix-only`` status keeps a comparison bug from masquerading as a
    successful key confirmation.

    *candidates* is ``(label, keys, expected_hmac)``.
    """
    full = [(label, expected) for label, _keys, expected in candidates
            if expected == captured]
    if full:
        label = full[0][0]
        if label == "as-parsed":
            return {
                "present": True,
                "status": "ok",
                "detail": "HMAC-SHA256(deviceKey, randomDevice||randomApp) "
                          "matches over the full 32 bytes — token, nonce "
                          "order and key derivation are confirmed before "
                          "decryption",
                "captured_len": len(captured),
            }
        return {
            "present": True,
            "status": "ok-normalised",
            "detail": "signature matches only with the nonces swapped; "
                      "deviceKey/appKey exchanged",
            "nonce_order": label,
            "captured_len": len(captured),
        }

    short = [(label, expected) for label, _keys, expected in candidates
             if captured and len(captured) < len(expected)
             and expected.startswith(captured)]
    if short:
        label = short[0][0]
        return {
            "present": True,
            "status": "prefix-only",
            "detail": f"deviceSign is only {len(captured)} bytes and is a "
                      f"prefix of the {len(short[0][1])}-byte HMAC for "
                      f"{label}; ByteUtil.equals() would accept it, but the "
                      "truncated value proves nothing",
            "captured_len": len(captured),
            "nonce_order": label,
        }

    return {
        "present": True,
        "status": "mismatch",
        "detail": "HMAC-SHA256(deviceKey, randomDevice||randomApp) != "
                  "deviceSign — the token is wrong or the nonces were "
                  "recovered incorrectly; decryption below is probably "
                  "meaningless",
        "captured_len": len(captured),
    }


def analyse_capture(path: str, token: bytes | str | None = None, *,
                    explicit_keys: Sequence[tuple[str, bytes]] = (),
                    min_len: int = MIN_CIPHERTEXT_LEN) -> CaptureReport:
    """Run every check over *path* and return a :class:`CaptureReport`."""
    if isinstance(token, str):
        token = parse_token(token)
    report = CaptureReport(path=path, token=token,
                           explicit_keys=list(explicit_keys))

    values, warnings = collect_att_values(path)
    report.att_values = values
    report.warnings.extend(warnings)

    streams = group_streams(values)
    for label, stream in streams.items():
        records, truncated = split_frames(stream, label)
        report.records.extend(records)
        report.truncated.extend(truncated)

    report.fragment_health = analyse_fragmentation(report.records, values)
    report.l1_health = analyse_l1_health(report.records, report.truncated)
    report.ack_health = analyse_acks(report.records)
    report.handshake = analyse_handshake(report.records)

    report.nonces = find_auth_nonces(report.records)
    report.warnings.extend(report.nonces.warnings)

    if token:
        keys, signature, key_warnings = _derive_key_candidates(
            token, report.nonces)
        report.keys.update(keys)
        report.signature = signature
        report.warnings.extend(key_warnings)
    elif any(r.is_encrypted for r in report.records):
        report.warnings.append(
            "encrypted payloads present but no --token given; "
            "no session key can be derived")

    report.payloads = analyse_payloads(
        report.records, report.keys, explicit_keys=explicit_keys,
        min_len=min_len)

    _decide_verdict(report)
    return report


def _decide_verdict(report: CaptureReport) -> None:
    """Fill ``report.verdict`` / ``verdict_note`` from the payload results."""
    encrypted = [r for r in report.records if r.is_encrypted]
    if not encrypted:
        report.verdict = "no-encrypted-traffic"
        report.verdict_note = (
            "no opcode=2 (encrypted) payloads in this capture — nothing to "
            "decide; framing checks below are still valid")
        return

    judged = report.adequate_payloads
    if not judged:
        report.verdict = "insufficient-data"
        reasons = {p.skipped for p in report.payloads if p.skipped}
        report.verdict_note = (
            f"{len(encrypted)} encrypted payload(s) seen but none could be "
            "judged: " + ("; ".join(sorted(reasons)) or "unknown reason"))
        return

    if not report.keys and not report.explicit_keys:
        report.verdict = "insufficient-data"
        report.verdict_note = (
            f"{len(judged)} encrypted payload(s) need a session key; pass "
            "--token (and make sure the capture includes the V2 auth "
            "nonces) or --key")
        return

    resolved = [p for p in judged if p.resolved]
    source_derived = [p for p in resolved if p.resolved_source_derived]
    # A payload that only decrypts with the *other* direction's key is
    # evidence for a key↔direction mix-up, not for the IV layout. It still
    # proves "IV = key" (the variant matched), but the report has to say so.
    mixed = [p for p in resolved if p.winning is not None
             and p.primary_diagnostics
             and not p.primary_diagnostics[0].ok]

    if len(source_derived) == len(judged):
        report.verdict = "confirmed-iv-is-key"
        report.verdict_note = (
            f"all {len(judged)} encrypted payload(s) decrypt to valid "
            "protobuf with IV = the full 16-byte session key — this is the "
            "layout in CipherApiCall:78/117 and r1.java; no other variant "
            "is needed")
        if report.signature.get("status") in ("ok", "ok-normalised"):
            report.verdict_note += "; deviceSign also verified"
        if mixed:
            labels = sorted({p.winning.key_label for p in mixed})
            report.verdict_note += (
                f". Note: {len(mixed)} payload(s) only decrypted with a "
                f"non-preferred key ({', '.join(labels)}) — the IV rule "
                "holds, but check the key↔direction mapping")
        return

    if resolved and all(not p.resolved_source_derived for p in resolved) \
            and len(resolved) == len(judged):
        winners = sorted({p.winning.variant.name for p in resolved})
        report.verdict = "contradicts-source"
        report.verdict_note = (
            f"every payload decrypts, but not with IV = key: {', '.join(winners)}. "
            "The capture disagrees with the decompiled code — suspect a "
            "firmware generation difference or a key mix-up (appKey vs "
            "deviceKey).")
        return

    if resolved:
        report.verdict = "partial"
        report.verdict_note = (
            f"{len(source_derived)}/{len(judged)} payload(s) decrypt with "
            "IV = key and "
            f"{len(resolved) - len(source_derived)}/{len(judged)} only with "
            "a fallback layout. Mixed evidence: a hardcoded key, a "
            "mid-session rekey, or a nonce recovered incorrectly can all "
            "produce this. Re-run with an explicit --key to separate them.")
        return

    report.verdict = "undetermined"
    best = max((d.score for p in judged for d in p.diagnostics), default=0)
    report.verdict_note = (
        f"none of {len(judged)} encrypted payload(s) decrypt to valid "
        f"protobuf under any of {len(judged[0].diagnostics) or 0} tested "
        f"layouts (best shape score {best}). Check the token, the nonce "
        "recovery and whether the payloads are truncated by the capture.")


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_VERDICT_TITLES = {
    "confirmed-iv-is-key": "CONFIRMED — V2 IV is the full 16-byte session key",
    "contradicts-source": "CONTRADICTED — capture disagrees with the source",
    "partial": "PARTIAL — mixed evidence",
    "undetermined": "UNDETERMINED — no layout produced valid protobuf",
    "insufficient-data": "INSUFFICIENT DATA",
    "no-encrypted-traffic": "NO ENCRYPTED TRAFFIC",
}


def render_report(report: CaptureReport, *, show_variants: bool = True,
                  max_payloads: int = 20) -> str:
    """Render a :class:`CaptureReport` as a human-readable text report."""
    lines: list[str] = []
    add = lines.append

    add("miwear verify — capture report")
    add(f"capture: {report.path}")
    add(f"ATT values: {len(report.att_values)}   "
        f"L1 frames: {len(report.records)}   "
        f"truncated: {len(report.truncated)}")
    add("")

    add("[verdict] " + _VERDICT_TITLES.get(report.verdict, report.verdict))
    add("  " + report.verdict_note)
    add("")

    # --- keys -------------------------------------------------------------
    add("[keys]")
    if report.keys:
        for name, key in report.keys.items():
            add(f"  {name:<20} {key.hex()}")
    else:
        add("  (none — pass --token, or supply --key)")
    nonces = report.nonces
    add(f"  randomApp            {nonces.random_app.hex() if nonces.random_app else '-'}")
    add(f"  randomDevice         {nonces.random_device.hex() if nonces.random_device else '-'}")
    add(f"  nonce source         {nonces.source}")
    if report.signature:
        add(f"  deviceSign           {report.signature.get('status')}"
            f" — {report.signature.get('detail', '')}")
    add("")

    # --- the decision table ----------------------------------------------
    judged = report.adequate_payloads
    add(f"[CTR variants] {len(judged)} judgeable encrypted payload(s)"
        + (f", showing first {max_payloads}" if len(judged) > max_payloads else "")
        + ("" if show_variants else " — winning variant only"))
    if not report.payloads:
        add("  (no opcode=2 payloads)")
    else:
        header = (f"  {'#':>2} {'dir':<8} {'ch':>2} {'seq':>3} {'len':>4} "
                  f"{'key':<10} {'variant':<26} {'ok':<3} {'score':>5}  plaintext")
        add(header)
        add("  " + "-" * (len(header) - 2))
        for payload in report.payloads[:max_payloads]:
            if payload.skipped:
                add(f"  {payload.index:>2} {payload.direction:<8} "
                    f"{payload.channel:>2} {payload.seq:>3} {payload.length:>4} "
                    f"{payload.key_label[:10]:<10} {'(skipped)':<26} {'-':<3} "
                    f"{'-':>5}  {payload.skipped}")
                continue
            if not payload.diagnostics:
                add(f"  {payload.index:>2} {payload.direction:<8} "
                    f"{payload.channel:>2} {payload.seq:>3} {payload.length:>4} "
                    f"{payload.key_label[:10]:<10} {'(no key)':<26} {'-':<3} "
                    f"{'-':>5}")
                continue
            winner = payload.winning
            ordered = sorted(payload.primary_diagnostics,
                             key=lambda d: (d.ok, d.score), reverse=True)
            if not show_variants:
                ordered = ordered[:1]
            primary_key = (payload.primary_diagnostics[0].key_label
                           if payload.primary_diagnostics else "")
            for position, diagnostic in enumerate(ordered):
                if position == 0:
                    prefix = (f"  {payload.index:>2} {payload.direction:<8} "
                              f"{payload.channel:>2} {payload.seq:>3} "
                              f"{payload.length:>4} "
                              f"{diagnostic.key_label[:10]:<10} ")
                else:
                    prefix = " " * (2 + 3 + 9 + 3 + 4 + 5 + 11)
                mark = "yes" if diagnostic.ok else "no"
                if diagnostic.ok:
                    plaintext = diagnostic.plaintext.hex()
                    if len(plaintext) > 42:
                        plaintext = plaintext[:42] + "…"
                else:
                    plaintext = diagnostic.check.reason
                    if len(plaintext) > 66:
                        plaintext = plaintext[:66] + "…"
                suffix = " <-- accepted" if (winner is diagnostic) else ""
                add(f"{prefix}{diagnostic.variant.name:<26} {mark:<3} "
                    f"{diagnostic.score:>5}  {plaintext}{suffix}")
            if winner is not None and winner.key_label != primary_key:
                # Only possible when the direction-appropriate key failed and
                # the other side's key worked: a genuine key mix-up.
                add(" " * (2 + 3 + 9 + 3 + 4 + 5 + 11)
                    + f"(only decrypts with {winner.key_label}, not "
                      f"{primary_key} — check the key/direction mapping)")
    add("")

    # --- health -----------------------------------------------------------
    l1 = report.l1_health
    if l1:
        add("[L1 framing]")
        add(f"  frames            {l1.get('frames', 0)}"
            f"  ({', '.join(f'{k}={v}' for k, v in sorted(l1.get('by_type', {}).items()))})")
        add(f"  CRC pass rate     {l1.get('crc_pass_rate', 0):.1%}"
            f"  ({l1.get('crc_ok', 0)}/{l1.get('frames', 0)} ok,"
            f" {l1.get('crc_bad', 0)} bad)")
        add(f"  sequence gaps     {l1.get('seq_gap_count', 0)}"
            f"   retransmissions {l1.get('retransmissions', 0)}")
        if l1.get("seq_gaps"):
            add("    " + ", ".join(
                f"{g['direction']} expected {g['expected']} got {g['got']}"
                for g in l1["seq_gaps"]))
        add(f"  truncated frames  {l1.get('truncated', 0)}")
        add("")

    frag = report.fragment_health
    if frag:
        add("[fragmentation]")
        add(f"  ATT writes        {frag.get('att_values', 0)}"
            f"  ({frag.get('bytes', 0)} bytes)")
        add(f"  frames spanning >1 ATT write   {frag.get('cross_att_frames', 0)}"
            f"   (max {frag.get('max_writes_per_frame', 0)} writes/frame)")
        add(f"  ATT writes holding >1 frame    "
            f"{frag.get('writes_carrying_multiple_frames', 0)}")
        add("")

    ack = report.ack_health
    if ack:
        add("[ACKs]")
        add(f"  ACK frames        {ack.get('acks', 0)}   NAKs {ack.get('naks', 0)}")
        add(f"  acked / unacked   {ack.get('acked_frames', 0)}"
            f" / {ack.get('unacked_frames', 0)}")
        p50 = ack.get("ack_latency_us_p50")
        pmax = ack.get("ack_latency_us_max")
        if p50 is not None:
            add(f"  ACK latency       p50 {p50 / 1000:.1f} ms"
                f"  max {pmax / 1000:.1f} ms"
                f"  ({ack.get('ack_latency_samples', 0)} sample(s))")
        budget_ms = ack.get("budget_us", _ACK_BATCH_BUDGET_US) / 1000
        add(f"  {budget_ms:.0f} ms budget     "
            f"{'compliant' if ack.get('budget_compliant') else 'VIOLATED'}"
            f"   (ACK later than the budget)")
        if ack.get("budget_violations"):
            add("    late ACKs: " + ", ".join(
                f"{g / 1000:.0f} ms" for g in ack["budget_violations"]))
        if ack.get("unexpected_acks"):
            add(f"  ACKs before their frame  {ack['unexpected_acks']}"
                f"   (timestamp or sequence anomaly)")
        add(f"  no-ACK channels   {ack.get('no_ack_channel_frames', 0)} frame(s)")
        add("")

    hs = report.handshake
    if hs:
        add("[handshake]")
        add(f"  START_REQ / RSP   {hs.get('requests', 0)} / {hs.get('responses', 0)}")
        if hs.get("negotiated_window") is not None:
            add(f"  negotiated window {hs['negotiated_window']}"
                f"   cumulative-ACK threshold {hs.get('cum_ack_threshold')}")
        for warning in hs.get("warnings", []):
            add(f"  ! {warning}")
        add("")

    if report.warnings:
        add("[warnings]")
        for warning in report.warnings:
            add("  ! " + warning)
        add("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Register the ``verify`` sub-command arguments on *parser*."""
    parser.add_argument("path", help="btsnoop or pcap file with HCI traffic")
    parser.add_argument("--token", help="stored auth token, hex",
                        default=None)
    parser.add_argument("--key", action="append", default=[],
                        metavar="HEX",
                        help="explicit 16-byte AES key (repeatable); skips "
                             "the HKDF path")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable JSON instead of text")
    parser.add_argument("--brief", action="store_true",
                        help="only the winning variant per payload")
    parser.add_argument("--min-len", type=int, default=MIN_CIPHERTEXT_LEN,
                        help="shortest ciphertext to judge (default %(default)s)")
    parser.add_argument("--max-payloads", type=int, default=20,
                        help="rows shown in the CTR table (default %(default)s)")


def cmd(args: argparse.Namespace) -> int:
    """``miwear verify`` entry point; returns a process exit code.

    Exit codes: ``0`` the primary hypothesis was confirmed (or there was no
    encrypted traffic to judge), ``1`` the analysis ran but could not
    confirm the hypothesis, ``2`` usage or I/O error.
    """
    path = getattr(args, "path", None)
    if not path:
        print("error: verify requires a capture path", file=sys.stderr)
        return 2

    explicit: list[tuple[str, bytes]] = []
    for index, raw in enumerate(getattr(args, "key", None) or []):
        try:
            explicit.append((f"--key[{index}]", _read_key_argument(raw)))
        except VerifyError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    token = None
    if getattr(args, "token", None):
        try:
            token = parse_token(args.token)
        except VerifyError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    try:
        report = analyse_capture(
            path, token, explicit_keys=explicit,
            min_len=max(1, int(getattr(args, "min_len", MIN_CIPHERTEXT_LEN))))
    except FileNotFoundError as exc:
        print(f"error: file not found: {exc.filename}", file=sys.stderr)
        return 2
    except CaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except VerifyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if getattr(args, "json", False):
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(render_report(
            report, show_variants=not getattr(args, "brief", False),
            max_payloads=max(1, int(getattr(args, "max_payloads", 20)))))

    return 0 if report.verdict in ("confirmed-iv-is-key",
                                   "no-encrypted-traffic") else 1


def build_parser() -> argparse.ArgumentParser:
    """Standalone parser so ``python -m miwear.verify`` works."""
    parser = argparse.ArgumentParser(
        prog="miwear verify",
        description="Verify miwear protocol assumptions against a real "
                    "BLE capture (btsnoop / pcap).")
    add_arguments(parser)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Standalone entry point (``python -m miwear.verify``)."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return cmd(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
