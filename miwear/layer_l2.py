"""L2 channel layer: ``channel u8 | opcode u8 | payload``.

The channel byte selects the logical stream (protobuf business traffic,
mass file transfer, OTA, ...) and the opcode says whether the payload is
encrypted.  ``TaskQueueV2`` treats any ``opcode == 2`` as encrypted
regardless of channel.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import constants as C

__all__ = ["L2Packet", "parse_l2", "build_l2", "decode_config_tlv"]


@dataclass
class L2Packet:
    """One decoded L2 packet."""

    channel: int
    opcode: int
    data: bytes

    @property
    def channel_name(self) -> str:
        return C.CHANNEL_NAMES.get(self.channel, f"unknown({self.channel})")

    @property
    def opcode_name(self) -> str:
        return C.OPCODE_NAMES.get(self.opcode, f"unknown({self.opcode})")

    @property
    def is_encrypted(self) -> bool:
        """True when the payload went through ``CipherApiCall``."""
        return self.opcode == C.OP_WRITE_ENC

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (f"<L2Packet ch={self.channel}({self.channel_name}) "
                f"op={self.opcode}({self.opcode_name}) len={len(self.data)}>")


def parse_l2(payload: bytes) -> L2Packet | None:
    """Split a L1 DATA payload into an :class:`L2Packet`.

    Returns ``None`` when the payload is shorter than the 2-byte L2 header.
    """
    if len(payload) < 2:
        return None
    return L2Packet(channel=payload[0], opcode=payload[1], data=payload[2:])


def build_l2(channel: int, opcode: int, data: bytes) -> bytes:
    """Serialise an L2 packet, matching ``L2Packet.getBytes()``."""
    if not 0 <= channel <= 0xFF:
        raise ValueError("channel must fit in one byte")
    if not 0 <= opcode <= 0xFF:
        raise ValueError("opcode must fit in one byte")
    return bytes([channel, opcode]) + data


def decode_config_tlv(payload: bytes) -> dict:
    """Decode a CMD payload: ``[cmd u8]`` followed by ``{type u8, len u16, value}``.

    Returns a dict with ``cmd``, ``cmd_name``, ``config`` (list of entries)
    and an optional ``trailing`` hex string for bytes that did not fit the
    TLV grammar (indicates a malformed or extended frame).
    """
    result: dict = {"cmd": None, "cmd_name": None, "config": []}
    if not payload:
        return result

    result["cmd"] = payload[0]
    result["cmd_name"] = C.CMD_NAMES.get(payload[0], f"unknown({payload[0]})")

    pos = 1
    total = len(payload)
    while pos + 3 <= total:
        cfg_type = payload[pos]
        cfg_len = int.from_bytes(payload[pos + 1:pos + 3], "little")
        value = payload[pos + 3:pos + 3 + cfg_len]
        pos += 3 + cfg_len

        entry = {
            "type": cfg_type,
            "name": C.CONFIG_NAMES.get(cfg_type, f"unknown({cfg_type})"),
            "len": cfg_len,
            "value": value.hex(),
        }
        if cfg_type in (C.CONFIG_MPS, C.CONFIG_TX_WIN, C.CONFIG_SEND_TIMEOUT) \
                and cfg_len == 2:
            entry["u16"] = int.from_bytes(value, "little")
        elif cfg_type == C.CONFIG_VERSION and cfg_len >= 3:
            entry["version"] = ".".join(str(b) for b in value[:3])
        elif cfg_type == C.CONFIG_DEVICE_NAME:
            entry["text"] = value.decode("utf-8", "replace")
        result["config"].append(entry)

    if pos != total:
        result["trailing"] = payload[pos:].hex()
    return result
