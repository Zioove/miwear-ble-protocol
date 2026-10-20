"""Protocol constants for the Xiaomi Mi Wear (miwear-core) BLE stack.

Every value here is traceable to a class in the decompiled
Xiaomi Health 3.59.1 APK (``com.xiaomi.hm.health``).  The class name is
noted next to each constant so claims can be re-verified.

Layer map
---------
L0  ATT/ GATT   service 0xFE95, write 0x005F, notify 0x005E
L1  SAR frame   8-byte header, magic A5 A5, CRC-16/ARC
L2  Channel     channel u8 | opcode u8 | payload
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# GATT  (defpackage.hx4 -> tvs.a(n) -> "0000%04x-0000-1000-8000-00805f9b34fb")
# ---------------------------------------------------------------------------

BASE_UUID_FMT = "0000{:04x}-0000-1000-8000-00805f9b34fb"


def short_uuid(v: int) -> str:
    """Expand a 16-bit Bluetooth UUID into its full 128-bit form."""
    return BASE_UUID_FMT.format(v)


#: Primary device service (``hx4.a`` = ``tvs.a(0xFE95)``).
SERVICE_UUID = short_uuid(0xFE95)

#: Firmware version characteristic, 3-byte little-endian ``major.minor.build``.
CHAR_VERSION = short_uuid(0x0050)      # hx4.b

#: Legacy (protocol V1) endpoints.
CHAR_PROTO_RX = short_uuid(0x0051)     # hx4.c
CHAR_PROTO_TX = short_uuid(0x0052)     # hx4.d
CHAR_FITNESS = short_uuid(0x0053)      # hx4.e
CHAR_VOICE = short_uuid(0x0054)        # hx4.f
CHAR_MASS = short_uuid(0x0055)         # hx4.g
CHAR_OTA_RX = short_uuid(0x0056)       # hx4.h
CHAR_OTA_TX = short_uuid(0x0057)       # hx4.i
CHAR_SENSOR = short_uuid(0x005A)       # hx4.l

#: SAR (Segmentation And Reassembly) transport endpoints — the ones that matter.
CHAR_SAR_NOTIFY = short_uuid(0x005E)   # hx4.m  device -> app
CHAR_SAR_WRITE = short_uuid(0x005F)    # hx4.n  app -> device

#: Standard CCCD used to enable notifications.
CCCD_UUID = short_uuid(0x2902)

# ---------------------------------------------------------------------------
# L1 SAR frame
# ---------------------------------------------------------------------------

#: Frame magic, ``TransportL1.L1_HEADER_MAGIC`` (``short`` -23131).
L1_MAGIC = 0xA5A5

#: Fixed header size, ``TransportL1.L1_HEADER_SIZE``.
L1_HEADER_SIZE = 8

#: ``L1Packet.DataType``
TYPE_NAK = 0
TYPE_ACK = 1
TYPE_CMD = 2
TYPE_DATA = 3

TYPE_NAMES = {
    TYPE_NAK: "NAK",
    TYPE_ACK: "ACK",
    TYPE_CMD: "CMD",
    TYPE_DATA: "DATA",
}

#: ``CMDPacket.CMD``
CMD_L1START_REQ = 1
CMD_L1START_RSP = 2
CMD_L1STOP_REQ = 3
CMD_L1STOP_RSP = 4

CMD_NAMES = {
    CMD_L1START_REQ: "CMD_L1START_REQ",
    CMD_L1START_RSP: "CMD_L1START_RSP",
    CMD_L1STOP_REQ: "CMD_L1STOP_REQ",
    CMD_L1STOP_RSP: "CMD_L1STOP_RSP",
}

#: ``TransportL1.ConfigType`` — TLV tags inside a CMD payload.
CONFIG_VERSION = 1
CONFIG_MPS = 2
CONFIG_TX_WIN = 3
CONFIG_SEND_TIMEOUT = 4
CONFIG_DEVICE_TYPE = 5
CONFIG_DEVICE_NAME = 6

CONFIG_NAMES = {
    CONFIG_VERSION: "CONFIG_TYPE_VERSION",
    CONFIG_MPS: "CONFIG_TYPE_MPS",
    CONFIG_TX_WIN: "CONFIG_TYPE_TX_WIN",
    CONFIG_SEND_TIMEOUT: "CONFIG_TYPE_SEND_TIMEOUT",
    CONFIG_DEVICE_TYPE: "CONFIG_TYPE_DEVICE_TYPE",
    CONFIG_DEVICE_NAME: "CONFIG_TYPE_DEVICE_NAME",
}

# --- SAR parameters (``TransportL1`` public constants) ---------------------

#: Maximum segment payload advertised by the phone.
SAR_DEFAULT_MPS = 64512
#: Local send window.
SAR_DEFAULT_TX_WIN = 32
#: Per-segment retransmit timeout in milliseconds.
SAR_SEND_TIMEOUT_MS = 10000
#: Delay before flushing a cumulative ACK.
SAR_CUM_ACK_TIMEOUT_MS = 500
#: Hard-coded inflight cap in ``TransportL1.runNext``.
SAR_MAX_INFLIGHT = 32

# ---------------------------------------------------------------------------
# L2 channel multiplexing
# ---------------------------------------------------------------------------

CH_PB = 1
CH_MASS = 2
CH_MASS_VOICE = 3
CH_FILE_SENSOR = 4
CH_FILE_FITNESS = 5
CH_OTA = 6
CH_NETWORK = 7
CH_LYRA = 8
CH_RESEARCH = 9
CH_MULTI_MODAL = 10

CHANNEL_NAMES = {
    CH_PB: "PB",
    CH_MASS: "MASS",
    CH_MASS_VOICE: "MASS_VOICE",
    CH_FILE_SENSOR: "FILE_SENSOR",
    CH_FILE_FITNESS: "FILE_FITNESS",
    CH_OTA: "OTA",
    CH_NETWORK: "NETWORK",
    CH_LYRA: "LYRA",
    CH_RESEARCH: "RESEARCH",
    CH_MULTI_MODAL: "MULTI_MODAL",
}

#: ``L2Packet.OpCode``
OP_WRITE = 1
OP_WRITE_ENC = 2
OP_READ = 3

OPCODE_NAMES = {
    OP_WRITE: "WRITE",
    OP_WRITE_ENC: "WRITE_ENC",
    OP_READ: "READ",
}

#: Channels that never request an ACK (``TransportL1.needSendAck``).
CHANNELS_WITHOUT_ACK = frozenset({CH_NETWORK, CH_MULTI_MODAL})

# ---------------------------------------------------------------------------
# Legacy V1 channel protocol (device firmware reporting version "0.x")
# ---------------------------------------------------------------------------

#: ``com.xiaomi.wearable.spp.b`` — SPP/RFCOMM fallback framing.
V1_FRAME_START = b"\xba\xdc\xfe"
V1_FRAME_END = 0xEF

#: ``defpackage.k0`` control codes.
V1_CTRL_SYNC_ACK_OK = 0
V1_CTRL_CMD_ACK = 1
V1_CTRL_SINGLE_ACK = 2
V1_CTRL_SINGLE_CMD = 3
V1_CTRL_SYNC_ACK_REQ = 5

V1_CTRL_NAMES = {
    V1_CTRL_SYNC_ACK_OK: "SYNC_ACK_OK",
    V1_CTRL_CMD_ACK: "CMD_ACK",
    V1_CTRL_SINGLE_ACK: "SINGLE_ACK",
    V1_CTRL_SINGLE_CMD: "SINGLE_CMD",
    V1_CTRL_SYNC_ACK_REQ: "SYNC_ACK_REQ",
}

#: ``com.xiaomi.wearable.spp.b`` data type byte.
V1_DT_PLAIN = 0
V1_DT_ENCRYPTED = 1
V1_DT_PROTOBUF = 2

V1_DATATYPE_NAMES = {
    V1_DT_PLAIN: "PLAIN",
    V1_DT_ENCRYPTED: "ENCRYPTED",
    V1_DT_PROTOBUF: "PROTOBUF",
}

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

#: HKDF info string, ``itn.i("miwear-auth", ...)``.
HKDF_INFO = b"miwear-auth"

#: Total derived key material: 16+16+4+4.
HKDF_OUTPUT_LEN = 40

#: ``pyt`` command ids used during authentication.
AUTH_CMD_V1_VERIFY = 5
AUTH_CMD_V2_VERIFY = 26
AUTH_CMD_V2_CONFIRM = 27

#: ``va0`` oneof field numbers used by the auth exchange.
VA0_FIELD_USER_ID = 7
VA0_FIELD_VERIFY_REQ = 30      # bb0
VA0_FIELD_VERIFY_RSP = 31      # hb0
VA0_FIELD_CONFIRM_REQ = 32     # ya0
VA0_FIELD_CONFIRM_RSP = 33     # eb0

# ---------------------------------------------------------------------------
# ATT / HCI plumbing
# ---------------------------------------------------------------------------

ATT_OP_WRITE_REQ = 0x12
ATT_OP_WRITE_RSP = 0x13
ATT_OP_PREPARE_WRITE_REQ = 0x16
ATT_OP_EXECUTE_WRITE_REQ = 0x18
ATT_OP_HANDLE_VALUE_NTF = 0x1B
ATT_OP_HANDLE_VALUE_IND = 0x1D
ATT_OP_HANDLE_VALUE_CNF = 0x1E
ATT_OP_WRITE_CMD = 0x52

ATT_OP_NAMES = {
    ATT_OP_WRITE_REQ: "Write Request",
    ATT_OP_WRITE_RSP: "Write Response",
    ATT_OP_PREPARE_WRITE_REQ: "Prepare Write Request",
    ATT_OP_EXECUTE_WRITE_REQ: "Execute Write Request",
    ATT_OP_HANDLE_VALUE_NTF: "Handle Value Notification",
    ATT_OP_HANDLE_VALUE_IND: "Handle Value Indication",
    ATT_OP_HANDLE_VALUE_CNF: "Handle Value Confirmation",
    ATT_OP_WRITE_CMD: "Write Command",
}

#: ATT PDUs that carry an application payload.
ATT_OPS_WITH_VALUE = frozenset({
    ATT_OP_WRITE_REQ,
    ATT_OP_PREPARE_WRITE_REQ,
    ATT_OP_HANDLE_VALUE_NTF,
    ATT_OP_HANDLE_VALUE_IND,
    ATT_OP_WRITE_CMD,
})

L2CAP_CID_ATT = 0x0004
HCI_ACLDATA_PKT = 0x02

#: pcap link types we understand.
DLT_BLUETOOTH_HCI_H4 = 187
DLT_BLUETOOTH_HCI_H4_WITH_PHDR = 201
