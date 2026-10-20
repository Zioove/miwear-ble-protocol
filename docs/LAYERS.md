# Layer walkthrough

A byte-level tour of one connection, from the first ATT write to the protobuf
payload. Every hex dump here was produced by the reference implementation while
validating the protocol, so you can check your own decoder against it byte for
byte.

Where you see a `miwear …` command, it names the reference tool used to
generate that output — that tool is not part of this documentation release.
Every result it printed is inlined below, so nothing here depends on running it.

- [0. Setup](#0-setup)
- [1. Handshake](#1-handshake)
- [2. Sending data](#2-sending-data)
- [3. Acknowledging](#3-acknowledging)
- [4. Reading a payload](#4-reading-a-payload)
- [5. Where the encryption sits](#5-where-the-encryption-sits)

---

## 0. Setup

```
App                                              Device
 │  connect + discover                             │
 │◄──────────────────── version 0x50 ──────────────│   e.g. 01 00 00 → "1.0.0"
 │  requestMtu(512)  ──────────────────────────────►│   → effective MTU 247
 │  enable notify 0x005E                           │
 │                                                 │
 │  mtu 247 ⇒ channel MTU = 244 bytes per write    │   BleChannel.getMTU() = mtu - 3
```

The version string decides everything downstream:

```java
// defpackage/d13.newTaskQueue()
versionName.startsWith("0") ? new BleTaskQueueV1(this)   // legacy
                            : new BleTaskQueueV2(this)   // SAR, this document
```

Read characteristic `0x0050` first: its value tells you which of the two
protocols the device speaks. Decode it as three bytes — `01 00 00` means
`1.0.0` and SAR framing; anything starting with `0` means legacy.

---

## 1. Handshake

The app opens the session by telling the device its segmentation parameters.
`CMDPacket.createCmdData()` is a fixed 21-byte TLV block:

```hex
01 0300 010000     CONFIG_TYPE_VERSION   len 3   "1.0.0"
02 0200 00FC       CONFIG_TYPE_MPS       len 2   64512
03 0200 2000       CONFIG_TYPE_TX_WIN    len 2   32
04 0200 1027       CONFIG_TYPE_SEND_TIMEOUT len 2 10000 ms
```

Wrapped in a CMD frame:

```hex
A5A5 02 00 1600 1D4D 01 010300 010000 020200 00FC 030200 2000 040200 1027
└──┬─┘ │  │  └─┬─┘ └─┬─┘ │  └───────────────┬──────────────────────────┘
  mag  │  │   len   crc  │                  └ 21-byte TLV block
       │  │             └ cmd = 1 (CMD_L1START_REQ)
       │  └ seq = 0
       └ type 2 (CMD) | frx 0

  offset 0   1   2   3   4   5   6   7   8 ...
```

Verification:

```bash
miwear build start
# CMD_L1START_REQ config TLV (21 bytes)
# 01030001000002020000fc03020020000402001027
# full frame (30 bytes)
# a5a5020016001d4d0101030001000002020000fc03020020000402001027
```

The device answers with its own `CMD_L1START_RSP` carrying **its** MPS and
window. From that moment the sender's window is `min(local, remote)` and the
cumulative-ACK threshold is `2/3 × remoteWindow`.

The RSP has the same layout with `frx = 1` and type `5`; only the TLV values
change. Timing: the app arms a **10 s** timer (`TransportV2.sendCmd`) and
reports `-4 cmd timeout` if the RSP never arrives.

### Why `frx` matters

`frx` (bit 4 of byte 2) marks an ACK that was generated in response to a peer
ACK — a loop-breaker. It is also reused by `ACKPacket` as the `force` flag.
For DATA frames it is always 0.

---

## 2. Sending data

Business traffic goes out as a DATA frame whose payload is an L2 packet:

```
DATA payload = channel(1) | opcode(1) | application data
```

Example — a V1 auth verify carrying the user id string:

```hex
A5A5 03 00 1600 000C 01 01 08 01 10 05 3A 0E 7573657269642D6578616D706C65
│    │  │  │    │    │  │  └──────────────┬──────────────────────────────┘
│    │  │  │    │    │  │                 └ protobuf: field7 = "userid-example"
│    │  │  │    │    │  └ opcode 1 = WRITE (plaintext)
│    │  │  │    │    └ channel 1 = PB
│    │  │  │    └ CRC-16/ARC = 0x0C00
│    │  │  └ dataLength = 22
│    │  └ seq = 0
│    └ type 3 (DATA)
└ magic

protobuf inside:
  08 01        field 1, varint,     1     (pyt.type)
  10 05        field 2, varint,     5     (pyt.cmd = verify)
  3A 0E ...    field 7, bytes, len 14    (va0.userId)
```

The L2 header in that frame reads `01 01`: channel 1 (PB), opcode 1 (WRITE,
plaintext). Everything after it is the protobuf above.

### Fragmenting

If the frame exceeds `MTU-3`, `TransportL0.performSendPacket` writes it in
chunks:

```
frame = [A5 A5 03 00 16 00 00 0C  01 01 08 01 10 05 3A 0E ...]   (30 bytes)
MTU-3 = 244                                                       → one write

If MTU-3 were 16, the receiver would see:
  write 1: A5 A5 03 00 16 00 00 0C 01 01 08 01 10 05 3A 0E
  write 2: 75 73 65 72 69 64 2D 65 78 61 6D 70 6C 65
```

Neither write starts with `A5 A5`, so **parsing per ATT value fails**. Stitch
first — walk the ACL fragments for the handle carrying `0x005E`/`0x005F`, then
concatenate their values in order before looking for the magic.

---

## 3. Acknowledging

A DATA frame with `waitAck` set stays in the queue until an ACK for its
sequence arrives.

```
A5A5 01 05 0000 0000
│    │  │  │    └ payload empty, CRC 0
│    │  │  └ dataLength 0
│    │  └ seq 5
│    └ type 1 (ACK), frx 0
└ magic
```

A NAK is the same frame with type `0`. It tells the sender "everything from
sequence *n* onwards must be resent".

Rules that shape captures:

| Situation | Wire behaviour |
|---|---|
| PB (ch1) / LYRA (ch8) data | immediate ACK per frame |
| other channels | cumulative ACK every 500 ms |
| out-of-order arrival | immediate NAK, frame dropped |
| ACK lost | 10 s retransmit of that frame and all later DATA |
| NETWORK (ch7) / MULTI_MODAL (ch10) | no ACK at all |

An ACK storm is normal during a large sync — expect roughly one ACK per
1-3 DATA frames on channel 5.

---

## 4. Reading a payload

Once you have a DATA frame, the L2 header tells you what to do:

```
channel 1 → protobuf business message (this section)
channel 2 → mass file transfer header (see PROTOCOL.md)
channel 6 → OTA image chunk
opcode  2 → decrypt first, then look at channel
```

For `opcode == 1` on channel 1, run a protobuf wire decoder over the bytes:

```json
[
  { "field": 1, "wire": "varint", "value": 1 },
  { "field": 2, "wire": "varint", "value": 5 },
  { "field": 7, "wire": "bytes", "len": 14, "text": "userid-example" }
]
```

That is what the bytes `08 01 10 05 3a 0e 7573657269642d6578616d706c65` decode
to: field 1 varint, field 2 varint, field 7 length-delimited ASCII.

Without a `.proto`, this is as far as pure tooling goes: you get field numbers.
`docs/PROTOCOL.md` maps the ones that could be recovered from the APK
(`pyt` envelope, auth messages, capability bitmap).

---

## 5. Where the encryption sits

Encryption is a property of the **L2 opcode**, applied after the frame is
built and before it is fragmented:

```
plaintext protobuf
      │
      ▼  AES-CTR, IV = key           ← CipherApiCall / defpackage.r1
encrypted bytes
      │
      ▼  L2 = channel | 0x02 | ciphertext
      │
      ▼  L1 frame  A5A5 | 03 | seq | len | crc | [01 02 <ciphertext>]
      │
      ▼  ATT writes of MTU-3 bytes
```

So to read an encrypted payload you need the L2 bytes and the session key —
the frame headers stay in the clear, which is why you can still read frame
types, sequence numbers and channel ids for encrypted traffic.

The key comes from the handshake in `docs/PROTOCOL.md`: run HKDF-SHA256 over
the stored token with the two random nonces as salt, and take 40 bytes —
`deviceKey(16) | appKey(16) | deviceIV(4) | appIV(4)`.

Note the order: the two random nonces are the HKDF **salt**, the stored token
is the **IKM**.
