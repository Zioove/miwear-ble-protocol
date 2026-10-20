# Protocol reference

Complete field-by-field description of the miwear stack as recovered from
Xiaomi Health **3.59.1**.

Conventions: all multi-byte integers are **little-endian** unless stated
otherwise. Class names refer to the decompiled APK and are the ground truth
for every claim here.

- [L0 — ATT / GATT](#l0--att--gatt)
- [L1 — SAR framing](#l1--sar-framing)
- [L2 — Channel multiplexing](#l2--channel-multiplexing)
- [Authentication](#authentication)
- [Payload encryption](#payload-encryption)
- [Legacy V1 protocol](#legacy-v1-protocol)
- [Application layer](#application-layer)
- [Unresolved](#unresolved)

---

## L0 — ATT / GATT

### Service and characteristics

`defpackage.hx4` builds every UUID through `tvs.a(n)`:

```java
// defpackage/tvs.java
public static UUID a(int i) {
    return UUID.fromString(String.format("0000%04x-0000-1000-8000-00805f9b34fb", i));
}
```

| Constant | Short UUID | Purpose |
|---|---|---|
| `hx4.a` | `0xFE95` | Device service |
| `hx4.b` | `0x0050` | Firmware version, 3 bytes LE → `major.minor.build` |
| `hx4.c` / `hx4.d` | `0x0051` / `0x0052` | Legacy protocol RX / TX |
| `hx4.e` | `0x0053` | Fitness data |
| `hx4.f` | `0x0054` | Voice |
| `hx4.g` | `0x0055` | Mass file transfer |
| `hx4.h` / `hx4.i` | `0x0056` / `0x0057` | OTA RX / TX |
| `hx4.l` | `0x005A` | Sensor capture |
| `hx4.m` | **`0x005E`** | **SAR notify (device → app)** |
| `hx4.n` | **`0x005F`** | **SAR write (app → device)** |

CCCD for notifications is the standard `0x2902`.

### Connection sequence

1. Connect, discover services.
2. Request MTU: `E(23)` sets an optimistic baseline, then `I(512)` calls
   `requestMtu(512)` when the device is not known to be MTU-limited
   (`zxt$h.H0()`, `zxt$h.E1()`).
3. Read characteristic `0x0050`. `BleManagerHandler.u` holds the negotiated MTU;
   `BleChannel.getMTU()` returns `mtu - 3`.
4. Enable notifications on `0x005E`.
5. **Branch on the version string** — `defpackage.d13.newTaskQueue()`:

```java
if (!versionName.startsWith("0")) {
    return new BleTaskQueueV2(this);   // SAR stack, documented below
}
BleTaskQueueV1 q = new BleTaskQueueV1(this);   // legacy, see bottom
q.setPrivateUUID(this.c.getPrivateUUID());
return q;
```

`isSupportLargeMtu()` exempts two models (`mijia.watch.band01`,
`mijia.watch.v1`) on the `hennessy` build from requesting 512.

### Fragmentation

`TransportL0.performSendPacket` splits each frame into `MTU-3` chunks and
writes them **serially**, chaining the next write onto the previous write's
callback:

```java
if (data.length <= mtu)            → single write
else                                → write [0, mtu), then [mtu, 2*mtu), ...
```

Consequence for tooling: an ATT write boundary carries **no** protocol
meaning. Always concatenate the values of one direction in capture order
before parsing.

Writes use the characteristic's default write type, i.e. **Write Request**
(with response), not Write Command.

---

## L1 — SAR framing

Source: `com.xiaomi.wearable.transport.layerl1.L1Packet`,
`...layerl1.TransportL1`, `...layerl0.TransportL0`.

### Frame layout

```
offset  size  field
0       2     magic          always A5 A5
2       1     type | frx     bits 0-3 = type, bit 4 = frx, bits 5-7 reserved
3       1     seq            8-bit, wraps at 256
4       2     dataLength     payload byte count
6       2     crc            CRC-16/ARC over payload; 0 when payload is empty
8       n     payload
```

Header parsing, verbatim from `L1Packet.Header$Companion.get`:

```java
ByteBuffer b = ByteBuffer.wrap(bytes).order(LITTLE_ENDIAN);
short magic = b.getShort();
byte  f     = b.get();
byte  type  = (byte)(f & 15);
byte  frx   = (byte)((f >> 4) & 1);
UByte seq   = UByte(b.get());
int   len   = b.getShort() & 0xFFFF;
short crc   = b.getShort();
```

`L1_HEADER_MAGIC` is declared as `short -23131`, i.e. `0xA5A5`.
`L1_HEADER_SIZE` is `8`.

### Frame types

| Value | Name | Payload |
|---|---|---|
| 0 | `NAK` | empty |
| 1 | `ACK` | empty |
| 2 | `CMD` | `cmd u8` + TLV block |
| 3 | `DATA` | one L2 packet |

### ACK / NAK encoding

`ACKPacket` reuses the frame type field for the ACK/NAK distinction and the
`frx` bit for `force`:

```java
new Header((short)0 /*→ A5A5*/, (byte)(ack ? 1 : 0), (byte)(force ? 1 : 0),
           (byte)0, seq, 0, (short)0, ...)
```

so an ACK is `A5 A5 | 01 | seq | 00 00 | 00 00` and a NAK is the same with
type `00`. `force=1` sets `frx`, which stops two peers from echoing ACKs at
each other.

### CMD payload: TLV configuration

`CMDPacket.createCmdPayload` prepends the command byte, then
`TransportL1.handleConfig` walks `{type u8, len u16 LE, value}` triples.

Commands (`CMDPacket.CMD`):

| Value | Name |
|---|---|
| 1 | `CMD_L1START_REQ` |
| 2 | `CMD_L1START_RSP` |
| 3 | `CMD_L1STOP_REQ` |
| 4 | `CMD_L1STOP_RSP` |

Config types (`TransportL1.ConfigType`):

| Value | Name | Size | Default |
|---|---|---|---|
| 1 | `CONFIG_TYPE_VERSION` | 3 | `major, minor, build` |
| 2 | `CONFIG_TYPE_MPS` | 2 | 64512 |
| 3 | `CONFIG_TYPE_TX_WIN` | 2 | 32 |
| 4 | `CONFIG_TYPE_SEND_TIMEOUT` | 2 | 10000 ms |
| 5 | `CONFIG_TYPE_DEVICE_TYPE` | — | not sent by this app version |
| 6 | `CONFIG_TYPE_DEVICE_NAME` | — | not sent by this app version |

`createCmdData()` produces the fixed 21-byte block:

```hex
01 0300 010000     type 1, len 3, version 1.0.0
02 0200 00FC       type 2, len 2, MPS = 64512
03 0200 2000       type 3, len 2, window = 32
04 0200 1027       type 4, len 2, timeout = 10000
```

The complete START_REQ frame (generated by `miwear build start`):

```hex
A5A5 02 00 1600 1D4D 01 010300 010000 020200 00FC 030200 2000 040200 1027
│    │  │  │    │    │  └ TLV block (21 bytes)
│    │  │  │    │    └ cmd = CMD_L1START_REQ
│    │  │  │    └ CRC-16/ARC = 0x4D1D
│    │  │  └ dataLength = 22
│    │  └ seq = 0
│    └ type = 2 (CMD), frx = 0
└ magic
```

### Connection setup

```
App                                              Device
 │  CMD_L1START_REQ (21-byte TLV)  ──────────────►│
 │◄────────────── CMD_L1START_RSP (21-byte TLV)   │   carries the peer's MPS/window
 │  (cmdExchanged = true; window params now known)│
 │  DATA ...  ────────────────────────────────────►│
 │◄─────────────────── ACK / NAK ─────────────────│
 │  CMD_L1STOP_REQ / RSP                          │
```

- `TransportV2.sendCmd()` arms a **10 s** timer; expiry fires the callback with
  `-4` (`cmd timeout`).
- A peer receiving `CMD_L1START_REQ` replies immediately with `CMD_L1START_RSP`.
- Until `cmdExchanged` is set, `runNext()` refuses to emit anything except
  CMD frames.

### Reliability algorithm

`TransportL1.Control` mirrors a TCP-style sliding window:

| State | Meaning |
|---|---|
| `txBase` | oldest unacknowledged sequence |
| `txNextSeqNum` | next sequence to assign |
| `rxExpectSeqNum` | next expected inbound sequence |
| `remoteMPS` | peer segment size, from `CONFIG_TYPE_MPS` |
| `remoteTXWindow` | peer window, from `CONFIG_TYPE_TX_WIN` |

Rules, all from `TransportL1`:

- **Inflight cap.** `runNext()` stops when
  `(txNextSeqNum - txBase) & 0xFF > 32`.
- **Immediate ACK** (`ackImmediately`) when the L2 channel is `1` (PB) or `8`,
  or when the cumulative counter reaches `2/3 * remoteTXWindow`.
- **Delayed ACK.** Otherwise a 500 ms timer accumulates and flushes one ACK
  covering the highest sequence seen.
- **Out-of-order.** On `seq != rxExpect` with an unsigned difference `< 128`,
  the frame is dropped and a NAK is emitted immediately.
- **NAK handling.** The sender marks everything with `seq >= nack.seq` for
  retransmission.
- **Retransmission.** 10 s without ACK on a DATA frame marks that frame and all
  later in-flight DATA frames for retransmission.
- **No ACK channels.** `7` (NETWORK) and `10` (MULTI_MODAL) never request ACKs
  (`needSendAck` returns false for them).
- **Resynchronisation.** `TransportL0.packetAssemble` scans for `A5 A5`; on CRC
  failure it drops **one byte** and rescans, which is why a CRC-bad frame is
  worth printing rather than discarding silently.
- **Inbound de-dup.** On the receive path, the expected-sequence check makes
  replayed frames harmless.

---

## L2 — Channel multiplexing

Source: `com.xiaomi.wearable.transport.layerl2.L2Packet`,
`...queue.TaskQueueV2`.

```
payload = channel(1) | opcode(1) | data
```

### Channels

| Value | Name | Business type | Notes |
|---|---|---|---|
| 1 | `TRANSPORT_CHANNEL_PB` | 100 / 101 | protobuf business traffic, auth |
| 2 | `TRANSPORT_CHANNEL_MASS` | 104 | large file transfer |
| 3 | `TRANSPORT_CHANNEL_MASS_VOICE` | 103 | voice payloads |
| 4 | `TRANSPORT_CHANNEL_FILE_SENSOR` | 107 | sensor capture files |
| 5 | `TRANSPORT_CHANNEL_FILE_FITNESS` | 102 | sport/health sync |
| 6 | `TRANSPORT_CHANNEL_OTA` | 105 | firmware update |
| 7 | `TRANSPORT_CHANNEL_NETWORK` | 108 | device network proxy |
| 8 | `TRANSPORT_CHANNEL_LYRA` | 112 | always encrypted |
| 9 | `TRANSPORT_CHANNEL_RESEARCH` | 113 | research/debug |
| 10 | `TRANSPORT_CHANNEL_MULTI_MODAL` | 114 | assistant / multi-modal |

`TaskQueueV2.channelToType()` and `getChannel()` are inverse maps, so a channel
number means the same thing in both directions.

### Opcodes

| Value | Name | Meaning |
|---|---|---|
| 1 | `TRANSPORT_OPCODE_WRITE` | plaintext payload |
| 2 | `TRANSPORT_OPCODE_WRITE_ENC` | encrypted payload |
| 3 | `TRANSPORT_OPCODE_READ` | read/response class |

Encryption is decided **purely by the opcode**, not the channel. The send path
additionally forces opcode 2 for business types 101 and 112
(`TaskQueueV2.needEncrypt`).

---

## Authentication

Source: `com.xiaomi.wearable.wear.api.WearAuthV1`, `WearAuthV2`,
`CipherApiCall`; `defpackage.uxt`, `sxt`, `itn`, `r1`, `ffc`, `sid`, `tp5`.

### Dispatch

```
BleConnection.connect()
  └─ new uxt(userId, token, appDeviceId, oob, requestBond, apiCall, flag)
       └─ on connected → getVersion()
            ├─ 0    → WearAuthV1  (system pairing, legacy channel auth)
            └─ > 0  → sxt extends WearAuthV2
```

The **token** is `DeviceInfo.getToken()`, a hex *string*, converted with
`ByteUtil.stringToBytes()` — that is, the hex digits are parsed as bytes, the
string is not UTF-8 encoded.

### Envelope message `pyt`

```proto
message Pyt {
  int32 type = 1;    // always 1
  int32 cmd  = 2;    // command id
  oneof body {
    Va0   va0  = 3;
    ...
    int32 code = 100;  // error code
  }
}
```

`Va0` is a 33-way oneof. Only four arms matter for authentication:

| Field | Type | Setter in the APK |
|---|---|---|
| 7 | string | `va0.y(String)` → V1 user id |
| 30 | `Bb0` | `va0.x(Bb0)` → V2 verify request |
| 31 | `Hb0` | `va0.p()` → device random + signature |
| 32 | `Ya0` | `va0.w(Ya0)` → V2 confirm request |
| 33 | `Eb0` | `va0.o()` → capability bitmap |

Sub-messages (field numbers recovered from each class's `j(CodedOutput…)`):

```proto
message Ya0 { bytes appSign = 1; bytes encAppInfo = 2; }
message Bb0 { bytes randomApp = 1; string appDeviceId = 2; bool hasOob = 3; }
message Hb0 { bytes randomDevice = 1; bytes deviceSign = 2; }
message Eb0 { bool confirm = 1; int32 capability = 2; int32 capabilityV2 = 3;
              int64 capabilityV3 = 4; }
message Jd0 { int32 platform = 1; float sdkInt = 2; string model = 3;
              int32 capability = 4; string region = 5; string reserved6 = 6; }
```

Command ids:

| cmd | Direction | Meaning |
|---|---|---|
| 5 | app → device | V1 verify (user id string in Va0 field 7) |
| 26 | app → device | V2 `sendAppVerify` (randomApp) |
| 27 | app → device | V2 `sendAppConfirm` (appSign + encAppInfo) |

### V2 handshake

```
App                                                        Device
 │ ① Pyt{type=1, cmd=26, va0{bb0{randomApp=16 random bytes,
 │        appDeviceId, hasOob}}}          ─────────────────►│
 │◄── Pyt{... va0{hb0{randomDevice=16 bytes, deviceSign}}}  │
 │                                                          │
 │ ② local derivation (WearAuthV2.k):                       │
 │      msg     = randomApp ‖ randomDevice                  │
 │      okm     = HKDF-SHA256(IKM=token, salt=msg,          │
 │                            info="miwear-auth", 40)       │
 │      deviceKey = okm[0:16]    appKey = okm[16:32]        │
 │      deviceIV  = okm[32:36]   appIV  = okm[36:40]        │
 │      check   HMAC-SHA256(deviceKey, msg) == deviceSign   │
 │      appSign = HMAC-SHA256(appKey, msg)                  │
 │                                                          │
 │ ③ Pyt{type=1, cmd=27, va0{ya0{appSign, encAppInfo}}} ───►│
 │      encAppInfo = CCM(appKey, nonce=appIV‖0‖0,           │
 │                       serialize(Jd0)) + 4-byte tag        │
 │◄── Pyt{... va0{eb0{confirm=true, capability, …}}}        │
 │      → 2004 "device ready"                               │
 └──────────────────────────────────────────────────────────┘
```

Derivation, quoted from `WearAuthV2.k()`:

```java
byte[] okm = itn.i("miwear-auth", this.f13866b /* authToken */, msg);
this.j      = copy(okm,  0, 16);   // _DeviceKey
this.f6425k = copy(okm, 16, 16);   // _AppKey
this.l      = copy(okm, 32,  4);   // _DeviceIV
this.m      = copy(okm, 36,  4);   // _AppIV

byte[] sign = ffc.a(this.j, msg);            // HMAC-SHA256(deviceKey, msg)
if (!ByteUtil.equals(sign, deviceSign)) → "verify device confirm failed"

byte[] appSign = ffc.a(this.f6425k, msg);    // HMAC-SHA256(appKey, msg)
ByteBuffer.allocate(12).order(LITTLE_ENDIAN).put(this.m).putInt(0).putInt(0)
  → itn.d(this.f6425k, nonce, udh.i(jd0))
```

### HKDF parameter order — easy to get backwards

```java
// defpackage/sid.java
public void f(byte[] bArr, byte[] bArr2) {          // f(ikm, salt)
    mac.init(new SecretKeySpec(bArr2 /* salt */, ...));
    PRK = mac.doFinal(bArr /* ikm */);
}
public byte[] d(byte[] bArr, int i) { ... }          // expand(info, length)
```

`itn.i(info, key, data)` therefore means:

| HKDF slot | Value |
|---|---|
| IKM | `authToken` (2nd argument) |
| salt | `msg = randomApp ‖ randomDevice` (3rd argument) |
| info | `"miwear-auth"` |
| length | 40 |

The nonce pair is the salt, not the IKM. Getting these two backwards produces
keys that look plausible but never match a capture.

### V1 handshake

Legacy devices (`version == 0`) pair first, then verify on the legacy channels
`0x51`/`0x52`:

1. `createBond()` — system pairing prompt.
2. Enable notifications.
3. `Pyt{type=1, cmd=5, va0{field7 = userId}}`.
4. Response `va0`:
   - field 3 (`int`) error code; `4` means **device not bound**
   - field 8 (`bool`) `true` means **ready**

---

## Payload encryption

Two different algorithms coexist. Do not mix them up.

### V2 — AES-CTR with the key as IV

Source: `defpackage.r1`, called from `CipherApiCall`.

```java
// r1.a(key, iv, data)  decrypt   /   r1.b(key, iv, data)  encrypt
Cipher.getInstance("AES/CTR/NoPadding");
cipher.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));

// call sites:
r1.a(mDeviceKey, mDeviceKey, input);   // decrypt, IV == key
r1.b(mAppKey,    mAppKey,    input);   // encrypt, IV == key
```

- Key **and** IV are the same 16-byte session key.
- No MAC, no padding, no counter prefix.
- Because the IV is 16 bytes, CTR starts at counter `= key[12:16]`.
- Replay protection comes entirely from the L1 sequence number and business
  fields; there is nothing cryptographic stopping a replay.

A 12-byte IV under SunJCE would be zero-padded and would increment only the
last four bytes big-endian — **this is the V1 CCM path, not V2.** An earlier
revision of this document cited a 12-byte IV for V2 and left the counter byte
order "unverified"; that was a conflation of the two code paths. For V2 the
16-byte `IvParameterSpec` receives the key verbatim, so there is no padding
step at all.

> **How this was settled.** `CipherApiCall.decryptDataV2` is literally
> `return r1.a(bArr, bArr, input);` where `bArr = this.mDeviceKey`, and
> `r1.a(byte[] key, byte[] iv, byte[] data)` does
> `new IvParameterSpec(bArr2)`. The only 12-byte `ByteBuffer` in that class
> belongs to `decryptData`/`encryptData`, i.e. the V1 CCM path.

### V1 — AES-CCM

Source: `CipherApiCall.encryptData` / `decryptData`, `defpackage.itn.g`.

- AES-CCM, **4-byte tag**, **12-byte nonce**.
- nonce = `iv4 ‖ 00 00 00 00 ‖ counter4` (`build_v1_nonce`).
- **The trailing `counter4` is little-endian.** `CipherApiCall.encryptData`
  builds it with `ByteBuffer.allocate(12).order(LITTLE_ENDIAN)`, and `tp5.c()` /
  `tp5.d()` emit `{low & 0xFF, low >> 8, high & 0xFF, high >> 8}`.
- counter from `defpackage.tp5`:
  - app → device: `addAppCount()` increments per packet
  - device → app: first two bytes of the reply update a little-endian u16 with
    wrap detection (`tp5.f()`)
- layout: `ciphertext ‖ tag(4)`, and the send path prefixes a `counter u16 LE`
  when the counter check is enabled.

---

## Legacy V1 protocol

Used when the version characteristic reports `0.x`. Two framings exist.

### SPP / RFCOMM (`com.xiaomi.wearable.spp.b`)

```java
UUID SPP_UUID = "00001101-0000-1000-8000-00805F9B34FB";
// SppChannel.getMTU() == 16394
```

```
BA DC FE | header u16 LE | dataLen u16 LE | opcode u8 | opCodeSN u8
        | dataType u8 | payload (dataLen - 3) | EF
```

| Field | Meaning |
|---|---|
| `header` bits 0-3 | channel type |
| `header` bit 14 | response required |
| `header` bit 15 | flag |
| `dataLen` | payload length **+ 3** (covers opcode, SN, dataType) |
| `dataType` | 0 = plain, 1 = encrypted, 2 = protobuf |

`miwear legacy <hex>` decodes this.

### ATT channel state machine (`defpackage.e84`)

Each UUID owns its own channel with built-in segmentation:

```
sessionId u16 | type u8 | code u8 | [seq u16]* | [payload]
```

Control codes (`defpackage.k0`): `0 SYNC_ACK_OK`, `1 CMD_ACK`,
`2 SINGLE_ACK`, `3 SINGLE_CMD`, `5 SYNC_ACK_REQ`.

Capacity derived from the negotiated MTU:

```java
E() = mtu - 7          // max size for single-packet mode
F() = mtu - 5          // payload per fragment in paged mode
G() = (mtu - 7) / 2    // how many fragments may be requested per retransmit
```

Optional 4-byte CRC-32 trailer when the characteristic enables it
(`g0() == true`).

---

## Application layer

Three encodings coexist above L2.

### protobuf (channels 1, 8, 9, 10)

Payloads come from `protobuf-java-nano`. Classes appear as `defpackage.*`
(`pyt`, `va0`, `eb0`, …) and under `com.xiaomi.hm.health.bt.proto.*`
(`Como`, `Hamburg`, `Lisbon`, `Osprey`, … — codenames per product family).

A schema-less protobuf wire decoder is enough to read these: parse varints and
length-delimited fields, recurse into nested messages, and report field numbers
plus wire types. Field *names* require a `.proto` (see Limitations).

### Mass file transfer (channel 2)

`com.xiaomi.wearable.mass.receiver.MassDataComposer`:

```
total u16 | index u16 | Header(26 bytes) | payload
Header: encrypt u8 | dataType u8 | dataId[16] | dataLength int32
```

- `index == total == 1` → single packet
- `index == 1` → first packet
- `index == total` → last packet
- integrity is checked by comparing the **file name with the uppercase MD5** of
  the received file, not by the trailing `int` field.

### Huami module protocol (Zepp OS watches)

`com.huami.bluetooth.profile.channel.module.a`:

```
moduleId u8 | command u8 | payload
```

`moduleId` is declared by `@d4(id = N)`; `AuthModule` is 128,
`EncryptEchoModule` is 129. Auth commands: `0 QUERY_VERSION`,
`1 START_LOCAL_BINDING`, `2 START_CLOUD_BINDING`, `3 VERIFY_SIGNATURE`,
`4 REQUEST_RANDOM_NUMBER`, `5 AUTHORIZE`, `6 REQUEST_DE_AUTH`,
`7 DE_AUTHORIZE`. Responses always start with `0x10` followed by the command id.

Crypto is **ECDH-P256 + ECDSA**, implemented in `libdevice-encrypt.so`
(JNI exports `Java_com_huami_core_device_feature_encrypt_impl_KeyShareApiImpl_*`,
internal symbols `ecdh_generate_keys`, `ecdh_shared_secret`, `ecdsa_sign`,
`ecdsa_verify`). Deliberately out of scope for this toolkit.

### Sport data (channel 5)

`com.xiaomi.hm.health.bt.profile.gdsp.gps.*` — parsers `SportDetailParser102`,
`205`, `206`, `SportSummary204/207/208`, plus the newer `sport800` family which
uses **BER-TLV** (`ber/BerTag`, `ber/BerLength`).

---

## Unresolved

Things this analysis could not settle, in priority order:

1. ~~**CTR counter endianness on real hardware.**~~ **Settled.** V2 passes the
   16-byte key as the IV, so nothing is padded and the initial counter block is
   the key. The 12-byte IV claim applied to the V1 CCM path. See
   [V2 — AES-CTR with the key as IV](#v2--aes-ctr-with-the-key-as-iv).
   What *is* still unverified is the first-block-index convention SunJCE uses
   for a full-length counter, which only matters for payloads above 2^32 blocks.
2. **`CONFIG_TYPE_DEVICE_TYPE` (5) and `CONFIG_TYPE_DEVICE_NAME` (6)** — the
   enum entries exist but 3.59.1 never sends them; length and encoding unknown.
3. **`CMD_L1STOP_REQ/RSP` semantics** — `sendStopRequest()` is an empty method,
   so whether the link is torn down afterwards is unverified.
4. **Whether the device always encrypts its own traffic.** The send path forces
   opcode 2 only for business types 101 and 112, but the receive path decrypts
   *any* opcode-2 payload.
5. **SPP `dataType` semantics per firmware** — 0/1/2 meaning is inferred from
   `BleTaskQueueV1.dispatchMessage` and may differ on older builds.
