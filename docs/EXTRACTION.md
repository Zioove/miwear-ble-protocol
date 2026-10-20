# How this was extracted

Reproducible notes on how the protocol was recovered, so the result can be
audited and repeated against another app version.

## Sample

| Item | Value |
|---|---|
| File | `3.59.1_20260906202621_mihealth.apk` |
| Package | `com.xiaomi.hm.health` |
| Version | 3.59.1 |
| Size | 143.6 MB |
| DEX files | 13 (`classes.dex` … `classes13.dex`) |
| ABIs | `arm64-v8a`, `armeabi-v7a` |

## Tooling

| Tool | Version | Role |
|---|---|---|
| jadx | 1.5.6 | DEX → Java |
| JDK | 26.0.2.1 | jadx runtime |
| IG5 / Ghidra | 12.1.4 (bundled) | native library analysis |

## Step 1 — decompile

```powershell
$env:JAVA_HOME = 'D:\tool\jdk-26.0.2.1'
java -Xmx8g -cp jadx-1.5.6-all.jar jadx.cli.JadxCLI `
     -d out --no-res --log-level warn -j 8 mihealth.apk
```

Result: **49,775** Java files. 397 methods failed to decompile (mostly Kotlin
coroutine `invokeSuspend` bodies); none of them were load-bearing for this
protocol.

## Step 2 — find the transport

The APK contains several unrelated Bluetooth stacks. The wearable one is
identifiable by package layout:

| Package | Purpose |
|---|---|
| `com.xiaomi.wearable.*` | **the protocol in this repo** |
| `com.xiaomi.smarthome.*` | Mi Home / IoT devices (RC4, `BLECipher`) |
| `no.nordicsemi.android.ble` | generic BLE library used as the GATT engine |
| `com.huami.*` | Zepp OS watch module protocol (out of scope) |

Search anchors that led straight to it:

```
onCharacteristicChanged
new BleChannel
0000fe
L1Packet
```

`defpackage.hx4` turned out to be the UUID table:

```java
public static final UUID a = tvs.a(65173);   // 0xFE95
public static final UUID m = tvs.a(94);      // 0x5E
public static final UUID n = tvs.a(95);      // 0x5F
```

with `tvs.a()` being `String.format("0000%04x-0000-1000-8000-00805f9b34fb", i)`.
One helper, all 14 UUIDs resolved.

## Step 3 — the layer stack

Reading order that worked:

1. `com.xiaomi.wearable.transport.layerl0.BleChannel` — GATT plumbing, `mtu - 3`.
2. `...layerl1.L1Packet` — the 8-byte header, magic `-23131` = `0xA5A5`.
3. `...layerl1.TransportL1` — windowing, ACK logic, all constants.
4. `...layerl0.TransportL0` — fragmentation and resynchronisation.
5. `...layerl2.L2Packet` — channel and opcode enums.
6. `...queue.TaskQueueV2` — channel↔business-type map, encryption hook.

Cross-checking the magic: `L1_HEADER_MAGIC = -23131` as a `short` is
`0xA5A5`, which the frame parser compares against the first two bytes.

## Step 4 — checksum identification

`CRCUtil.TABLE_16` starts `{0, 49345, 49537, 320, 49921, 960, …}`.
`49345 = 0xC0C1`, `49537 = 0xC181` — the classic reflected CRC-16/ARC table.
Confirmed by computing the check value for `"123456789"` → `0xBB3D`.

## Step 5 — authentication

Entry point was `com.xiaomi.wearable.connection.BleConnection.connect()`, which
constructs the auth wrapper:

```java
new uxt(userId, token, appDeviceId, oob, requestBond, (d13) apiCall, getMFrom())
```

Following `uxt` → `sxt` → `WearAuthV2` produced the message flow, and
`WearAuthV2.k()` produced the derivation. The **parameter order trap** was
caught by reading `defpackage.sid.f(byte[] ikm, byte[] salt)` rather than
trusting the call site's variable names:

```java
sidVarE.f(bArr, bArr2);   // f(ikm = authToken, salt = msg)
```

An earlier draft had salt and IKM swapped; the RFC 5869 test vector in
`selftest` does not catch that (it only validates HKDF itself), so the fix was
verified by re-reading `sid.java`. This is documented in
`docs/PROTOCOL.md#hkdf-parameter-order--easy-to-get-backwards` so the next
person does not repeat it.

## Step 6 — encryption

Two call sites, two algorithms:

```java
// V2 — defpackage/r1.java
Cipher.getInstance("AES/CTR/NoPadding");
// called as r1.a(mDeviceKey, mDeviceKey, input)

// V1 — defpackage/itn.java
CCMBlockCipher via dl3/h1/wdf, 4-byte tag, 12-byte nonce
```

The V2 call passing the key twice looked like a bug until the signature was
checked: `r1.a(byte[] key, byte[] iv, byte[] data)`.

## Step 7 — native libraries

`libdevice-encrypt.so` (214 KB, arm64) exports only four JNI methods but
carries named internal symbols, which made identification trivial:

```
ecdh_generate_keys      ecdh_shared_secret
ecdsa_sign              ecdsa_verify
```

Those belong to the Huami/Zepp path, not to the miwear V2 path — the latter is
pure Java. Recorded here so nobody assumes the .so holds the miwear keys.

Other libraries checked and found irrelevant to this protocol:
`libdevice-compress.so` (zip), `libcentralclient.so` (BLE central client
plumbing), `libxmd.so`.

## Step 8 — verification

Because no device was available, correctness was anchored to published vectors
rather than to a capture:

| Claim | Evidence |
|---|---|
| CRC-16/ARC | check value `0xBB3D` |
| AES-128 | FIPS-197 C.1 |
| AES-CTR | NIST SP 800-38A F.5.1 |
| HKDF | RFC 5869 A.1 |
| HMAC | RFC 4231 case 1 |
| START_REQ bytes | equal to `CMDPacket.createCmdData()` output |

Each of these can be checked with any crypto library: the point is that the
algorithm choices are not guesses, they reproduce standard check values.

The one thing vectors cannot confirm is the CTR counter byte order as the
device actually implements it — see Limitations in the README.

## Reproducing against a newer version

1. Re-run step 1.
2. Diff `defpackage/hx4.java` — UUIDs are stable but the obfuscation letters
   are not, so search for the numeric literals (`65173`, `94`, `95`).
3. Diff `TransportL1` constants (`L1_HEADER_MAGIC`, `SAR_DEFAULT_*`).
4. Re-read `WearAuthV2.k()` and `itn.i()` — the derivation is the part most
   likely to change between major versions.
5. Grep for `0xA5A5` / `-23131` to confirm the frame magic survived.
