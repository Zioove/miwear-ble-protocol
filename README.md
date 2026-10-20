# miwear — Xiaomi Mi Wear BLE protocol

Reverse-engineered Bluetooth Low Energy protocol used by the **Xiaomi Health
app** (`com.xiaomi.hm.health`, analyzed version **3.59.1**) to talk to Mi Band
and Mi Watch wearables.

[中文文档](README.zh-CN.md) · [Protocol reference](docs/PROTOCOL.md) · [Layer diagrams](docs/LAYERS.md) · [Extraction notes](docs/EXTRACTION.md)

> **Status:** the framing, checksums and key derivation are fully recovered and
> verified against published test vectors. The application layer above L2 is
> protobuf and *structurally* decodable but has no `.proto` attached — see
> [Limitations](#limitations).

> **Scope of this repository.** This is the **full toolkit**: the wire-format
> reference, the extraction notes, and the reference Python implementation that
> produced the hexdumps below. Everything runs on the standard library alone —
> there is nothing to install to decode a frame.

---

## Why this exists

Everything here was recovered by static analysis of the APK: no device
firmware, no vendor SDK, no vendor documentation was used. The goal is a
toolkit that turns a raw `btsnoop` capture into readable frames, and that
documents the wire format well enough for anyone to re-implement it.

Nothing in this repository contains proprietary source code, keys, or
firmware. It ships only protocol facts and clean-room Python.

---

## The protocol in one picture

```
                                     ┌──────────── ATT / GATT ────────────┐
  service 0xFE95                     │ write 0x005F   notify 0x005E       │
                                     │ MTU-3 bytes per write, must stitch │
                                     └────────────────┬───────────────────┘
                                                      │
                              ┌───────────────────────▼────────────────────────┐
                              │ L1  SAR frame (8-byte header, CRC-16/ARC)      │
                              │  A5 A5 │ type|frx │ seq │ len │ crc │ payload  │
                              │  sliding window 32, cumulative ACK, 10 s retry │
                              └───────────────────────┬────────────────────────┘
                                                      │
                              ┌───────────────────────▼────────────────────────┐
                              │ L2  channel(1) │ opcode(1) │ payload           │
                              │  ch 1 = protobuf business traffic              │
                              │  opcode 2 = encrypted (AES-CTR, IV = key)      │
                              └───────────────────────┬────────────────────────┘
                                                      │
                              ┌───────────────────────▼────────────────────────┐
                              │ application: protobuf (nano), mass files, OTA  │
                              └────────────────────────────────────────────────┘
```

Full field tables: [docs/PROTOCOL.md](docs/PROTOCOL.md).

---

## How to use it

Install it, or just run it from a checkout — the core package has no
dependencies:

```bash
python -m miwear selftest                     # 40 protocol checks, no data needed
python -m miwear decode <hex>                 # decode SAR frames from a hex string
python -m miwear capture btsnoop_hci.log      # peel HCI -> ATT -> SAR -> L2
python -m miwear keys --token <hex> --app <hex> --dev <hex>
python -m miwear decrypt --key <hex> <payload-hex>
python -m miwear verify   btsnoop_hci.log --token <hex>   # check a real capture
python -m miwear protogen session.hex -o band.proto       # infer a .proto
python -m miwear live scan                                # talk to a real band
```

`pip install -e .` puts a `miwear` command on your PATH. Optional extras:
`[ccm]` adds AES-CCM for legacy V1 payloads, `[live]` adds `bleak` for talking
to real hardware (`miwear live` / `miwear-live`).

`verify` is the one to reach for when you finally have a capture: it replays
the handshake, decrypts with the derived keys, and tells you whether the
documented behaviour actually matches the traffic — see
[Verifying a capture](#verifying-a-capture).

Read the documentation in this order:

| Your goal | Read |
|---|---|
| Understand the three layers at a glance | the diagram above |
| **Implement** the protocol yourself | [docs/PROTOCOL.md](docs/PROTOCOL.md) — every field, enum and state transition |
| Walk through real frames | [docs/LAYERS.md](docs/LAYERS.md) — layer-by-layer with hexdumps |
| Know how these conclusions were reached | [docs/EXTRACTION.md](docs/EXTRACTION.md) — decompilation steps and where each fact was found |

Get your own capture to compare against:

```bash
# Android: Developer options → Enable Bluetooth HCI snoop log → pair once
adb bugreport bugreport.zip
unzip -o bugreport.zip 'FS/data/misc/bluetooth/logs/*' -d hci
```

The `btsnoop` file holds the full HCI layer. You have to peel L2CAP → ATT → SAR
yourself. **The stitching step is not optional**: one SAR frame can span
several ATT writes, and one write can hold several frames.

---

## What a frame looks like

This frame comes from a real connection setup. You can decode it by hand
against [docs/PROTOCOL.md](docs/PROTOCOL.md#l1--sar-framing):

```
a5a5020016001d4d 0101030001000002020000fc03020020000402001027
└──┬──┘│││└─┬─┘└┬┘ └──────────────────┬───────────────────────┘
 magic │││ len  crc                    payload
       ││└ seq                      CMD_L1START_REQ
       │└ opcode/type
       └ frx
```

The configuration TLV it carries:

| Field | Value | Meaning |
|---|---|---|
| `CONFIG_TYPE_VERSION` | `010000` | 1.0.0 |
| `CONFIG_TYPE_MPS` | `00fc` | 64512 |
| `CONFIG_TYPE_TX_WIN` | `2000` | 32 (sliding window) |
| `CONFIG_TYPE_SEND_TIMEOUT` | `1027` | 10000 ms (retransmit timeout) |

More samples in [docs/LAYERS.md](docs/LAYERS.md).

---

## Verifying a capture

Every claim in these docs came from static analysis. `miwear verify` is how you
check them against traffic:

```bash
miwear verify btsnoop_hci.log --token <token-hex>
miwear verify btsnoop_hci.log --key <session-key-hex>    # if you already have it
miwear verify btsnoop_hci.log --token <hex> --json       # for scripting
```

It stitches ATT values into L1 frames, walks the V2 handshake to recover
`randomApp`/`randomDevice`, derives the session keys from the token, and then
decrypts the first `opcode == 2` payload each way it plausibly could — reporting
which one yields valid protobuf. It also reports CRC pass rate, sequence gaps,
cross-write fragmentation and ACK timing.

By default the expected answer is `IV = key` (the documented behaviour); the
other variants stay in the table as diagnostics, so a mismatch tells you *that*
the firmware differs rather than just that decryption failed.

---

## What is verified and what is not

Verified against external published vectors:

| Component | Vector |
|---|---|
| CRC-16/ARC | check value `0xBB3D` |
| CRC-32/IEEE | check value `0xCBF43926` |
| AES-128 block | FIPS-197 Appendix C.1 |
| AES-CTR | NIST SP 800-38A F.5.1 |
| HKDF-SHA256 | RFC 5869 Appendix A.1 |
| HMAC-SHA256 | RFC 4231 case 1 |
| START_REQ frame bytes | matches `CMDPacket.createCmdData()` exactly |
| Frame parser | round-trip, corruption, resynchronisation |

## Limitations

Be aware of these before relying on the output:

1. **No `.proto` files.** Application payloads decode structurally (field
   numbers and wire types), not semantically. Field *meanings* are documented
   in [docs/PROTOCOL.md](docs/PROTOCOL.md) where they were recoverable from
   decompiled code.
2. **The V2 IV is the session key itself — settled from the code.** `CipherApiCall`
   calls `r1.a(mDeviceKey, mDeviceKey, input)` and `defpackage.r1` feeds the
   second argument straight into `new IvParameterSpec(iv)`. Key and IV are the
   same 16 bytes, so nothing is padded and the initial counter block *is* the
   key. The 12-byte `ByteBuffer` you will find in `CipherApiCall` belongs to the
   **V1 CCM** path (`decryptData`/`encryptData`), not to V2; an earlier revision
   of this document conflated the two. See [docs/PROTOCOL.md](docs/PROTOCOL.md#v2--aes-ctr-with-the-key-as-iv).
   The only residual question is how SunJCE increments the counter, and that
   cannot differ from a plain big-endian increment for any payload that stays
   under 2^32 blocks.
3. **Two generations coexist.** Devices reporting firmware `0.x` use a
   completely different channel protocol (see `miwear/legacy_v1.py`). Check the
   version characteristic `0x0050` before assuming SAR framing.
4. **Huawei/Zepp-branded watches** on the same app use a separate Huami module
   protocol with ECDH-P256 + ECDSA, deliberately out of scope here.
5. **Only static analysis.** Nothing was confirmed against a real handshake.
   Contributions with captures are very welcome.

---

## Repository layout

```
miwear-ble-protocol/
├── miwear/              reference implementation (standard library only)
│   ├── constants.py     UUIDs, enums, magic numbers
│   ├── crc.py           CRC-16/ARC, CRC-32
│   ├── layer_l1.py      SAR framing, CMD/TLV, ACK/NAK
│   ├── layer_l2.py      channel | opcode demultiplexing
│   ├── crypto.py        HKDF, HMAC, AES-CTR, V1 nonce layout
│   ├── protobuf.py      structural protobuf wire decoder
│   ├── capture.py       btsnoop / pcap -> ATT values
│   ├── session.py       whole-capture pipeline
│   ├── legacy_v1.py     BA DC FE … EF legacy framing
│   └── cli.py           the `miwear` command
├── tests/               unit tests (`python tests/run_tests.py`)
├── examples/            generated sample frames, doubling as a smoke test
├── docs/
│   ├── PROTOCOL.md      complete field-by-field reference
│   ├── LAYERS.md        layer-by-layer walkthrough with hexdumps
│   └── EXTRACTION.md    how the analysis was done, reproducibility
├── CONTRIBUTING.md
└── LICENSE
```

---

## Contributing

Captures are the most valuable contribution — a `btsnoop` around a handshake
plus the fw version would settle every open question in Limitations. Please
redact MAC addresses and tokens before attaching.

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Legal

Independent interoperability research on a protocol you are entitled to
observe on your own hardware. Provided for education, debugging and
interoperability. Not affiliated with or endorsed by Xiaomi.

Xiaomi, Mi Band and Mi Watch are trademarks of their respective owners.
Licensed under [MIT](LICENSE).
