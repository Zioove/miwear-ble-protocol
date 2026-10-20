# Contributing

Thanks for helping. The most useful contribution is **a capture**.

## Captures settle open questions

A `btsnoop` covering the handshake answers everything in the README's
Limitations section:

- the real CTR counter byte order
- whether the device encrypts its own traffic
- what `CMD_L1STOP` actually does
- the exact length/encoding of config types 5 and 6

### How to record one

Android (developer options → Enable Bluetooth HCI snoop log), then:

```bash
adb pull /data/misc/bluetooth/logs/btsnoop_hci.log
# or on newer builds
adb bugreport && unzip -p bugreport-*.zip FS/data/misc/bluetooth/logs/btsnoop_hci.log
```

iOS has no equivalent; use a nRF Sniffer or an Android phone against the same
device.

### Before attaching

- Redact MAC addresses. They appear in HCI connection events and in every
  `AttValue` line printed by `--verbose`.
- **Never include a session token, `randomApp`/`randomDevice` pair together
  with a decrypted payload from a device you still use.** That triple is enough
  to derive the session keys.
- Trim to the window of interest if the log is large.

A useful minimum: from connect through the first `CMD_L1START_RSP`, plus a few
hundred bytes of channel 1 traffic.

## Bug reports

For a decoding bug, include:

```
miwear --version
python --version
# the exact hex that failed
# what you expected
# the full miwear output
```

Please say whether the failing frame came from a real capture or was
hand-constructed — it changes the diagnosis completely.

## Code changes

- Keep `miwear selftest` green. Add a check for anything new you rely on.
- Prefer anchoring new claims to a published test vector. If there is no
  vector, say so explicitly in the docstring.
- Do not add runtime dependencies to the core package. Optional features go
  behind an extra (`[ccm]`).
- Every constant that comes from the APK should carry its originating class
  name as a comment.

```bash
python -m pytest          # unit tests
python -m miwear selftest # protocol checks
```

## Documentation changes

`docs/PROTOCOL.md` is the reference. If you learn a field's meaning, add it
with the evidence (which class, which method) rather than as a bare claim.
Move items out of the "Unresolved" section only when you have evidence.

## Scope

In scope: the `com.xiaomi.wearable.*` transport stack, its auth, and the
application encodings riding on it.

Out of scope by design: the Huami/Zepp module protocol, Mi Home / IoT BLE,
and anything requiring firmware extraction.

## Licensing of contributions

By submitting a pull request you agree to license your contribution under the
project's MIT license.
