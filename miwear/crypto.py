"""Cryptography used by miwear authentication and payload protection.

Three independent schemes exist in the APK and must not be confused:

V2 handshake (devices with firmware version >= 1.x)
    HKDF-SHA256 derives 40 bytes of session material from the stored auth
    token and the two random nonces exchanged over the protobuf auth flow:
    ``deviceKey || appKey || deviceIV || appIV`` (16/16/4/4).

V2 payload (``opcode == 2`` on the SAR channel)
    ``AES/CTR/NoPadding`` with the *key used as the IV* — see
    ``defpackage.r1``.  No MAC, no counter prefix.

V1 payload (legacy channels)
    ``AES-CCM`` with a 4-byte tag and a 12-byte nonce built from a 4-byte
    per-direction IV and a rolling 16-bit counter (``defpackage.tp5``).
"""

from __future__ import annotations

import hashlib
import hmac
import struct

from . import constants as C

__all__ = [
    "hkdf_sha256",
    "hkdf_salt",
    "derive_v2_keys",
    "sign_hmac",
    "sign_message",
    "app_sign_message",
    "aes_ctr_crypt",
    "decrypt_v2_payload",
    "build_v1_nonce",
    "V2Keys",
]


# ---------------------------------------------------------------------------
# HKDF / HMAC
# ---------------------------------------------------------------------------

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF with SHA-256.

    Argument order matches ``defpackage.sid.f(ikm, salt)`` in the APK.

    RFC 5869 Appendix A.1 test case:

    >>> ikm = bytes.fromhex("0b" * 22)
    >>> salt = bytes.fromhex("000102030405060708090a0b0c")
    >>> info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    >>> hkdf_sha256(ikm, salt, info, 42).hex()[:16]
    '3cb25f25faacd57a'
    """
    if length > 255 * 32:
        raise ValueError("requested key material too long for HKDF-SHA256")
    if not salt:
        salt = b"\x00" * 32

    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = bytearray()
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]),
                         hashlib.sha256).digest()
        okm += block
        counter += 1
    return bytes(okm[:length])


def sign_hmac(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA256, matching ``defpackage.ffc.a(key, message)``."""
    return hmac.new(key, message, hashlib.sha256).digest()


class V2Keys:
    """Session material derived by ``WearAuthV2.k()``."""

    __slots__ = ("device_key", "app_key", "device_iv", "app_iv", "raw")

    def __init__(self, raw: bytes) -> None:
        if len(raw) != C.HKDF_OUTPUT_LEN:
            raise ValueError(f"expected {C.HKDF_OUTPUT_LEN} bytes of key material")
        self.raw = raw
        self.device_key = raw[0:16]
        self.app_key = raw[16:32]
        self.device_iv = raw[32:36]
        self.app_iv = raw[36:40]

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (f"<V2Keys deviceKey={self.device_key.hex()} "
                f"appKey={self.app_key.hex()}>")


def hkdf_salt(random_app: bytes, random_device: bytes) -> bytes:
    """HKDF salt: ``randomApp || randomDevice`` (app first).

    ``WearAuthV2.k()`` lines 161-163 build ``bArr5`` app-first and hand it to
    ``itn.i()`` as the salt.
    """
    return random_app + random_device


def sign_message(random_app: bytes, random_device: bytes,
                 oob: bytes = b"") -> bytes:
    """Message covered by **deviceSign**: ``randomDevice || randomApp [|| oob]``.

    ``WearAuthV2.k()`` lines 179-190. Note this is the *reverse* operand order
    of the HKDF salt, and that ``oob`` (``this.n``) is appended when non-empty.
    Getting this order wrong makes the device-side signature check fail.
    """
    return random_device + random_app + oob


def app_sign_message(random_app: bytes, random_device: bytes,
                     oob: bytes = b"") -> bytes:
    """Message covered by **appSign**: ``randomApp || randomDevice [|| oob]``.

    ``WearAuthV2.k()`` lines 204-205 *overwrite* the first 32 bytes of the
    existing buffer in app-first order.  When ``oob`` is present it sits from
    offset 32 onward, so it survives the overwrite and is still covered.
    """
    return random_app + random_device + oob


def derive_v2_keys(token: bytes, random_app: bytes,
                   random_device: bytes) -> V2Keys:
    """Derive the V2 session keys.

    The APK calls::

        itn.i("miwear-auth", authToken, salt)
          -> sid.f(ikm = authToken, salt = salt)     // PRK
          -> sid.d(info = "miwear-auth", 40)         // expand

    where ``salt = randomApp || randomDevice`` (see :func:`hkdf_salt`).

    Note the unusual argument order: the 32-byte nonce pair is the HKDF
    *salt* and the stored token is the *input keying material*.
    """
    okm = hkdf_sha256(ikm=token, salt=hkdf_salt(random_app, random_device),
                      info=C.HKDF_INFO, length=C.HKDF_OUTPUT_LEN)
    return V2Keys(okm)


# ---------------------------------------------------------------------------
# AES-128 (pure Python, encryption only — enough for CTR keystream)
# ---------------------------------------------------------------------------

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)

_SHIFT_ROWS = tuple((i + 4 * (i % 4)) % 16 for i in range(16))
_MUL2 = tuple(
    ((b << 1) ^ 0x11B) & 0xFF if b & 0x80 else (b << 1) & 0xFF
    for b in range(256)
)


def _mul3(b: int) -> int:
    return _MUL2[b] ^ b


class _AES128:
    """Minimal AES-128 block cipher (encryption direction only)."""

    __slots__ = ("_round_keys",)

    def __init__(self, key: bytes) -> None:
        if len(key) != 16:
            raise ValueError("AES-128 requires a 16-byte key")
        self._round_keys = self._expand(key)

    @staticmethod
    def _expand(key: bytes) -> list[list[int]]:
        words = [list(key[i:i + 4]) for i in range(0, 16, 4)]
        for i in range(4, 44):
            temp = list(words[i - 1])
            if i % 4 == 0:
                temp = temp[1:] + temp[:1]
                temp = [_SBOX[b] for b in temp]
                temp[0] ^= _RCON[i // 4 - 1]
            words.append([words[i - 4][j] ^ temp[j] for j in range(4)])
        return [sum(words[4 * r:4 * r + 4], []) for r in range(11)]

    def encrypt_block(self, block: bytes) -> bytes:
        rk = self._round_keys
        state = [block[i] ^ rk[0][i] for i in range(16)]
        for rnd in range(1, 11):
            state = [_SBOX[b] for b in state]
            state = [state[_SHIFT_ROWS[i]] for i in range(16)]
            if rnd != 10:
                mixed = []
                for col in range(4):
                    a0, a1, a2, a3 = state[4 * col:4 * col + 4]
                    mixed += (
                        _MUL2[a0] ^ _mul3(a1) ^ a2 ^ a3,
                        a0 ^ _MUL2[a1] ^ _mul3(a2) ^ a3,
                        a0 ^ a1 ^ _MUL2[a2] ^ _mul3(a3),
                        _mul3(a0) ^ a1 ^ a2 ^ _MUL2[a3],
                    )
                state = mixed
            state = [state[i] ^ rk[rnd][i] for i in range(16)]
        return bytes(state)


def aes_ctr_crypt(key: bytes, iv: bytes, counter: int = 0, data: bytes = b"",
                  *, counter_little_endian: bool = False) -> bytes:
    """AES-CTR matching Java's ``AES/CTR/NoPadding``.

    SunJCE pads a short IV with zeroes up to 16 bytes and increments only
    the **last four bytes** as a big-endian counter.  Consequently:

    * V2 payloads pass the key itself as IV, so the initial counter is the
      last four bytes of the key.
    * V1 payloads pass ``iv4 || 00000000 || counter4``.

    *counter* shifts the starting block index by that many blocks.
    """
    if len(iv) > 16:
        raise ValueError("IV must be at most 16 bytes")

    block0 = bytearray(iv + b"\x00" * (16 - len(iv)))
    base = struct.unpack(">I", bytes(block0[12:16]))[0]
    cipher = _AES128(key)

    out = bytearray()
    for index, pos in enumerate(range(0, len(data), 16)):
        current = (base + counter + index) & 0xFFFFFFFF
        block = bytearray(block0)
        block[12:16] = struct.pack(
            "<I" if counter_little_endian else ">I", current)
        keystream = cipher.encrypt_block(bytes(block))
        chunk = data[pos:pos + 16]
        out += bytes(a ^ b for a, b in zip(chunk, keystream))
    return bytes(out)


def decrypt_v2_payload(key: bytes, data: bytes) -> bytes:
    """Decrypt a V2 ``opcode == 2`` payload (IV equals the key)."""
    return aes_ctr_crypt(key, key, 0, data)


def build_v1_nonce(iv4: bytes, counter: int) -> bytes:
    """Build the 12-byte CCM nonce ``iv4 || 00000000 || counter4``.

    ``CipherApiCall.encryptData`` allocates 12 bytes and does
    ``put(appIV).putInt(0).putInt(counter)``.  Because the buffer is
    ``order(LITTLE_ENDIAN)``, that final ``putInt`` is **little-endian**.

    The counter itself comes from ``defpackage.tp5.c()`` / ``tp5.d()``, which
    return ``{(low & 0xFF), (low >> 8), (high & 0xFF), (high >> 8)}`` — also
    little-endian.  An earlier revision of this function packed big-endian,
    which byteswapped both halves.
    """
    if len(iv4) != 4:
        raise ValueError("V1 IV must be 4 bytes")
    return iv4 + b"\x00\x00\x00\x00" + struct.pack("<I", counter & 0xFFFFFFFF)


def aes_ccm_decrypt(key: bytes, nonce: bytes, data: bytes,
                    tag_len: int = 4) -> bytes:
    """Decrypt an AES-CCM payload (V1 channels).

    Requires the ``cryptography`` package; raises :class:`RuntimeError` with
    an actionable message when it is unavailable so the pure-stdlib code
    path keeps working for everything else.
    """
    if len(data) < tag_len:
        raise ValueError("ciphertext shorter than the authentication tag")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESCCM
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "AES-CCM support requires the 'cryptography' package: "
            "pip install cryptography"
        ) from exc
    aead = AESCCM(key, tag_length=tag_len)
    return aead.decrypt(nonce, data, None)
