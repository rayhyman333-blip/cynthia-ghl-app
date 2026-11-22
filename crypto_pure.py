"""Pure-Python cryptography helpers — standard library only.

Cynthia's house stack is stdlib-only Python (see the Cynthia MCP server
and REST facade), and this wrapper keeps the same rule: no pip installs,
no paid services. Python's standard library has no AES and no Ed25519,
and HighLevel needs both:

  * AES-256-CBC  — decrypting the Custom Page user-context payload
                   (CryptoJS / OpenSSL "Salted__" format; see ghl_sso.py).
  * Ed25519      — verifying HighLevel webhook signatures
                   (the X-GHL-Signature header; see ghl_webhooks.py).

So both are implemented here, compactly and carefully:

  * The AES S-boxes are generated algorithmically (multiplicative
    inverse in GF(2^8) + the FIPS-197 affine transform) instead of
    embedding 512 hand-typed constants that could hide a typo.
  * Ed25519 verification follows RFC 8032 section 5.1.7 using plain
    affine arithmetic with pow() inversions. It is not fast, and it
    does not need to be: it verifies one webhook signature at a time.

Both are covered by known-answer tests in tests/test_crypto.py
(FIPS-197 AES-256 vector, an OpenSSL-generated CBC payload, and the
RFC 8032 Ed25519 test vector).
"""

from __future__ import annotations

import hashlib

# ---------------------------------------------------------------------
# AES (FIPS-197), 128/192/256-bit keys, block encrypt + decrypt.
# ---------------------------------------------------------------------


def _gf_mul(a: int, b: int) -> int:
    """Multiply in GF(2^8) modulo the AES polynomial x^8+x^4+x^3+x+1."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _gf_pow(a: int, e: int) -> int:
    r = 1
    while e:
        if e & 1:
            r = _gf_mul(r, a)
        a = _gf_mul(a, a)
        e >>= 1
    return r


def _rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_sboxes() -> tuple[list[int], list[int]]:
    sbox = [0] * 256
    inv = [0] * 256
    for i in range(256):
        # Multiplicative inverse (0 maps to 0), then the affine transform.
        x = 0 if i == 0 else _gf_pow(i, 254)
        s = x ^ _rotl8(x, 1) ^ _rotl8(x, 2) ^ _rotl8(x, 3) ^ _rotl8(x, 4) ^ 0x63
        sbox[i] = s
        inv[s] = i
    return sbox, inv


_SBOX, _INV_SBOX = _build_sboxes()

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _expand_key(key: bytes) -> list[list[int]]:
    """AES key schedule. Returns the list of round keys (4-word rows)."""
    nk = len(key) // 4
    if nk not in (4, 6, 8):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    nr = nk + 6
    w: list[list[int]] = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = [_SBOX[temp[1]] ^ _RCON[i // nk - 1],
                    _SBOX[temp[2]], _SBOX[temp[3]], _SBOX[temp[0]]]
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
    return [w[4 * r:4 * r + 4] for r in range(nr + 1)]


def _add_round_key(state: list[int], round_key: list[list[int]]) -> None:
    for c in range(4):
        for r in range(4):
            state[4 * c + r] ^= round_key[c][r]


def _shift_rows(state: list[int]) -> list[int]:
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[4 * c + r] = state[4 * ((c + r) % 4) + r]
    return out


def _inv_shift_rows(state: list[int]) -> list[int]:
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[4 * c + r] = state[4 * ((c - r) % 4) + r]
    return out


def _mix_columns(state: list[int]) -> list[int]:
    out = [0] * 16
    for c in range(4):
        a = state[4 * c:4 * c + 4]
        out[4 * c + 0] = _gf_mul(a[0], 2) ^ _gf_mul(a[1], 3) ^ a[2] ^ a[3]
        out[4 * c + 1] = a[0] ^ _gf_mul(a[1], 2) ^ _gf_mul(a[2], 3) ^ a[3]
        out[4 * c + 2] = a[0] ^ a[1] ^ _gf_mul(a[2], 2) ^ _gf_mul(a[3], 3)
        out[4 * c + 3] = _gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ _gf_mul(a[3], 2)
    return out


def _inv_mix_columns(state: list[int]) -> list[int]:
    out = [0] * 16
    for c in range(4):
        a = state[4 * c:4 * c + 4]
        out[4 * c + 0] = (_gf_mul(a[0], 14) ^ _gf_mul(a[1], 11)
                          ^ _gf_mul(a[2], 13) ^ _gf_mul(a[3], 9))
        out[4 * c + 1] = (_gf_mul(a[0], 9) ^ _gf_mul(a[1], 14)
                          ^ _gf_mul(a[2], 11) ^ _gf_mul(a[3], 13))
        out[4 * c + 2] = (_gf_mul(a[0], 13) ^ _gf_mul(a[1], 9)
                          ^ _gf_mul(a[2], 14) ^ _gf_mul(a[3], 11))
        out[4 * c + 3] = (_gf_mul(a[0], 11) ^ _gf_mul(a[1], 13)
                          ^ _gf_mul(a[2], 9) ^ _gf_mul(a[3], 14))
    return out


def aes_encrypt_block(key: bytes, block: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")
    round_keys = _expand_key(key)
    nr = len(round_keys) - 1
    state = list(block)
    _add_round_key(state, round_keys[0])
    for rnd in range(1, nr):
        state = [_SBOX[b] for b in state]
        state = _shift_rows(state)
        state = _mix_columns(state)
        _add_round_key(state, round_keys[rnd])
    state = [_SBOX[b] for b in state]
    state = _shift_rows(state)
    _add_round_key(state, round_keys[nr])
    return bytes(state)


def aes_decrypt_block(key: bytes, block: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")
    round_keys = _expand_key(key)
    nr = len(round_keys) - 1
    state = list(block)
    _add_round_key(state, round_keys[nr])
    for rnd in range(nr - 1, 0, -1):
        state = _inv_shift_rows(state)
        state = [_INV_SBOX[b] for b in state]
        _add_round_key(state, round_keys[rnd])
        state = _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = [_INV_SBOX[b] for b in state]
    _add_round_key(state, round_keys[0])
    return bytes(state)


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-CBC encrypt with PKCS#7 padding."""
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    pad = 16 - (len(data) % 16)
    data = data + bytes([pad]) * pad
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        block = bytes(x ^ y for x, y in zip(data[i:i + 16], prev))
        enc = aes_encrypt_block(key, block)
        out.extend(enc)
        prev = enc
    return bytes(out)


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-CBC decrypt with PKCS#7 unpadding. Raises ValueError on bad
    padding or a non-multiple-of-16 ciphertext."""
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    if not data or len(data) % 16 != 0:
        raise ValueError("ciphertext must be a non-empty multiple of 16 bytes")
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        dec = aes_decrypt_block(key, block)
        out.extend(x ^ y for x, y in zip(dec, prev))
        prev = block
    pad = out[-1]
    if pad < 1 or pad > 16 or out[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid PKCS#7 padding")
    return bytes(out[:-pad])


# ---------------------------------------------------------------------
# Ed25519 signature verification (RFC 8032 section 5.1.7).
# ---------------------------------------------------------------------

_Q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)
_IDENTITY = (0, 1)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = (4 * pow(5, _Q - 2, _Q)) % _Q
_B = (_xrecover(_BY), _BY)


def _edwards_add(p: tuple[int, int], q: tuple[int, int]) -> tuple[int, int]:
    (x1, y1), (x2, y2) = p, q
    denom = pow(1 + _D * x1 * x2 * y1 * y2, _Q - 2, _Q)
    x3 = (x1 * y2 + x2 * y1) * denom % _Q
    denom2 = pow(1 - _D * x1 * x2 * y1 * y2, _Q - 2, _Q)
    y3 = (y1 * y2 + x1 * x2) * denom2 % _Q
    return x3, y3


def _scalarmult(p: tuple[int, int], e: int) -> tuple[int, int]:
    result = _IDENTITY
    addend = p
    while e:
        if e & 1:
            result = _edwards_add(result, addend)
        addend = _edwards_add(addend, addend)
        e >>= 1
    return result


def _decode_point(data: bytes) -> tuple[int, int]:
    if len(data) != 32:
        raise ValueError("encoded point must be 32 bytes")
    bits = int.from_bytes(data, "little")
    y = bits & ((1 << 255) - 1)
    sign = (bits >> 255) & 1
    if y >= _Q:
        raise ValueError("point y out of range")
    x = _xrecover(y)
    if x == 0 and sign == 1:
        raise ValueError("invalid point encoding (x=0 with sign bit set)")
    if (x & 1) != sign:
        x = _Q - x
    return x, y


def _encode_point(p: tuple[int, int]) -> bytes:
    x, y = p
    bits = y | ((x & 1) << 255)
    return bits.to_bytes(32, "little")


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return True iff `signature` is a valid Ed25519 signature of
    `message` under `public_key` (both raw 32-byte forms). Never raises
    on malformed input — malformed simply means not valid."""
    try:
        if len(public_key) != 32 or len(signature) != 64:
            return False
        a_point = _decode_point(public_key)
        r_bytes = signature[:32]
        s = int.from_bytes(signature[32:], "little")
        if s >= _L:
            return False
        r_point = _decode_point(r_bytes)
        h = int.from_bytes(
            hashlib.sha512(r_bytes + public_key + message).digest(),
            "little",
        )
        # Verification equation: [S]B == R + [H(R, A, M)]A
        left = _scalarmult(_B, s)
        right = _edwards_add(r_point, _scalarmult(a_point, h))
        return _encode_point(left) == _encode_point(right)
    except (ValueError, ZeroDivisionError):
        return False


def ed25519_public_key_from_spki_base64(spki_b64: str) -> bytes:
    """Extract the raw 32-byte Ed25519 public key from a base64-encoded
    DER SubjectPublicKeyInfo (the form HighLevel publishes its webhook
    signing key in). The Ed25519 SPKI prefix is fixed (RFC 8410)."""
    import base64

    der = base64.b64decode(spki_b64)
    prefix = bytes.fromhex("302a300506032b6570032100")
    if not der.startswith(prefix) or len(der) != len(prefix) + 32:
        raise ValueError("not an Ed25519 SPKI key")
    return der[len(prefix):]
