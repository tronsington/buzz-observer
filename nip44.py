"""NIP-44 v2 (ChaCha20 + HMAC-SHA256) for Buzz observer frames.

Ported from ``skills/social-media/buzz-cli/scripts/publish-observer-frame.py``, which
passed step 0a on 2026-11-04 against the official ``nip44.vectors.json`` (35/35
conversation keys, 24/24 padding buckets, 10/10 encrypt/decrypt, 3/3 long messages).

The one detail that silently breaks NIP-44: the conversation key is HKDF **extract only**
(``PRK = HMAC-SHA256("nip44-v2", ECDH_x)``), not a full extract+expand derive. A normal
``HKDF(...).derive()`` also yields 32 plausible bytes, frames encrypt fine, the relay
answers ``OK true``, and the client decrypts nothing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import math
import os

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

CURVE = ec.SECP256K1()
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SALT = b"nip44-v2"


def _xonly_to_point(x_hex: str) -> ec.EllipticCurvePublicKey:
    x = int(x_hex, 16)
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if (y * y) % P != y2:
        raise ValueError("x not on curve")
    if y % 2:  # BIP-340 lifts x-only keys to the even-y point
        y = P - y
    return ec.EllipticCurvePublicNumbers(x, y, CURVE).public_key()


def conversation_key(sec_hex: str, pub_x_hex: str) -> bytes:
    """HKDF-extract only: PRK = HMAC-SHA256(salt="nip44-v2", msg=ECDH_x)."""
    pub = pub_x_hex[2:] if len(pub_x_hex) == 66 else pub_x_hex  # tolerate compressed keys
    shared = ec.derive_private_key(int(sec_hex, 16), CURVE).exchange(ec.ECDH(), _xonly_to_point(pub))
    return hmac.new(SALT, shared, hashlib.sha256).digest()


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def message_keys(conv: bytes, nonce: bytes) -> tuple[bytes, bytes, bytes]:
    k = _expand(conv, nonce, 76)
    return k[:32], k[32:44], k[44:76]


def calc_padded_len(n: int) -> int:
    """Spec chunking: 32-byte chunks up to 256, then next_power/8 chunks.

    Not a fixed bucket list: 33 pads to 64 (not 40), 257 to 320.
    """
    if n <= 32:
        return 32
    chunk = 32 if (1 << (int(math.floor(math.log2(n - 1))) + 1)) <= 256 else (1 << (int(math.floor(math.log2(n - 1))) + 1)) // 8
    return chunk * (int(math.floor((n - 1) / chunk)) + 1)


def _pad(pt: bytes) -> bytes:
    n = len(pt)
    prefix = (b"\x00\x00" + n.to_bytes(4, "big")) if n >= 65536 else n.to_bytes(2, "big")
    return prefix + pt + b"\x00" * (calc_padded_len(n) - n)


def _unpad(padded: bytes) -> bytes:
    n = int.from_bytes(padded[:2], "big")
    plen = 2
    if n == 0:
        n, plen = int.from_bytes(padded[2:6], "big"), 6
    body = padded[plen:plen + n]
    if n == 0 or len(body) != n or len(padded) != plen + calc_padded_len(n):
        raise ValueError("bad padding")
    return body


def _chacha20(key: bytes, nonce12: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.ChaCha20(key, b"\x00\x00\x00\x00" + nonce12), mode=None).encryptor()
    return cipher.update(data) + cipher.finalize()


def encrypt(text: str, conv: bytes, nonce: bytes | None = None) -> str:
    nonce = nonce or os.urandom(32)
    ck, cn, hk = message_keys(conv, nonce)
    ct = _chacha20(ck, cn, _pad(text.encode()))
    mac = hmac.new(hk, nonce + ct, hashlib.sha256).digest()
    return base64.b64encode(b"\x02" + nonce + ct + mac).decode()


def decrypt(payload: str, conv: bytes) -> str:
    raw = base64.b64decode(payload)
    if raw[0] != 2:
        raise ValueError("unknown version")
    nonce, ct, mac = raw[1:33], raw[33:-32], raw[-32:]
    ck, cn, hk = message_keys(conv, nonce)
    if not hmac.compare_digest(hmac.new(hk, nonce + ct, hashlib.sha256).digest(), mac):
        raise ValueError("bad mac")
    return _unpad(_chacha20(ck, cn, ct)).decode()
