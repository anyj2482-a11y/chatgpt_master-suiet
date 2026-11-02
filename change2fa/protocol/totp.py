"""RFC 6238 TOTP (HMAC-SHA1)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time


def generate_secret(nbytes: int = 20) -> str:
    raw = os.urandom(nbytes)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def totp_remaining(*, for_time: float | None = None, period: int = 30) -> float:
    now = time.time() if for_time is None else for_time
    return period - (now % period)


def totp(secret_b32: str, *, for_time: int | None = None, digits: int = 6, period: int = 30) -> str:
    key = _decode_secret(secret_b32)
    counter = int((for_time if for_time is not None else time.time()) // period)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    code = code_int % (10**digits)
    return str(code).zfill(digits)


def _decode_secret(secret_b32: str) -> bytes:
    s = secret_b32.strip().replace(" ", "").upper()
    pad = "=" * ((8 - len(s) % 8) % 8)
    return base64.b32decode(s + pad, casefold=True)
