"""Authentication primitives for the CET431 SecureShop learning application.

Argon2id protects passwords at rest. RFC 6238 TOTP is an independent
possession-based factor. These are teaching primitives, not a WebAuthn substitute.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerificationError, InvalidHashError

PASSWORD_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16, type=Type.ID)


def hash_password(password: str) -> str:
    return PASSWORD_HASHER.hash(password)


def verify_password(password: str, stored: str) -> bool:
    try:
        return bool(PASSWORD_HASHER.verify(stored, password))
    except (VerificationError, InvalidHashError, ValueError, TypeError):
        return False


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode('ascii').rstrip('=')


def totp_at(secret: str, when: int, step: int = 30) -> str:
    secret_bytes = base64.b32decode(secret + '=' * (-len(secret) % 8), casefold=True)
    moving = struct.pack('>Q', int(when) // step)
    digest = hmac.new(secret_bytes, moving, hashlib.sha1).digest()
    offset = digest[-1] & 15
    code = (struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f'{code:06d}'


def match_totp_step(secret: str, supplied: str, now: int | None = None, window: int = 1) -> int | None:
    if not isinstance(supplied, str) or len(supplied) != 6 or not supplied.isascii() or not supplied.isdigit():
        return None
    now = int(time.time()) if now is None else int(now)
    for shift in range(-window, window + 1):
        timestamp = now + shift * 30
        if timestamp < 0:
            continue
        if hmac.compare_digest(totp_at(secret, timestamp), supplied):
            return timestamp // 30
    return None
