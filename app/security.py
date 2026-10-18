"""argon2 password hashing and HS256 JWT access-token helpers.

Pure functions — no routes, no database access. Every access-token failure
mode (expired, tampered, malformed, wrong algorithm, missing/non-integer
``sub``) surfaces as :class:`InvalidTokenError`; PyJWT's internal exception
types never leak to callers.
"""

import time

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error

from app.config import ACCESS_TTL_SECONDS, get_jwt_secret

ALGORITHM = "HS256"

# argon2id with argon2-cffi's defaults (lead ruling: no new dependencies).
_hasher = PasswordHasher()


class InvalidTokenError(Exception):
    """Raised by ``decode_access_token`` for every token failure mode."""


def hash_password(password: str) -> str:
    """Return an argon2id hash of ``password`` (never the plaintext)."""
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Return True iff ``password`` matches ``password_hash``.

    Wrong password, corrupted hash, and unsupported hash parameters all
    return False rather than raising.
    """
    try:
        return _hasher.verify(password_hash, password)
    except (Argon2Error, ValueError):
        # VerifyMismatchError (Argon2Error) · InvalidHashError and
        # UnsupportedParametersError (both ValueError subclasses).
        return False


def create_access_token(user_id: int, ttl_seconds: int = ACCESS_TTL_SECONDS) -> str:
    """Encode an HS256 access token: ``sub`` = str(user_id), ``iat``, ``exp``."""
    now = int(time.time())
    payload = {"sub": str(user_id), "iat": now, "exp": now + ttl_seconds}
    return jwt.encode(payload, get_jwt_secret(), algorithm=ALGORITHM)


def decode_access_token(token: str) -> int:
    """Return the integer user id for ``token`` or raise InvalidTokenError."""
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[ALGORITHM])
    except jwt.PyJWTError as exc:
        # ExpiredSignatureError, InvalidSignatureError, DecodeError,
        # InvalidAlgorithmError, ... — all wrapped, none leak.
        raise InvalidTokenError("Invalid or expired access token") from exc
    return _user_id_from_payload(payload)


def _user_id_from_payload(payload: dict) -> int:
    sub = payload.get("sub")
    if isinstance(sub, str):
        try:
            return int(sub)
        except ValueError as exc:
            raise InvalidTokenError("Invalid or expired access token") from exc
    if isinstance(sub, int) and not isinstance(sub, bool):
        return sub
    raise InvalidTokenError("Invalid or expired access token")
