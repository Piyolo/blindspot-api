"""argon2 password hashing and HS256 JWT access-token helpers.

Pure functions — no routes, no database access. Every access-token failure
mode (expired, tampered, malformed, wrong algorithm, missing or
non-canonical ``sub``) surfaces as :class:`InvalidTokenError`; PyJWT's
internal exception types never leak to callers.
"""

import re
import time

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error

from app.config import ACCESS_TTL_SECONDS, get_jwt_secret

ALGORITHM = "HS256"

# Ratified sub rule: a decimal string with no sign, leading zero,
# whitespace or underscores ("1", "42", "999999999999999999999").
_CANONICAL_SUB = re.compile(r"[1-9][0-9]*")

# argon2id with argon2-cffi's defaults (lead ruling: no new dependencies).
_hasher = PasswordHasher()


class InvalidTokenError(Exception):
    """Raised by ``decode_access_token`` for every token failure mode."""


def hash_password(password: str) -> str:
    """Return an argon2id hash of ``password`` (never the plaintext)."""
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Return True iff ``password`` matches ``password_hash``.

    Wrong password, a non-string or empty hash, a corrupted hash, and
    unsupported hash parameters all return False rather than raising.
    """
    if not isinstance(password_hash, str) or not password_hash:
        return False
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
        payload = jwt.decode(
            token,
            get_jwt_secret(),
            algorithms=[ALGORITHM],
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.PyJWTError as exc:
        # ExpiredSignatureError, InvalidSignatureError, DecodeError,
        # InvalidAlgorithmError, MissingRequiredClaimError, ... — all
        # wrapped, none leak.
        raise InvalidTokenError("Invalid or expired access token") from exc
    return _user_id_from_payload(payload)


def _user_id_from_payload(payload: dict) -> int:
    # PyJWT 2.15.1's verify_sub (default on) guarantees "sub" is present
    # and a string by the time it reaches us; the canonical-form rule below
    # is ours: ^[1-9][0-9]*$ — no sign, leading zero, whitespace or
    # underscores (fullmatch, so not even a trailing newline slips through).
    sub = payload.get("sub")
    if not isinstance(sub, str) or _CANONICAL_SUB.fullmatch(sub) is None:
        raise InvalidTokenError("Invalid or expired access token")
    try:
        return int(sub)
    except ValueError as exc:
        # Only reachable for absurdly long digit strings under runtimes
        # with the int-to-str digit limit (Python 3.11+).
        raise InvalidTokenError("Invalid or expired access token") from exc
