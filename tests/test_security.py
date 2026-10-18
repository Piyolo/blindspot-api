"""Tests for the argon2 + JWT security helpers (Task 2).

Every test gets a throwaway ``JWT_SECRET`` from the autouse fixture below, so
no test depends on ``.env`` or a real secret value — and no secret is printed.
"""

import base64
import json
import time

import jwt
import pytest

from app.config import ACCESS_TTL_SECONDS, get_jwt_secret
from app.security import (
    ALGORITHM,
    InvalidTokenError,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


@pytest.fixture(autouse=True)
def jwt_secret(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "test-secret")


def test_hash_password_is_argon2id_and_verifies():
    password_hash = hash_password("password123")
    assert password_hash != "password123"
    assert password_hash.startswith("$argon2id$")
    assert verify_password("password123", password_hash) is True


def test_verify_password_wrong_password_returns_false():
    password_hash = hash_password("password123")
    assert verify_password("wrong-password", password_hash) is False


def test_verify_password_garbage_hash_returns_false():
    # A corrupt/unreadable hash must return False, not raise out of verify.
    assert verify_password("password123", "not-a-hash") is False


def test_token_round_trips_to_same_id():
    token = create_access_token(user_id=7)
    assert decode_access_token(token) == 7


def test_token_claims_and_algorithm():
    token = create_access_token(user_id=42)
    assert jwt.get_unverified_header(token)["alg"] == ALGORITHM == "HS256"
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["sub"] == "42"
    assert isinstance(claims["iat"], int)
    assert isinstance(claims["exp"], int)
    assert claims["exp"] - claims["iat"] == ACCESS_TTL_SECONDS


def test_expired_token_raises_invalid_token():
    token = create_access_token(user_id=1, ttl_seconds=-1)
    with pytest.raises(InvalidTokenError):
        decode_access_token(token)


def test_tampered_token_raises_invalid_token():
    token = create_access_token(user_id=1)
    header, _body, signature = token.split(".")
    claims = jwt.decode(token, options={"verify_signature": False})
    claims["sub"] = "999"
    forged_body = (
        base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    )
    tampered = "{}.{}.{}".format(header, forged_body, signature)
    with pytest.raises(InvalidTokenError):
        decode_access_token(tampered)


def test_garbage_token_raises_invalid_token():
    with pytest.raises(InvalidTokenError):
        decode_access_token("garbage")


def test_wrong_algorithm_token_raises_invalid_token():
    now = int(time.time())
    token = jwt.encode(
        {"sub": "1", "iat": now, "exp": now + 60},
        "not-the-real-secret",
        algorithm="HS512",
    )
    with pytest.raises(InvalidTokenError):
        decode_access_token(token)


def test_missing_sub_raises_invalid_token():
    now = int(time.time())
    token = jwt.encode(
        {"iat": now, "exp": now + 60}, get_jwt_secret(), algorithm="HS256"
    )
    with pytest.raises(InvalidTokenError):
        decode_access_token(token)


@pytest.mark.parametrize("bad_sub", ["abc", "", None, ["1"], 1.5])
def test_non_int_sub_raises_invalid_token(bad_sub):
    now = int(time.time())
    token = jwt.encode(
        {"sub": bad_sub, "iat": now, "exp": now + 60},
        get_jwt_secret(),
        algorithm="HS256",
    )
    with pytest.raises(InvalidTokenError):
        decode_access_token(token)


# --- Fix round 1 (findings F1-F4, F6) -------------------------------------


def test_token_is_bound_to_env_secret(monkeypatch):
    # F1: the secret must come from the environment on *both* encode and
    # decode — a hard-coded secret would make this decode succeed.
    token = create_access_token(user_id=7)
    monkeypatch.setenv("JWT_SECRET", "rotated-secret")
    with pytest.raises(InvalidTokenError):
        decode_access_token(token)


def test_hs512_with_matching_secret_rejected():
    # F2: pins algorithms=[ALGORITHM] — same secret, correct signature,
    # wrong algorithm must still be rejected. Passes only if the allowlist
    # stays HS256-only; widening it to "HS512" must fail this test.
    now = int(time.time())
    token = jwt.encode(
        {"sub": "1", "iat": now, "exp": now + 60},
        get_jwt_secret(),
        algorithm="HS512",
    )
    with pytest.raises(InvalidTokenError):
        decode_access_token(token)


@pytest.mark.parametrize("good_sub", ["1", "42", "999999999999999999999"])
def test_canonical_sub_accepted(good_sub):
    # F3: ^[1-9][0-9]*$ decodes to the integer user id.
    now = int(time.time())
    token = jwt.encode(
        {"sub": good_sub, "iat": now, "exp": now + 60},
        get_jwt_secret(),
        algorithm="HS256",
    )
    assert decode_access_token(token) == int(good_sub)


_MISSING = object()  # sentinel: payload without a "sub" claim at all


@pytest.mark.parametrize(
    "bad_sub",
    ["0", "007", " 12 ", "+5", "-5", "1_0", "abc", "", "12\n", _MISSING],
)
def test_non_canonical_sub_rejected(bad_sub):
    # F3: no sign, no leading zero, no whitespace, no underscores, no
    # empty/non-string — only ^[1-9][0-9]*$ and a present claim.
    now = int(time.time())
    payload = {"iat": now, "exp": now + 60}
    if bad_sub is not _MISSING:
        payload["sub"] = bad_sub
    token = jwt.encode(payload, get_jwt_secret(), algorithm="HS256")
    with pytest.raises(InvalidTokenError):
        decode_access_token(token)


def test_json_integer_sub_rejected():
    # F5 evidence for the report claim: PyJWT 2.15.1 verify_sub defaults to
    # True, so a JSON-integer sub never reaches this module's code — callers
    # still only ever see InvalidTokenError.
    now = int(time.time())
    token = jwt.encode(
        {"sub": 123, "iat": now, "exp": now + 60},
        get_jwt_secret(),
        algorithm="HS256",
    )
    with pytest.raises(InvalidTokenError):
        decode_access_token(token)


@pytest.mark.parametrize("bad_hash", [None, "", 123, b"bytes"])
def test_verify_password_non_string_or_empty_hash_returns_false(bad_hash):
    # F4: the docstring promises False (never an exception) for any bad hash.
    assert verify_password("x", bad_hash) is False


@pytest.mark.parametrize("missing", ["exp", "iat"])
def test_token_missing_required_claim_rejected(missing):
    # F6: exp, iat and sub are required at decode time.
    now = int(time.time())
    payload = {"sub": "1", "iat": now, "exp": now + 60}
    del payload[missing]
    token = jwt.encode(payload, get_jwt_secret(), algorithm="HS256")
    with pytest.raises(InvalidTokenError):
        decode_access_token(token)
