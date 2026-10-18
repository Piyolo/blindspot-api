"""Tests for the auth router, deps, and failure limiter (Task 3).

Route tests run through the Task 1 ``client`` fixture (in-memory SQLite via
``app.deps.get_db``); the autouse ``jwt_secret`` fixture keeps token signing
self-contained (same pattern as ``test_security.py``) and the conftest
``_reset_limiters`` fixture keeps the shared client IP clean between tests.
No password value is ever printed.
"""

import pytest
from fastapi import HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials

from app.deps import get_current_user
from app.rate_limit import FailureLimiter, client_ip, login_limiter, signup_limiter
from app.security import create_access_token, decode_access_token

SIGNUP = "/api/v1/auth/signup"
LOGIN = "/api/v1/auth/login"

VALID_SIGNUP = {
    "name": "Maria Santos",
    "email": "maria@example.com",
    "password": "password123",
    "contact_number": "0917 123 4567",
}


@pytest.fixture(autouse=True)
def jwt_secret(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "test-secret")


def _signup_payload(**overrides):
    payload = dict(VALID_SIGNUP)
    payload.update(overrides)
    return payload


def _credentials(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


# --- POST /auth/signup ---------------------------------------------------


async def test_signup_returns_token_and_user(client):
    r = await client.post(SIGNUP, json=_signup_payload())
    assert r.status_code == 201
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["user"]["name"] == "Maria Santos"
    assert body["user"]["email"] == "maria@example.com"
    # canonical form: digits only
    assert body["user"]["contact_number"] == "09171234567"
    assert body["user"]["id"] >= 1
    # the token's sub is the new row's id
    assert decode_access_token(body["access_token"]) == body["user"]["id"]


async def test_signup_duplicate_email_is_409(client):
    first = await client.post(SIGNUP, json=_signup_payload(email="maria@example.com"))
    assert first.status_code == 201
    # Same address in a different case — the duplicate check is
    # case-insensitive.
    second = await client.post(SIGNUP, json=_signup_payload(email="MARIA@Example.com"))
    assert second.status_code == 409
    assert second.json()["detail"] == "This email is already registered. Try logging in."


async def test_signup_rate_limited_after_5_per_hour(client):
    for i in range(5):
        r = await client.post(SIGNUP, json=_signup_payload(email=f"user{i}@example.com"))
        assert r.status_code == 201
    r = await client.post(SIGNUP, json=_signup_payload(email="user5@example.com"))
    assert r.status_code == 429
    assert r.json()["detail"] == "Too many attempts. Try again later."


async def test_signup_invalid_body_is_400_with_string_detail(client):
    # End-to-end counterpart of Task 1's handler unit test: a missing field
    # reaches the app-level handler and comes back as a string detail.
    r = await client.post(SIGNUP, json={"email": "maria@example.com"})
    assert r.status_code == 400
    assert isinstance(r.json()["detail"], str)


# --- POST /auth/login ----------------------------------------------------


async def test_login_ok_and_wrong_password(client):
    signup = await client.post(SIGNUP, json=_signup_payload())
    assert signup.status_code == 201
    user_id = signup.json()["user"]["id"]

    ok = await client.post(
        LOGIN, json={"email": "maria@example.com", "password": "password123"}
    )
    assert ok.status_code == 200
    assert decode_access_token(ok.json()["access_token"]) == user_id

    wrong = await client.post(
        LOGIN, json={"email": "maria@example.com", "password": "wrong-pass-1"}
    )
    assert wrong.status_code == 401
    assert wrong.json()["detail"] == "Invalid email or password."


async def test_login_unknown_email_is_401_generic(client):
    r = await client.post(
        LOGIN, json={"email": "nobody@example.com", "password": "password123"}
    )
    assert r.status_code == 401
    # identical detail to a wrong password — no user enumeration
    assert r.json()["detail"] == "Invalid email or password."


async def test_login_rate_limited_after_10_failures(client):
    for _ in range(10):
        r = await client.post(
            LOGIN, json={"email": "ghost@example.com", "password": "nope12345"}
        )
        assert r.status_code == 401
    r = await client.post(
        LOGIN, json={"email": "ghost@example.com", "password": "nope12345"}
    )
    assert r.status_code == 429
    assert r.json()["detail"] == "Too many attempts. Try again later."


async def test_login_success_resets_limiter(client):
    await client.post(SIGNUP, json=_signup_payload())
    for _ in range(9):
        r = await client.post(
            LOGIN, json={"email": "maria@example.com", "password": "wrong-pass-1"}
        )
        assert r.status_code == 401
    ok = await client.post(
        LOGIN, json={"email": "maria@example.com", "password": "password123"}
    )
    assert ok.status_code == 200
    # counter was reset: the next failure is a plain 401, not a 429
    r = await client.post(
        LOGIN, json={"email": "maria@example.com", "password": "wrong-pass-1"}
    )
    assert r.status_code == 401


# --- app.deps.get_current_user -------------------------------------------


async def test_get_current_user_missing_token_is_401(db_session):
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(credentials=None, db=db_session)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid or expired token"


async def test_get_current_user_expired_token_is_401(db_session):
    token = create_access_token(user_id=1, ttl_seconds=-10)
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(credentials=_credentials(token), db=db_session)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid or expired token"


async def test_get_current_user_unknown_user_is_401(db_session):
    token = create_access_token(user_id=999)  # no such row
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(credentials=_credentials(token), db=db_session)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid or expired token"


# --- app.rate_limit -------------------------------------------------------


def test_module_limiters_match_spec():
    assert (login_limiter.limit, login_limiter.window_seconds) == (10, 600)
    assert (signup_limiter.limit, signup_limiter.window_seconds) == (5, 3600)


def test_failure_limiter_allows_key_with_no_hits_and_allowed_is_pure():
    limiter = FailureLimiter(1, 60)
    assert limiter.allowed("ip") is True
    # allowed() records nothing, so the key is still allowed
    assert limiter.allowed("ip") is True


def test_failure_limiter_blocks_at_limit_and_reset_clears():
    limiter = FailureLimiter(2, 600)
    limiter.record("ip", now=1000.0)
    assert limiter.allowed("ip", now=1001.0) is True
    limiter.record("ip", now=1001.0)
    assert limiter.allowed("ip", now=1002.0) is False
    limiter.reset("ip")
    assert limiter.allowed("ip", now=1003.0) is True
    limiter.reset("never-seen")  # no-op, must not raise


def test_failure_limiter_prunes_hits_older_than_window():
    limiter = FailureLimiter(2, 600)
    limiter.record("ip", now=1000.0)
    limiter.record("ip", now=1300.0)
    # At 1600 the hit at 1000 is exactly one window old -> expired.
    assert limiter.allowed("ip", now=1600.0) is True
    limiter.record("ip", now=1601.0)
    assert limiter.allowed("ip", now=1602.0) is False


def _request(headers=None, client_host="127.0.0.1"):
    scope = {
        "type": "http",
        "headers": [
            (name.lower().encode(), value.encode())
            for name, value in (headers or {}).items()
        ],
        "client": (client_host, 12345),
    }
    return Request(scope)


def test_client_ip_prefers_first_x_forwarded_for_entry():
    request = _request(headers={"X-Forwarded-For": "203.0.113.7, 10.0.0.1"})
    assert client_ip(request) == "203.0.113.7"


def test_client_ip_trims_forwarded_entry():
    request = _request(headers={"X-Forwarded-For": "  203.0.113.7 ,10.0.0.1"})
    assert client_ip(request) == "203.0.113.7"


def test_client_ip_falls_back_to_client_host():
    assert client_ip(_request()) == "127.0.0.1"
