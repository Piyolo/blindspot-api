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
from sqlalchemy import text

from app.deps import get_current_user, get_db
from app.models import User
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


async def test_signup_rate_limit_ignores_rotating_x_forwarded_for(client):
    # Live regression (Render behind Cloudflare): the edge APPENDS to
    # X-Forwarded-For, so a caller who omits CF-Connecting-IP and rotates
    # XFF on every request must still share ONE bucket. Keying on any XFF
    # position spread these across buckets and the deployed 6th signup
    # returned 201 instead of 429.
    for i in range(5):
        r = await client.post(
            SIGNUP,
            json=_signup_payload(email=f"rot{i}@example.com"),
            headers={"X-Forwarded-For": f"203.0.113.{i + 1}"},
        )
        assert r.status_code == 201
    r = await client.post(
        SIGNUP,
        json=_signup_payload(email="rot5@example.com"),
        headers={"X-Forwarded-For": "203.0.113.6"},
    )
    assert r.status_code == 429
    assert r.json()["detail"] == "Too many attempts. Try again later."


async def test_signup_stable_cf_connecting_ip_gets_its_own_bucket(client):
    # A stable CF-Connecting-IP fills and trips its own bucket even while
    # XFF rotates on every request; it shares nothing with a no-CF caller,
    # whose key is the test client's socket host (each test starts from a
    # freshly reset limiter).
    for i in range(5):
        r = await client.post(
            SIGNUP,
            json=_signup_payload(email=f"cf{i}@example.com"),
            headers={
                "CF-Connecting-IP": "203.0.113.9",
                "X-Forwarded-For": f"198.51.100.{i + 1}",
            },
        )
        assert r.status_code == 201
    r = await client.post(
        SIGNUP,
        json=_signup_payload(email="cf5@example.com"),
        headers={"CF-Connecting-IP": "203.0.113.9", "X-Forwarded-For": "198.51.100.6"},
    )
    assert r.status_code == 429
    assert r.json()["detail"] == "Too many attempts. Try again later."


async def test_signup_limit_holds_when_true_client_ip_rotates_but_cf_connecting_ip_is_stable(
    client,
):
    # Precedence must hold at the ROUTE level too: Cloudflare strips/blocks a
    # caller-supplied CF-Connecting-IP at its edge (403), while a caller-
    # supplied True-Client-IP does reach the app. So an attacker who sends
    # both headers and rotates True-Client-IP must still land in the one
    # CF-Connecting-IP bucket — 5 fills trip the limit and the 6th request
    # 429s even though its True-Client-IP differs from every fill.
    for i in range(5):
        r = await client.post(
            SIGNUP,
            json=_signup_payload(email=f"prec{i}@example.com"),
            headers={
                "CF-Connecting-IP": "203.0.113.9",
                "True-Client-IP": f"198.51.100.{i + 1}",
            },
        )
        assert r.status_code == 201
    r = await client.post(
        SIGNUP,
        json=_signup_payload(email="prec5@example.com"),
        headers={"CF-Connecting-IP": "203.0.113.9", "True-Client-IP": "198.51.100.6"},
    )
    assert r.status_code == 429
    assert r.json()["detail"] == "Too many attempts. Try again later."


async def test_signup_rotating_cf_connecting_ip_gets_fresh_buckets(client):
    # CF-Connecting-IP is Cloudflare-controlled in production — Cloudflare
    # overwrites whatever the caller sent, so callers cannot rotate it
    # there. In this in-process test the header is caller-controlled, so
    # rotating it mints a fresh bucket per request: the expected behaviour
    # of the agreed contract, not a production bypass.
    for i in range(10):
        r = await client.post(
            SIGNUP,
            json=_signup_payload(email=f"fresh{i}@example.com"),
            headers={"CF-Connecting-IP": f"203.0.113.{i + 1}"},
        )
        assert r.status_code == 201


async def test_signup_invalid_body_is_400_with_string_detail(client):
    # End-to-end counterpart of Task 1's handler unit test: a missing field
    # reaches the app-level handler and comes back as a string detail.
    r = await client.post(SIGNUP, json={"email": "maria@example.com"})
    assert r.status_code == 400
    assert isinstance(r.json()["detail"], str)


async def test_signup_lost_race_is_409_not_500(client, db_session, monkeypatch):
    # Reproduce the concurrent-duplicate race deterministically: request A
    # has already committed the row, and request B's duplicate pre-check
    # SELECT ran before that commit — so B's check misses and its INSERT
    # collides with the UNIQUE constraint.
    db_session.add(
        User(
            name="Race Winner",
            email="maria@example.com",
            password_hash="unusable-hash",
            contact_number="09171234567",
        )
    )
    await db_session.commit()

    async def pre_check_misses(db, email):
        return None

    monkeypatch.setattr("app.routers.auth._find_user_id_by_email", pre_check_misses)

    r = await client.post(SIGNUP, json=_signup_payload())
    assert r.status_code == 409
    assert r.json()["detail"] == "This email is already registered. Try logging in."


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


async def test_login_rate_limit_ignores_rotating_x_forwarded_for(client):
    # Same live regression on the login path: rotating XFF while omitting
    # CF-Connecting-IP must still share ONE bucket, so the 11th consecutive
    # failure trips 429 (deployed it returned 401).
    for i in range(10):
        r = await client.post(
            LOGIN,
            json={"email": "ghost@example.com", "password": "nope12345"},
            headers={"X-Forwarded-For": f"203.0.113.{i + 1}"},
        )
        assert r.status_code == 401
    r = await client.post(
        LOGIN,
        json={"email": "ghost@example.com", "password": "nope12345"},
        headers={"X-Forwarded-For": "203.0.113.11"},
    )
    assert r.status_code == 429
    assert r.json()["detail"] == "Too many attempts. Try again later."


async def test_login_stable_cf_connecting_ip_is_its_own_bucket(client):
    # 5 failures from a caller with no CF header, then 6 from a caller with
    # a stable CF-Connecting-IP: neither trips (limit is 10), but under a
    # shared bucket the 11th request would be over the limit and 429.
    for _ in range(5):
        r = await client.post(
            LOGIN,
            json={"email": "ghost@example.com", "password": "nope12345"},
        )
        assert r.status_code == 401
    for _ in range(6):
        r = await client.post(
            LOGIN,
            json={"email": "ghost@example.com", "password": "nope12345"},
            headers={"CF-Connecting-IP": "203.0.113.9"},
        )
        assert r.status_code == 401


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
    # The success must have reset the bucket: a full fresh quota of 10
    # failures is allowed before the limiter trips again. (Without the
    # reset the bucket still holds 9 hits, so the 2nd failure below — the
    # 11th overall — would 429.)
    for _ in range(10):
        r = await client.post(
            LOGIN, json={"email": "maria@example.com", "password": "wrong-pass-1"}
        )
        assert r.status_code == 401
    r = await client.post(
        LOGIN, json={"email": "maria@example.com", "password": "wrong-pass-1"}
    )
    assert r.status_code == 429
    assert r.json()["detail"] == "Too many attempts. Try again later."


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


def _request(headers=None, *, client_host="127.0.0.1"):
    scope = {
        "type": "http",
        "headers": [
            (name.lower().encode(), value.encode())
            for name, value in (headers or {}).items()
        ],
    }
    if client_host is not None:
        scope["client"] = (client_host, 12345)
    return Request(scope)


def test_client_ip_prefers_cf_connecting_ip_and_ignores_spoofed_xff():
    # Regression for the live defect: Cloudflare APPENDS to X-Forwarded-For,
    # so the leftmost entry is caller-controlled and the rest are rotating
    # edge hops. A caller-supplied XFF must never influence the key.
    request = _request(
        headers={
            "CF-Connecting-IP": "203.0.113.9",
            "X-Forwarded-For": "8.8.8.8, 1.1.1.1",
        }
    )
    assert client_ip(request) == "203.0.113.9"


def test_client_ip_prefers_cf_connecting_ip_over_true_client_ip():
    # Both headers present with DIFFERENT valid addresses: CF-Connecting-IP
    # must win. Cloudflare strips/blocks a caller-supplied CF-Connecting-IP
    # (403 at the edge) but forwards a caller-supplied True-Client-IP, so a
    # swapped lookup order would let a caller pick their own limiter key and
    # mint fresh buckets.
    request = _request(
        headers={
            "CF-Connecting-IP": "203.0.113.9",
            "True-Client-IP": "198.51.100.7",
        }
    )
    assert client_ip(request) == "203.0.113.9"


def test_client_ip_falls_back_to_true_client_ip():
    request = _request(headers={"True-Client-IP": "198.51.100.7"})
    assert client_ip(request) == "198.51.100.7"


def test_client_ip_never_keys_on_x_forwarded_for_alone():
    # A lone, perfectly valid-looking XFF entry must be ignored entirely —
    # no XFF position may ever be used as a rate-limit key.
    request = _request(headers={"X-Forwarded-For": "203.0.113.9"})
    assert client_ip(request) == "127.0.0.1"


def test_client_ip_falls_back_to_client_host():
    assert client_ip(_request()) == "127.0.0.1"


def test_client_ip_is_unknown_when_no_client_and_no_headers():
    request = _request(client_host=None)  # scope has no "client" key
    assert client_ip(request) == "unknown"


def test_client_ip_is_unknown_when_client_host_is_empty():
    assert client_ip(_request(client_host="")) == "unknown"


def test_client_ip_trims_cf_connecting_ip():
    request = _request(headers={"CF-Connecting-IP": " 203.0.113.9 "})
    assert client_ip(request) == "203.0.113.9"


def test_client_ip_trims_true_client_ip():
    request = _request(headers={"True-Client-IP": "  198.51.100.7  "})
    assert client_ip(request) == "198.51.100.7"


@pytest.mark.parametrize(
    "junk",
    ["not-an-ip", "999.999.999.999", "  ", ""],
    ids=["not-an-ip", "out-of-range-octets", "blank", "empty"],
)
def test_client_ip_never_returns_junk_cf_connecting_ip(junk):
    # The junk value must never become the key: fall through to the socket
    # peer instead.
    assert client_ip(_request(headers={"CF-Connecting-IP": junk})) == "127.0.0.1"


def test_client_ip_junk_cf_falls_through_to_valid_true_client_ip():
    request = _request(
        headers={"CF-Connecting-IP": "not-an-ip", "True-Client-IP": "198.51.100.7"}
    )
    assert client_ip(request) == "198.51.100.7"


def test_client_ip_junk_cf_and_junk_true_client_ip_fall_back_to_client_host():
    request = _request(
        headers={"CF-Connecting-IP": "999.999.999.999", "True-Client-IP": "nope"}
    )
    assert client_ip(request) == "127.0.0.1"


# --- app.deps.get_db ------------------------------------------------------


async def test_get_db_closes_session_when_body_raises(db_engine, monkeypatch):
    monkeypatch.setattr("app.database.get_engine", lambda: db_engine)
    agen = get_db()
    session = await agen.__anext__()  # advance to the yield
    await session.execute(text("SELECT 1"))  # autobegins a transaction
    assert session.in_transaction() is True
    with pytest.raises(RuntimeError, match="boom"):
        await agen.athrow(RuntimeError("boom"))  # simulate a failing request
    # The finally clause must have closed the session, ending its
    # transaction (an unclosed session would still be in_transaction).
    assert session.in_transaction() is False
