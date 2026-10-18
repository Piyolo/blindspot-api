"""Tests for the /me router (Task 4): read, partial update, password change.

Route tests run through the Task 1 ``client`` fixture (in-memory SQLite via
``app.deps.get_db``); the conftest ``auth_headers`` fixture signs a user up
through the real signup route and yields their bearer headers, and this
module's autouse ``jwt_secret`` fixture keeps token signing self-contained
(same pattern as ``test_auth.py``). No password value is ever printed.

Task 3's ``get_current_user`` tests call the dependency directly, bypassing
``HTTPBearer``; the parametrised cases at the bottom of this file close that
gap through the real mounted route.
"""

import pytest
from sqlalchemy import delete, select

from app.models import User
from app.security import create_access_token, decode_access_token, verify_password

SIGNUP = "/api/v1/auth/signup"
LOGIN = "/api/v1/auth/login"
ME = "/api/v1/me"
ME_PASSWORD = "/api/v1/me/password"

SIGNUP_EMAIL = "maria@example.com"
SIGNUP_PASSWORD = "password123"
NEW_PASSWORD = "newpass456"

# Copy-deck strings, pinned verbatim (spec §11) — same style as test_auth.py.
CONTACT_NUMBER_ERROR = "Enter a valid contact number (7 to 15 digits)."
PASSWORD_RULE_ERROR = "Password must be at least 8 characters with a letter and a number."
CURRENT_PASSWORD_ERROR = "Current password is incorrect."
INVALID_TOKEN_DETAIL = "Invalid or expired token"


@pytest.fixture(autouse=True)
def jwt_secret(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "test-secret")


# --- GET /me --------------------------------------------------------------


async def test_me_returns_current_user(client, auth_headers):
    r = await client.get(ME, headers=auth_headers)
    assert r.status_code == 200
    user = r.json()["user"]
    assert user["email"] == SIGNUP_EMAIL
    assert user["name"] == "Maria Santos"
    # canonical form: digits only (the signup sent "0917 123 4567")
    assert user["contact_number"] == "09171234567"
    assert user["id"] >= 1


async def test_get_me_without_token_is_401(client):
    r = await client.get(ME)
    assert r.status_code == 401
    assert r.json()["detail"] == INVALID_TOKEN_DETAIL


# --- PUT /me --------------------------------------------------------------


async def test_put_me_updates_contact_and_persists(client, auth_headers):
    r = await client.put(
        ME, headers=auth_headers, json={"contact_number": "+63 917 123 4567"}
    )
    assert r.status_code == 200
    body = r.json()
    # canonical form of what was sent
    assert body["user"]["contact_number"] == "+639171234567"
    # the absent field was not touched
    assert body["user"]["name"] == "Maria Santos"
    # a fresh GET shows the new canonical value was committed
    r = await client.get(ME, headers=auth_headers)
    assert r.json()["user"]["contact_number"] == "+639171234567"


async def test_put_me_partial_update_leaves_other_fields_alone(client, auth_headers):
    # name only: contact_number is absent, so it stays as signed up
    r = await client.put(ME, headers=auth_headers, json={"name": "Maria Cruz"})
    assert r.status_code == 200
    assert r.json()["user"]["name"] == "Maria Cruz"
    assert r.json()["user"]["contact_number"] == "09171234567"
    # explicit nulls are ignored too — never cleared
    r = await client.put(
        ME, headers=auth_headers, json={"name": None, "contact_number": None}
    )
    assert r.status_code == 200
    assert r.json()["user"]["name"] == "Maria Cruz"
    assert r.json()["user"]["contact_number"] == "09171234567"


async def test_put_me_rejects_bad_contact(client, auth_headers):
    r = await client.put(ME, headers=auth_headers, json={"contact_number": "12"})
    assert r.status_code == 400
    assert isinstance(r.json()["detail"], str)
    assert r.json()["detail"] == CONTACT_NUMBER_ERROR


async def test_put_me_without_token_is_401(client):
    r = await client.put(ME, json={"contact_number": "09171234567"})
    assert r.status_code == 401
    assert r.json()["detail"] == INVALID_TOKEN_DETAIL


# --- PUT /me/password -----------------------------------------------------


async def test_change_password_happy_path(client, auth_headers, db_session):
    r = await client.put(
        ME_PASSWORD,
        headers=auth_headers,
        json={"current_password": SIGNUP_PASSWORD, "new_password": NEW_PASSWORD},
    )
    assert r.status_code == 200
    assert r.json() == {"ok": True}

    # the row now stores an argon2 hash of the new password (never plaintext)
    stored_hash = await db_session.scalar(
        select(User.password_hash).where(User.email == SIGNUP_EMAIL)
    )
    assert stored_hash != NEW_PASSWORD
    assert verify_password(NEW_PASSWORD, stored_hash) is True
    assert verify_password(SIGNUP_PASSWORD, stored_hash) is False

    # the old password stops working, the new one works
    old = await client.post(
        LOGIN, json={"email": SIGNUP_EMAIL, "password": SIGNUP_PASSWORD}
    )
    assert old.status_code == 401
    new = await client.post(
        LOGIN, json={"email": SIGNUP_EMAIL, "password": NEW_PASSWORD}
    )
    assert new.status_code == 200

    # the already-issued token keeps working (spec: single 30-day JWT, no
    # revocation on password change)
    still = await client.get(ME, headers=auth_headers)
    assert still.status_code == 200


async def test_change_password_wrong_current_is_401(client, auth_headers):
    r = await client.put(
        ME_PASSWORD,
        headers=auth_headers,
        json={"current_password": "wrong-pass-1", "new_password": NEW_PASSWORD},
    )
    assert r.status_code == 401
    assert r.json()["detail"] == CURRENT_PASSWORD_ERROR
    # nothing changed: the original password still logs in
    ok = await client.post(
        LOGIN, json={"email": SIGNUP_EMAIL, "password": SIGNUP_PASSWORD}
    )
    assert ok.status_code == 200


async def test_change_password_enforces_rules(client, auth_headers):
    r = await client.put(
        ME_PASSWORD,
        headers=auth_headers,
        json={"current_password": SIGNUP_PASSWORD, "new_password": "short1"},
    )
    assert r.status_code == 400
    assert isinstance(r.json()["detail"], str)
    assert r.json()["detail"] == PASSWORD_RULE_ERROR


# --- bad Authorization headers through the real route ---------------------


@pytest.mark.parametrize(
    "case",
    [
        "missing_header",
        "wrong_scheme",
        "bearer_without_token",
        "bearer_blank_token",
        "expired_token",
        "tampered_token",
        "deleted_user",
    ],
)
async def test_me_rejects_bad_authorization_headers(
    client, auth_headers, db_session, case
):
    """Every bad-authorization mode reaching the mounted route ⇒ same 401.

    Task 3's tests cover ``get_current_user`` directly; these cases go
    through FastAPI's ``HTTPBearer`` parsing and the route itself, so a
    missing header, a wrong scheme, empty credentials, an expired or
    tampered token, and a token whose user row is gone are all
    indistinguishable to the client.
    """
    token = auth_headers["Authorization"].split(" ", 1)[1]
    user_id = decode_access_token(token)
    headers = None  # missing_header: no Authorization header at all
    if case == "wrong_scheme":
        headers = {"Authorization": "Token abc"}
    elif case == "bearer_without_token":
        headers = {"Authorization": "Bearer"}
    elif case == "bearer_blank_token":
        headers = {"Authorization": "Bearer  "}
    elif case == "expired_token":
        headers = {
            "Authorization": f"Bearer {create_access_token(user_id, ttl_seconds=-10)}"
        }
    elif case == "tampered_token":
        # flip the signature's last character — still well-formed JWT shape
        forged = token[:-1] + ("A" if token[-1] != "A" else "B")
        headers = {"Authorization": f"Bearer {forged}"}
    elif case == "deleted_user":
        await db_session.execute(delete(User).where(User.id == user_id))
        await db_session.commit()
    r = await client.get(ME, headers=headers)
    assert r.status_code == 401
    assert r.json()["detail"] == INVALID_TOKEN_DETAIL
