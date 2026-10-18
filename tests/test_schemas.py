import json

import pytest
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError

from datetime import datetime, timezone

from app.main import validation_exception_handler
from app.models import User
from app.schemas import (
    CONTACT_NUMBER_ERROR,
    PASSWORD_RULE_ERROR,
    ChangePasswordRequest,
    LoginRequest,
    OkResponse,
    SignupRequest,
    TokenResponse,
    UpdateMeRequest,
    UserOut,
    normalize_contact_number,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("0917 123 4567", "09171234567"),
        ("+63 917-123-4567", "+639171234567"),
        (" 0917-123-4567 ", "09171234567"),
        ("abc09171234567", "09171234567"),
        ("++639171234567", "+639171234567"),
    ],
)
def test_contact_normalization(raw, expected):
    assert normalize_contact_number(raw) == expected


@pytest.mark.parametrize("raw", ["１２３４５６７", "０９１７１２３４５６７", "٠٩١٧١٢٣٤٥٦٧"])
def test_contact_rejects_non_ascii_digits(raw):
    # ASCII-only rule (parity with the client): Unicode digits are stripped,
    # leaving fewer than 7 ASCII digits -> ValueError with the pinned message.
    with pytest.raises(ValueError) as excinfo:
        normalize_contact_number(raw)
    assert str(excinfo.value) == CONTACT_NUMBER_ERROR


def test_login_email_is_lowercased():
    login = LoginRequest(email="Ana@Example.COM", password="whatever")
    assert login.email == "ana@example.com"


def test_signup_email_is_lowercased():
    signup = SignupRequest(
        name="Ana",
        email="Ana@Example.COM",
        password="password123",
        contact_number="09171234567",
    )
    assert signup.email == "ana@example.com"


def test_signup_rejects_blank_name():
    with pytest.raises(ValidationError):
        SignupRequest(
            name="   ",
            email="ana@example.com",
            password="password123",
            contact_number="09171234567",
        )


def test_signup_strips_name():
    signup = SignupRequest(
        name="  Ana  ",
        email="ana@example.com",
        password="password123",
        contact_number="09171234567",
    )
    assert signup.name == "Ana"


async def test_user_out_from_attributes(db_session):
    user = User(
        name="Ana",
        email="ana@example.com",
        password_hash="x",
        contact_number="09171234567",
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    out = UserOut.model_validate(user)
    assert out.id == user.id
    assert out.name == "Ana"
    assert out.email == "ana@example.com"
    assert out.contact_number == "09171234567"
    assert out.created_at == user.created_at


def test_token_response_token_type_default():
    token = TokenResponse(
        access_token="tok",
        user={
            "id": 1,
            "name": "Ana",
            "email": "ana@example.com",
            "contact_number": "09171234567",
            "created_at": datetime.now(timezone.utc),
        },
    )
    assert token.access_token == "tok"
    assert token.token_type == "bearer"
    assert token.user.name == "Ana"


def test_update_me_request_fields_optional_by_default():
    update = UpdateMeRequest()
    assert update.name is None
    assert update.contact_number is None


def test_change_password_request_field_names():
    change = ChangePasswordRequest(current_password="oldpass123", new_password="newpass123")
    assert change.current_password == "oldpass123"
    assert change.new_password == "newpass123"


def test_ok_response_default_true():
    assert OkResponse().ok is True


async def _signup_detail(**overrides) -> str:
    """Validate a signup payload and return the 400 ``detail`` the app would hear."""
    payload = {
        "name": "Ana",
        "email": "ana@example.com",
        "password": "password123",
        "contact_number": "09171234567",
    }
    payload.update(overrides)
    with pytest.raises(ValidationError) as excinfo:
        SignupRequest(**payload)
    resp = await validation_exception_handler(
        None, RequestValidationError(excinfo.value.errors())
    )
    assert resp.status_code == 400
    return json.loads(resp.body)["detail"]


@pytest.mark.parametrize("raw", ["123", "12345678901234567", "abcd", "+"])
async def test_contact_rejects_bad(raw):
    # ValueError from validator -> 400 detail string
    detail = await _signup_detail(contact_number=raw)
    assert detail == CONTACT_NUMBER_ERROR


@pytest.mark.parametrize("bad", ["short1", "allletters", "12345678"])
async def test_signup_rejects_bad_password(bad):
    detail = await _signup_detail(password=bad)
    assert detail == PASSWORD_RULE_ERROR


async def test_validation_handler_returns_400_with_string_detail():
    # The /auth/signup route does not exist until Task 3; Task 3 adds the end-to-end 400 test.
    # Here the handler is unit-tested directly, so it is a module-level function.
    exc = RequestValidationError(
        [{"loc": ("body", "email"), "msg": "field required", "type": "missing"}]
    )
    resp = await validation_exception_handler(None, exc)
    assert resp.status_code == 400 and isinstance(json.loads(resp.body)["detail"], str)
