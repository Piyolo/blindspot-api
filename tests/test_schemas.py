import json

import pytest
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError

from app.main import validation_exception_handler
from app.schemas import (
    CONTACT_NUMBER_ERROR,
    PASSWORD_RULE_ERROR,
    SignupRequest,
    normalize_contact_number,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("0917 123 4567", "09171234567"),
        ("+63 917-123-4567", "+639171234567"),
        (" 0917-123-4567 ", "09171234567"),
    ],
)
def test_contact_normalization(raw, expected):
    assert normalize_contact_number(raw) == expected


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
