"""Pydantic request/response schemas and validation helpers.

The error strings defined here are copy-deck strings (spec §11): they reach
the app verbatim as ``{"detail": "..."}``, so they must not change without a
copy-deck review.
"""

import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

PASSWORD_RULE_ERROR = "Password must be at least 8 characters with a letter and a number."
CONTACT_NUMBER_ERROR = "Enter a valid contact number (7 to 15 digits)."


def is_valid_password(raw: str) -> bool:
    """True when the password is at least 8 characters with a letter and a digit."""
    return (
        len(raw) >= 8
        and any(ch.isalpha() for ch in raw)
        and any(ch.isdigit() for ch in raw)
    )


def normalize_contact_number(raw: str) -> str:
    """Strip formatting, keep a leading ``+``, and validate 7-15 digits.

    ASCII-only by contract (parity with the client's rule): a leading ``+``
    is kept, only ASCII digits ``[0-9]`` count, everything else is stripped —
    so Unicode digits (fullwidth, Arabic-Indic, ...) never satisfy the rule.
    Returns the canonical form (digits, or ``+`` followed by digits).
    Raises ``ValueError`` (surfaced to clients as a 400 ``detail`` string)
    when the number holds fewer than 7 or more than 15 digits.
    """
    text = raw.strip()
    has_plus = text.startswith("+")
    digits = re.sub(r"[^0-9]", "", text)
    if not 7 <= len(digits) <= 15:
        raise ValueError(CONTACT_NUMBER_ERROR)
    return f"+{digits}" if has_plus else digits


def _strip_name(value):
    if isinstance(value, str):
        return value.strip()
    return value


class SignupRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    email: EmailStr = Field(max_length=254)
    password: str
    contact_number: str

    @field_validator("name", mode="before")
    @classmethod
    def strip_name(cls, value):
        return _strip_name(value)

    @field_validator("email")
    @classmethod
    def lower_email(cls, value: str) -> str:
        return value.lower()

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str) -> str:
        if not is_valid_password(value):
            raise ValueError(PASSWORD_RULE_ERROR)
        return value

    @field_validator("contact_number")
    @classmethod
    def normalize_contact(cls, value: str) -> str:
        return normalize_contact_number(value)


class LoginRequest(BaseModel):
    email: EmailStr = Field(max_length=254)
    password: str

    @field_validator("email")
    @classmethod
    def lower_email(cls, value: str) -> str:
        # email-validator keeps the local part's case; lowercase so the
        # stored canonical form and Task 3's lookup always agree.
        return value.lower()


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    email: str
    contact_number: str
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class UpdateMeRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    contact_number: str | None = None

    @field_validator("name", mode="before")
    @classmethod
    def strip_name(cls, value):
        return _strip_name(value)

    @field_validator("contact_number")
    @classmethod
    def normalize_contact(cls, value):
        if value is None:
            return None
        return normalize_contact_number(value)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def check_password(cls, value: str) -> str:
        if not is_valid_password(value):
            raise ValueError(PASSWORD_RULE_ERROR)
        return value


class OkResponse(BaseModel):
    ok: bool = True
