"""Profile routes: read, partial update, and password change (Task 4)."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_current_user, get_db
from app.models import User
from app.schemas import (
    ChangePasswordRequest,
    OkResponse,
    UpdateMeRequest,
    UserOut,
)
from app.security import hash_password, verify_password

router = APIRouter(tags=["me"])

CURRENT_PASSWORD_ERROR = "Current password is incorrect."


class MeResponse(BaseModel):
    """Envelope for the /me routes: ``{"user": UserOut}``."""

    user: UserOut


@router.get("/me", response_model=MeResponse)
async def read_me(user: User = Depends(get_current_user)) -> MeResponse:
    """Return the bearer-authenticated user's profile.

    ``get_current_user`` raises 401 for every bad-authorization mode
    (missing/malformed/expired/tampered token, deleted user row) with one
    generic detail, so nothing here can leak token diagnostics.
    """
    return MeResponse(user=UserOut.model_validate(user))


@router.put("/me", response_model=MeResponse)
async def update_me(
    payload: UpdateMeRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MeResponse:
    """Partially update ``name`` and/or ``contact_number``.

    A field that is absent or explicitly ``null`` is ignored, never
    cleared. Validation (name bounds, contact normalisation and the
    7-15-digit rule) lives in ``UpdateMeRequest`` and surfaces through
    Task 1's handler as a 400 with a string detail. The route session is
    built with ``expire_on_commit=False``, so ``user`` stays usable after
    the commit.
    """
    if payload.name is not None:
        user.name = payload.name
    if payload.contact_number is not None:
        user.contact_number = payload.contact_number
    await db.commit()
    return MeResponse(user=UserOut.model_validate(user))


@router.put("/me/password", response_model=OkResponse)
async def change_password(
    payload: ChangePasswordRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> OkResponse:
    """Replace the user's password after re-checking the current one.

    ``ChangePasswordRequest`` enforces the pinned password rules on
    ``new_password`` (400 via Task 1's handler). A wrong current password
    is a 401 with its own detail. The new hash is stored via
    ``hash_password``; the plaintext is never logged or echoed. Per spec,
    already-issued tokens stay valid — a single 30-day JWT, no revocation.
    """
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=401, detail=CURRENT_PASSWORD_ERROR)
    user.password_hash = hash_password(payload.new_password)
    await db.commit()
    return OkResponse()
