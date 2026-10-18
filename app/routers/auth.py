"""Auth routes: signup and login (Task 3)."""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db
from app.models import User
from app.rate_limit import client_ip, login_limiter, signup_limiter
from app.schemas import LoginRequest, SignupRequest, TokenResponse, UserOut
from app.security import create_access_token, hash_password, verify_password

router = APIRouter(tags=["auth"])

RATE_LIMIT_DETAIL = "Too many attempts. Try again later."
EMAIL_TAKEN_DETAIL = "This email is already registered. Try logging in."
LOGIN_FAILED_DETAIL = "Invalid email or password."


@router.post("/auth/signup", status_code=201, response_model=TokenResponse)
async def signup(
    payload: SignupRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Register a new user and return their first access token.

    Emails are stored and compared lowercased (``SignupRequest``'s
    validator), so the duplicate check is case-insensitive. Every allowed
    attempt counts against ``signup_limiter`` (5 per IP per hour).
    """
    ip = client_ip(request)
    if not signup_limiter.allowed(ip):
        raise HTTPException(status_code=429, detail=RATE_LIMIT_DETAIL)
    signup_limiter.record(ip)
    existing = await db.scalar(select(User.id).where(User.email == payload.email))
    if existing is not None:
        raise HTTPException(status_code=409, detail=EMAIL_TAKEN_DETAIL)
    user = User(
        name=payload.name,
        email=payload.email,
        password_hash=hash_password(payload.password),
        contact_number=payload.contact_number,
    )
    db.add(user)
    await db.commit()
    return TokenResponse(
        access_token=create_access_token(user.id),
        user=UserOut.model_validate(user),
    )


@router.post("/auth/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Authenticate and return an access token.

    Unknown email and wrong password are indistinguishable — same generic
    detail, same recorded failure (no user enumeration). A successful login
    resets the IP's failure counter. ``LoginRequest``'s validator lowercases
    the email, matching the stored canonical form.
    """
    ip = client_ip(request)
    if not login_limiter.allowed(ip):
        raise HTTPException(status_code=429, detail=RATE_LIMIT_DETAIL)
    user = await db.scalar(select(User).where(User.email == payload.email))
    if user is None or not verify_password(payload.password, user.password_hash):
        login_limiter.record(ip)
        raise HTTPException(status_code=401, detail=LOGIN_FAILED_DETAIL)
    login_limiter.reset(ip)
    return TokenResponse(
        access_token=create_access_token(user.id),
        user=UserOut.model_validate(user),
    )
