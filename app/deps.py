"""FastAPI dependencies: per-request DB session and the authenticated user."""

from collections.abc import AsyncIterator

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app import database
from app.models import User
from app.security import InvalidTokenError, decode_access_token

_bearer = HTTPBearer(auto_error=False)


async def get_db() -> AsyncIterator[AsyncSession]:
    """Yield one session per request from the app engine; always closed."""
    maker = async_sessionmaker(database.get_engine(), expire_on_commit=False)
    session = maker()
    try:
        yield session
    finally:
        await session.close()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Resolve the bearer token to its ``User`` row or raise 401.

    Missing, malformed and expired tokens, and tokens whose user row is
    gone, all fail with the same generic detail — no token diagnostics leak.
    """
    if credentials is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    try:
        user_id = decode_access_token(credentials.credentials)
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return user
