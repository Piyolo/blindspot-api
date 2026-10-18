"""Async test fixtures: in-memory SQLite engine/session and an ASGI test client.

No fixture here touches ``DATABASE_URL`` or any real environment variable —
the app engine is replaced by a function-scoped ``sqlite+aiosqlite`` in-memory
engine, and tables are created on that engine (``app.main``'s lifespan only
runs under a real server, never under ``httpx.ASGITransport``).
"""

import httpx
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.main import app
from app.models import Base
from app.rate_limit import login_limiter, signup_limiter

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture
async def db_engine():
    engine = create_async_engine(
        TEST_DATABASE_URL,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def db_session(db_engine):
    maker = async_sessionmaker(db_engine, expire_on_commit=False)
    async with maker() as session:
        yield session


@pytest.fixture
async def client(db_engine, monkeypatch):
    # db_engine: schema exists on the test engine. Route sessions come from
    # app.deps.get_db -> database.get_engine, so point the app engine at the
    # test engine and both share the same in-memory SQLite database.
    monkeypatch.setattr("app.database.get_engine", lambda: db_engine)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as test_client:
        yield test_client


@pytest.fixture
async def auth_headers(client):
    """Bearer headers for a freshly signed-up user (Task 4's ``auth_headers``).

    Signs the user up through the real signup route, so the token is a real
    HS256 token for a real row. ``client`` points the app engine at the test
    engine, and the autouse ``_reset_limiters`` fixture keeps the shared IP's
    signup quota clean, so every test may sign up once. JWT signing needs
    ``JWT_SECRET`` — each module that uses this fixture sets it via its own
    autouse ``jwt_secret`` fixture (same pattern as ``test_auth.py``).
    """
    response = await client.post(
        "/api/v1/auth/signup",
        json={
            "name": "Maria Santos",
            "email": "maria@example.com",
            "password": "password123",
            "contact_number": "0917 123 4567",
        },
    )
    assert response.status_code == 201
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture(autouse=True)
def _reset_limiters():
    """Clear both in-memory failure limiters before every test.

    Every test shares one client IP, and later fixtures (Task 4's
    ``auth_headers``) sign up repeatedly — without this reset, unrelated
    tests would trip the 429s.
    """
    login_limiter.reset()
    signup_limiter.reset()
