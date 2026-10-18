from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from app.config import get_database_url

_engine: AsyncEngine | None = None


def sanitize_database_url(url: str) -> str:
    """Make a Postgres URL safe for the asyncpg dialect behind PgBouncer.

    - strips surrounding whitespace
    - drops any ``channel_binding`` query param (rejected by many poolers)
    - forces ``prepared_statement_cache_size=0`` (Neon pooler-safe)
    - rewrites ``postgresql://`` / ``postgres://`` -> ``postgresql+asyncpg://``
    - keeps every other query param untouched
    - idempotent: sanitizing an already-sanitized URL returns it unchanged
    """
    url = url.strip()
    parts = urlsplit(url)

    scheme = parts.scheme
    if scheme in ("postgresql", "postgres"):
        scheme = "postgresql+asyncpg"

    query: list[tuple[str, str]] = []
    seen_prepared_statement_cache_size = False
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key == "channel_binding":
            continue
        if key == "prepared_statement_cache_size":
            if not seen_prepared_statement_cache_size:
                query.append((key, "0"))
                seen_prepared_statement_cache_size = True
            continue
        query.append((key, value))
    if not seen_prepared_statement_cache_size:
        query.append(("prepared_statement_cache_size", "0"))

    return urlunsplit(
        (scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
    )


def _to_asyncpg_connect_url(url: str) -> str:
    """Translate libpq ``sslmode=`` into asyncpg's ``ssl=`` connect argument.

    SQLAlchemy's asyncpg dialect forwards every URL query parameter to
    ``asyncpg.connect()`` as a keyword argument, and asyncpg has no ``sslmode``
    keyword (it only parses ``sslmode`` inside DSN strings). asyncpg's ``ssl``
    keyword does accept libpq-style strings (``require``, ``verify-full``, ...),
    so swap the parameter name while keeping its value. Applied only here —
    ``sanitize_database_url`` keeps ``sslmode`` untouched by design.
    """
    parts = urlsplit(url)
    query: list[tuple[str, str]] = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key == "sslmode":
            query.append(("ssl", value))
        else:
            query.append((key, value))
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
    )


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            _to_asyncpg_connect_url(sanitize_database_url(get_database_url())),
            poolclass=NullPool,
            connect_args={"statement_cache_size": 0},
        )
    return _engine


async def ping_db() -> None:
    async with get_engine().connect() as conn:
        await conn.execute(text("SELECT 1"))
