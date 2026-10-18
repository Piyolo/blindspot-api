from app.database import sanitize_database_url

POOLED = (
    "postgresql://neondb_owner:pw@ep-xxx-pooler.aws.neon.tech/neondb"
    "?sslmode=require&channel_binding=require"
)


def test_sanitize_strips_channel_binding():
    assert "channel_binding" not in sanitize_database_url(POOLED)


def test_sanitize_converts_scheme_to_asyncpg():
    assert sanitize_database_url(POOLED).startswith("postgresql+asyncpg://")


def test_sanitize_preserves_sslmode():
    assert "sslmode=require" in sanitize_database_url(POOLED)


def test_sanitize_forces_prepared_statement_cache_off():
    assert "prepared_statement_cache_size=0" in sanitize_database_url(POOLED)


def test_sanitize_idempotent():
    once = sanitize_database_url(POOLED)
    assert sanitize_database_url(once) == once
