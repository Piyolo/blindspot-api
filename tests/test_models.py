import pytest
from sqlalchemy.exc import IntegrityError

from app.models import User


async def test_user_row_round_trips_with_timezone_created_at(db_session):
    user = User(
        name="Ana",
        email="ana@example.com",
        password_hash="x",
        contact_number="+639171234567",
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    assert user.id is not None and user.created_at.tzinfo is not None


async def test_email_is_unique(db_session):
    db_session.add(
        User(name="Ana", email="dup@example.com", password_hash="x", contact_number="09171234567")
    )
    await db_session.commit()
    db_session.add(
        User(name="Bo", email="dup@example.com", password_hash="y", contact_number="09181234567")
    )
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()
