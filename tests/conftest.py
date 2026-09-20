import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DATABASE_URL", "sqlite://")
# Assigned, not defaulted: a real key exported in the developer's shell must never be what tests run with.
os.environ["API_SECRET_KEY"] = "test-secret-" + "k" * 40

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from core.models import Base, User


@pytest.fixture
def session():
    # StaticPool + check_same_thread keeps one in-memory database usable from the
    # TestClient's worker thread as well as the test thread.
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    maker = sessionmaker(bind=engine, expire_on_commit=False)
    with maker() as s:
        yield s


@pytest.fixture(autouse=True)
def _fresh_rate_limits():
    """The sign-in and verification throttles are process-wide; each test starts with none spent."""
    from api import auth, domains

    auth.reset_limiters()
    domains.reset_limiters()
    yield


@pytest.fixture
def make_user(session):
    """Create a user directly (skipping the slow password hash unless a test needs a real one)."""

    def make(email: str = "owner@example.com", **fields) -> User:
        user = User(email=email, password_hash=fields.pop("password_hash", "x"), **fields)
        session.add(user)
        session.flush()
        return user

    return make

