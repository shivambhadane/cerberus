import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DATABASE_URL", "sqlite://")
# Assigned, not defaulted: a real key exported in the developer's shell must never be what tests run with.
os.environ["API_SECRET_KEY"] = "test-secret-" + "k" * 40
# The synthetic Firebase token is an auth bypass; only the test suite may turn it on (core/firebase_auth.py).
os.environ["CERBERUS_ALLOW_TEST_TOKENS"] = "1"

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
    from api import providers as provider_routes

    auth.reset_limiters()
    domains.reset_limiters()
    provider_routes.reset_limiters()
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



@pytest.fixture
def platform_env(monkeypatch):
    """Provider credentials, an encryption key and public URLs, as an operator would configure them."""
    from cryptography.fernet import Fernet

    for key, value in {
        "PROVIDER_TOKEN_ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "PUBLIC_API_URL": "https://api.cerberus.test",
        "FRONTEND_URL": "https://app.cerberus.test",
        "VERCEL_CLIENT_ID": "oac_vercel_id", "VERCEL_CLIENT_SECRET": "vercel-client-secret",
        "VERCEL_INTEGRATION_SLUG": "cerberus-test",
        "NETLIFY_CLIENT_ID": "netlify_id", "NETLIFY_CLIENT_SECRET": "netlify-client-secret",
        "CLOUDFLARE_CLIENT_ID": "cf_id", "CLOUDFLARE_CLIENT_SECRET": "cf-client-secret",
        "CLOUDFLARE_OAUTH_SCOPES": "pages.read account.read",
    }.items():
        monkeypatch.setenv(key, value)


@pytest.fixture
def fake_http(platform_env):
    """Every provider call in the test goes here instead of the network."""
    import providers
    from tests.provider_fakes import FakeHttp

    fake = FakeHttp()
    providers.use_http(fake)
    yield fake
    providers.use_http(None)
