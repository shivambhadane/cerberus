"""Tests for Firebase Authentication token verification and user syncing in the API."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from api.main import app, get_session
from core.firebase_auth import (
    FirebaseAuthError,
    FirebaseTokenExpiredError,
    set_test_token_verifier,
)
from core.models import User


@pytest.fixture
def client(session):
    app.dependency_overrides[get_session] = lambda: session
    yield TestClient(app)
    app.dependency_overrides.clear()
    set_test_token_verifier(None)


def test_firebase_token_authenticates_and_auto_provisions_user(client, session):
    # Synthetic test token: format "test-firebase-token:<email>:<uid>"
    token = "test-firebase-token:alice@example.com:fb-uid-123"
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    body = response.json()
    assert body["email"] == "alice@example.com"
    assert body["email_verified"] is True

    # Check that user row was committed in the database
    user = session.scalar(select(User).where(User.email == "alice@example.com"))
    assert user is not None
    assert user.id == "fb-uid-123"
    assert user.is_active is True
    assert user.password_hash == "firebase_managed"


def test_firebase_token_links_existing_user_by_email(client, session, make_user):
    # Existing user created prior to Firebase migration
    existing = make_user("bob@example.com", name="Bob Existing", password_hash="$argon2id$somehash")
    existing_id = existing.id

    token = "test-firebase-token:bob@example.com:firebase-bob-uid"
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    body = response.json()
    assert body["email"] == "bob@example.com"
    assert body["id"] == existing_id  # Preserves existing primary key and domain ownership


def test_firebase_token_rejects_inactive_user(client, session, make_user):
    make_user("disabled@example.com", is_active=False)

    token = "test-firebase-token:disabled@example.com:uid-disabled"
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


def test_expired_firebase_token_raises_token_expired(client):
    def verifier(token: str):
        if token == "expired-fb-token":
            raise FirebaseTokenExpiredError("Token expired")
        return None

    set_test_token_verifier(verifier)
    response = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer expired-fb-token"})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "token_expired"


def test_invalid_firebase_token_falls_through_to_unauthorized(client):
    def verifier(token: str):
        if token == "invalid-fb-token":
            raise FirebaseAuthError("Invalid signature")
        return None

    set_test_token_verifier(verifier)
    response = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer invalid-fb-token"})
    assert response.status_code == 401
    assert response.json()["error"]["code"] in ("token_invalid", "unauthorized")


# --- the synthetic test token is an auth bypass unless explicitly enabled --------------------------

def test_the_synthetic_token_is_refused_unless_tests_enabled_it(client, session, make_user, monkeypatch):
    """Regression: `test-firebase-token:<email>:<uid>` once authenticated anyone as any email address,
    and linked to an existing account by email, which was a full account takeover."""
    victim = make_user("victim@example.com", name="Victim")
    monkeypatch.delenv("CERBERUS_ALLOW_TEST_TOKENS", raising=False)

    forged = {"Authorization": "Bearer test-firebase-token:victim@example.com:attacker-uid"}
    response = client.get("/api/v1/auth/me", headers=forged)

    assert response.status_code == 401
    assert session.scalar(select(User).where(User.email == "victim@example.com")).id == victim.id
    # and it did not create an account for an address nobody proved they own
    fresh = {"Authorization": "Bearer test-firebase-token:nobody@example.com:x"}
    assert client.get("/api/v1/auth/me", headers=fresh).status_code == 401
    assert session.scalar(select(User).where(User.email == "nobody@example.com")) is None


def test_the_synthetic_token_works_only_when_the_test_suite_enables_it(client, monkeypatch):
    monkeypatch.setenv("CERBERUS_ALLOW_TEST_TOKENS", "1")
    token = "test-firebase-token:t@example.com:t1"
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200
