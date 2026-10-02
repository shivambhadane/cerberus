"""The Google profile: name and picture come from the verified token, and an email address is only
allowed to claim an existing account once the provider has verified it."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from api.main import app, get_session
from core.firebase_auth import set_test_token_verifier
from core.models import User
from core.profile import clean_display_name, clean_picture_url, sign_in_provider

PHOTO = "https://lh3.googleusercontent.com/a/ACg8ocKexample=s96-c"


@pytest.fixture
def client(session):
    app.dependency_overrides[get_session] = lambda: session
    yield TestClient(app)
    app.dependency_overrides.clear()
    set_test_token_verifier(None)


def sign_in_as(client, **claims):
    """Present a token whose *verified* payload is `claims` (the verifier is injected, as in Firebase)."""
    payload = {"sub": "g-uid-1", "uid": "g-uid-1", "email": "ada@example.com", "email_verified": True,
               "name": "Ada Lovelace", "picture": PHOTO, "firebase": {"sign_in_provider": "google.com"}}
    payload.update(claims)
    set_test_token_verifier(lambda token: payload)
    return client.get("/api/v1/auth/me", headers={"Authorization": "Bearer opaque-provider-token"})


# --- what is kept from a provider profile ---------------------------------------------------------

@pytest.mark.parametrize("url", [
    "javascript:alert(1)", "data:image/png;base64,AAAA", "http://lh3.googleusercontent.com/x",
    "//lh3.googleusercontent.com/x", "https://user:pw@evil.example/x.png", "https://",
    "https://ok.example/a b.png", "https://ok.example/\\x", "", "   ", None, 42, "x" * 3000,
])
def test_only_a_plain_https_picture_is_kept(url):
    assert clean_picture_url(url) is None


def test_a_google_photo_url_is_kept_as_is():
    assert clean_picture_url(PHOTO) == PHOTO
    assert clean_picture_url("  " + PHOTO + "  ") == PHOTO


def test_names_are_trimmed_collapsed_and_bounded():
    assert clean_display_name("  Ada   Lovelace \n") == "Ada Lovelace"
    assert len(clean_display_name("x" * 1000)) == 255
    assert clean_display_name(None) == "" and clean_display_name(7) == ""


def test_only_known_sign_in_methods_are_recorded():
    assert sign_in_provider({"firebase": {"sign_in_provider": "google.com"}}) == "google.com"
    assert sign_in_provider({"firebase": {"sign_in_provider": "evil<script>"}}) is None
    assert sign_in_provider({"firebase": "not-a-dict"}) is None and sign_in_provider({}) is None


# --- the profile arrives with the first sign-in ---------------------------------------------------

def test_first_google_sign_in_records_name_picture_and_method(client, session):
    body = sign_in_as(client).json()
    assert body["name"] == "Ada Lovelace" and body["picture_url"] == PHOTO
    assert body["auth_provider"] == "google.com" and body["email_verified"] is True
    assert body["last_login_at"]
    row = session.scalar(select(User).where(User.email == "ada@example.com"))
    assert row.picture_url == PHOTO and row.auth_provider == "google.com"


def test_a_hostile_picture_url_is_dropped_not_stored(client, session):
    body = sign_in_as(client, picture="javascript:alert(document.cookie)").json()
    assert body["picture_url"] is None
    assert session.scalar(select(User)).picture_url is None


def test_a_changed_google_photo_follows_the_provider(client, session):
    sign_in_as(client)
    new = "https://lh3.googleusercontent.com/a/ACg8ocNEW=s96-c"
    assert sign_in_as(client, picture=new).json()["picture_url"] == new


def test_a_missing_photo_does_not_erase_the_one_we_have(client):
    sign_in_as(client)
    assert sign_in_as(client, picture=None).json()["picture_url"] == PHOTO


def test_a_name_the_person_set_is_not_overwritten_by_the_provider(client, session):
    sign_in_as(client)
    session.scalar(select(User)).name = "Countess Ada"
    session.flush()
    assert sign_in_as(client, name="Ada Lovelace").json()["name"] == "Countess Ada"


def test_a_name_is_filled_in_when_we_had_none(client, session, make_user):
    make_user("ada@example.com", name="", email_verified=True)
    session.flush()
    assert sign_in_as(client, sub="local", uid="local").json()["name"] == "Ada Lovelace"


def test_the_profile_never_exposes_credentials(client):
    body = sign_in_as(client).json()
    assert set(body) == {"id", "email", "name", "email_verified", "created_at", "last_login_at",
                         "picture_url", "auth_provider", "is_admin"}


# --- an email address must be verified before it can claim an account -----------------------------

def test_an_unverified_email_cannot_take_over_an_existing_account(client, session, make_user):
    """Firebase lets anyone sign up with any address, unverified. Linking by address alone would hand
    the victim's account (and every scan in it) to whoever typed the address."""
    victim = make_user("victim@example.com", name="Victim")
    response = sign_in_as(client, sub="attacker-uid", uid="attacker-uid", email="victim@example.com",
                          email_verified=False, firebase={"sign_in_provider": "password"})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "email_not_verified"
    assert session.scalar(select(User).where(User.email == "victim@example.com")).id == victim.id


def test_a_verified_email_may_claim_the_existing_account(client, session, make_user):
    existing = make_user("ada@example.com", name="Ada")
    body = sign_in_as(client, sub="g-new", uid="g-new").json()
    assert body["id"] == existing.id and body["picture_url"] == PHOTO


def test_an_unverified_account_can_still_use_itself(client):
    """Signing up unverified is allowed; the same person can keep using the account they created."""
    args = dict(sub="me", uid="me", email="new@example.com", email_verified=False,
                firebase={"sign_in_provider": "password"}, picture=None)
    assert sign_in_as(client, **args).status_code == 200
    assert sign_in_as(client, **args).status_code == 200
