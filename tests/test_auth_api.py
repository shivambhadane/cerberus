"""Registration, sign-in, refresh-token rotation, sign-out. The session guarantees, tested end to end."""

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from api.auth import REFRESH_COOKIE
from api.main import app, get_session
from core.models import AuthSession, User, utcnow
from core.security import hash_password

PASSWORD = "correct horse battery staple"
BASE = "/api/v1/auth"


@pytest.fixture
def client(session):
    app.dependency_overrides[get_session] = lambda: session
    yield TestClient(app)
    app.dependency_overrides.clear()


def register(client, email="Shivam@Example.com", password=PASSWORD, name="Shivam", **kw):
    return client.post(f"{BASE}/register", json={"email": email, "password": password, "name": name}, **kw)


def login(client, email="shivam@example.com", password=PASSWORD, **kw):
    return client.post(f"{BASE}/login", json={"email": email, "password": password}, **kw)


def bearer(response) -> dict[str, str]:
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


# --- registration ---------------------------------------------------------------------------

def test_registering_creates_an_account_and_signs_in(client, session):
    response = register(client)
    assert response.status_code == 201
    body = response.json()
    assert body["user"]["email"] == "shivam@example.com"  # normalised
    assert body["user"]["name"] == "Shivam" and body["user"]["email_verified"] is False
    assert body["token_type"] == "bearer" and body["expires_in"] == 15 * 60
    assert client.get(f"{BASE}/me", headers=bearer(response)).json()["email"] == "shivam@example.com"


def test_the_password_is_stored_as_an_argon2id_hash_and_never_returned(client, session):
    body = register(client).json()
    stored = session.scalar(select(User)).password_hash
    assert stored.startswith("$argon2id$") and PASSWORD not in stored
    assert PASSWORD not in str(body) and "password" not in str(body).lower().replace("password_", "")
    assert "hash" not in str(body).lower()


def test_the_refresh_token_is_an_httponly_samesite_cookie_scoped_to_auth(client):
    header = register(client).headers["set-cookie"].lower()
    assert f"{REFRESH_COOKIE}=" in header
    assert "httponly" in header and "samesite=lax" in header and "path=/api/v1/auth" in header
    assert "max-age=1209600" in header  # 14 days


def test_the_cookie_is_marked_secure_when_configured(client, monkeypatch):
    monkeypatch.setenv("COOKIE_SECURE", "1")
    assert "secure" in register(client).headers["set-cookie"].lower()


def test_the_refresh_token_never_appears_in_the_response_body(client):
    response = register(client)
    raw = client.cookies.get(REFRESH_COOKIE)
    assert raw and raw not in response.text


def test_only_a_hash_of_the_refresh_token_is_stored(client, session):
    register(client)
    raw = client.cookies.get(REFRESH_COOKIE)
    stored = session.scalar(select(AuthSession)).token_hash
    assert stored != raw and raw not in stored and len(stored) == 64


def test_the_same_email_cannot_register_twice_even_in_another_case(client):
    assert register(client).status_code == 201
    duplicate = register(client, email="SHIVAM@EXAMPLE.COM")
    assert duplicate.status_code == 409 and duplicate.json()["error"]["code"] == "email_taken"


@pytest.mark.parametrize("password,fragment", [
    ("tiny", "at least"),
    ("a" * 200, "at most"),
    ("shivam@example.com", "email"),
])
def test_weak_passwords_are_refused_with_a_reason(client, password, fragment):
    response = register(client, password=password)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "weak_password"
    assert fragment in response.json()["error"]["message"]


@pytest.mark.parametrize("email", ["", "nope", "a@b", "a b@c.com", "@c.com"])
def test_invalid_emails_are_refused(client, email):
    response = register(client, email=email)
    assert response.status_code in (400, 422)


def test_registration_is_rate_limited_per_address(client):
    statuses = [register(client, email=f"user{i}@example.com").status_code for i in range(11)]
    assert statuses[:10] == [201] * 10
    assert statuses[10] == 429


# --- sign-in --------------------------------------------------------------------------------

def test_the_right_password_signs_in_and_records_the_time(client, session):
    register(client)
    fresh = TestClient(app)  # a different browser
    response = login(fresh)
    assert response.status_code == 200 and response.json()["access_token"]
    assert session.scalar(select(User)).last_login_at is not None


def test_email_case_does_not_matter_at_sign_in(client):
    register(client)
    assert login(TestClient(app), email="  SHIVAM@example.COM ").status_code == 200


def test_wrong_password_unknown_email_and_disabled_account_are_indistinguishable(client, session):
    register(client)
    session.scalar(select(User)).is_active = True
    session.flush()
    wrong = login(client, password="not the password at all")
    unknown = login(client, email="nobody@example.com")
    session.scalar(select(User)).is_active = False
    session.flush()
    disabled = login(client)
    for response in (wrong, unknown, disabled):
        assert response.status_code == 401
    assert wrong.json() == unknown.json() == disabled.json()
    assert wrong.json()["error"]["code"] == "invalid_credentials"


def test_repeated_failures_lock_that_account_out_for_a_while(client):
    register(client)
    fresh = TestClient(app)
    for _ in range(5):
        assert login(fresh, password="wrong wrong wrong wrong").status_code == 401
    locked = login(fresh)  # even the right password is refused while locked
    assert locked.status_code == 429
    assert locked.json()["error"]["code"] == "too_many_attempts"
    assert int(locked.headers["retry-after"]) > 0


def test_lockout_is_per_account_not_global(client):
    register(client)
    register(client, email="other@example.com")
    fresh = TestClient(app)
    for _ in range(5):
        login(fresh, password="wrong wrong wrong wrong")
    assert login(fresh, email="other@example.com").status_code == 200


def test_a_success_clears_the_failure_count(client):
    register(client)
    fresh = TestClient(app)
    for _ in range(4):
        login(fresh, password="wrong wrong wrong wrong")
    assert login(fresh).status_code == 200
    for _ in range(4):  # another four are allowed, because the count restarted
        assert login(fresh, password="wrong wrong wrong wrong").status_code == 401


def test_many_different_accounts_from_one_address_are_throttled_too(client):
    """Spreading guesses across accounts must not dodge the per-account limit."""
    fresh = TestClient(app)
    codes = [login(fresh, email=f"nobody{i}@example.com", password="wrong wrong wrong").status_code
             for i in range(31)]
    assert codes[:30] == [401] * 30 and codes[30] == 429


def test_a_weaker_stored_hash_is_upgraded_at_sign_in(client, session):
    from argon2 import PasswordHasher

    register(client)
    user = session.scalar(select(User))
    user.password_hash = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(PASSWORD)
    session.flush()
    weak = user.password_hash
    assert login(TestClient(app)).status_code == 200
    assert user.password_hash != weak and user.password_hash.startswith("$argon2id$")


def test_a_malformed_stored_hash_is_a_failed_login_not_a_server_error(client, session):
    register(client)
    session.scalar(select(User)).password_hash = "garbage"
    session.flush()
    assert login(TestClient(app)).status_code == 401


# --- origin check ---------------------------------------------------------------------------

def test_a_request_from_an_unlisted_origin_is_refused(client):
    for path in ("register", "login", "refresh", "logout"):
        response = client.post(f"{BASE}/{path}", json={"email": "a@b.co", "password": "x" * 12},
                               headers={"Origin": "https://evil.example"})
        assert response.status_code == 403, path
        assert response.json()["error"]["code"] == "forbidden_origin"


def test_the_dashboards_own_origin_is_allowed(client):
    response = register(client, headers={"Origin": "http://localhost:5173"})
    assert response.status_code == 201
    assert response.headers["access-control-allow-credentials"] == "true"
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


# --- refresh: rotation and theft detection --------------------------------------------------

def test_refreshing_returns_a_new_access_token_and_rotates_the_cookie(client, session):
    register(client)
    before = client.cookies.get(REFRESH_COOKIE)
    response = client.post(f"{BASE}/refresh")
    assert response.status_code == 200 and response.json()["access_token"]
    assert client.cookies.get(REFRESH_COOKIE) != before
    rows = session.scalars(select(AuthSession).order_by(AuthSession.created_at)).all()
    assert len(rows) == 2 and rows[0].rotated_at is not None and rows[1].rotated_at is None
    assert rows[0].revoked_at is None and rows[1].revoked_at is None  # rotated is not revoked
    assert rows[0].family_id == rows[1].family_id  # one login, one family


def test_a_refreshed_token_authenticates(client):
    register(client)
    refreshed = client.post(f"{BASE}/refresh")
    assert client.get(f"{BASE}/me", headers=bearer(refreshed)).status_code == 200


def test_refreshing_without_a_cookie_says_to_sign_in(client):
    response = client.post(f"{BASE}/refresh")
    assert response.status_code == 401 and response.json()["error"]["code"] == "no_session"


def test_an_unknown_cookie_is_refused_and_cleared(client):
    client.cookies.set(REFRESH_COOKIE, "not-a-real-token", path="/api/v1/auth")
    response = client.post(f"{BASE}/refresh")
    assert response.status_code == 401 and response.json()["error"]["code"] == "invalid_session"
    assert "max-age=0" in response.headers["set-cookie"].lower()


def test_an_expired_session_cannot_refresh(client, session):
    register(client)
    session.scalar(select(AuthSession)).expires_at = utcnow() - timedelta(seconds=1)
    session.flush()
    response = client.post(f"{BASE}/refresh")
    assert response.status_code == 401 and response.json()["error"]["code"] == "session_expired"


def test_replaying_a_rotated_out_token_revokes_the_whole_login(client, session):
    """The theft case: an attacker holds a copy of a token that was since used. When it turns up,
    both parties are signed out, because they cannot both be the user."""
    register(client)
    stolen = client.cookies.get(REFRESH_COOKIE)
    assert client.post(f"{BASE}/refresh").status_code == 200  # the real user rotates it
    for row in session.scalars(select(AuthSession)):  # ...and the leeway for races has long passed
        if row.rotated_at:
            row.rotated_at = utcnow() - timedelta(minutes=5)
    session.flush()

    attacker = TestClient(app)
    attacker.cookies.set(REFRESH_COOKIE, stolen, path="/api/v1/auth")
    replay = attacker.post(f"{BASE}/refresh")
    assert replay.status_code == 401 and replay.json()["error"]["code"] == "session_revoked"

    # The real user's newest token died with the family, immediately: a revoked token gets no
    # leeway (regression: the race allowance once let a just-revoked token through).
    assert client.post(f"{BASE}/refresh").status_code == 401
    assert all(row.revoked_at is not None for row in session.scalars(select(AuthSession)))


def test_two_tabs_refreshing_at_the_same_instant_are_not_mistaken_for_theft(client, session):
    register(client)
    shared = client.cookies.get(REFRESH_COOKIE)
    assert client.post(f"{BASE}/refresh").status_code == 200  # tab A

    tab_b = TestClient(app)  # tab B still holds the cookie A just replaced
    tab_b.cookies.set(REFRESH_COOKIE, shared, path="/api/v1/auth")
    assert tab_b.post(f"{BASE}/refresh").status_code == 200


def test_a_disabled_account_cannot_refresh(client, session):
    register(client)
    session.scalar(select(User)).is_active = False
    session.flush()
    assert client.post(f"{BASE}/refresh").status_code == 401


# --- sign-out --------------------------------------------------------------------------------

def test_signing_out_ends_the_login_and_clears_the_cookie(client, session):
    register(client)
    response = client.post(f"{BASE}/logout")
    assert response.status_code == 204 and "max-age=0" in response.headers["set-cookie"].lower()
    assert all(row.revoked_at is not None for row in session.scalars(select(AuthSession)))
    client.cookies.set(REFRESH_COOKIE, "still-have-the-old-one", path="/api/v1/auth")
    assert client.post(f"{BASE}/refresh").status_code == 401


def test_a_token_copied_before_sign_out_cannot_refresh_afterwards(client):
    register(client)
    copy = client.cookies.get(REFRESH_COOKIE)
    client.post(f"{BASE}/logout")
    thief = TestClient(app)
    thief.cookies.set(REFRESH_COOKIE, copy, path="/api/v1/auth")
    assert thief.post(f"{BASE}/refresh").status_code == 401


def test_signing_out_twice_is_fine(client):
    register(client)
    assert client.post(f"{BASE}/logout").status_code == 204
    assert client.post(f"{BASE}/logout").status_code == 204
    assert TestClient(app).post(f"{BASE}/logout").status_code == 204


def test_signing_out_one_login_leaves_another_alone(client, session):
    register(client)
    other_device = TestClient(app)
    assert login(other_device).status_code == 200
    client.post(f"{BASE}/logout")
    assert other_device.post(f"{BASE}/refresh").status_code == 200


# --- who am I -------------------------------------------------------------------------------

def test_me_needs_a_token(client):
    assert client.get(f"{BASE}/me").status_code == 401


def test_me_reports_only_public_fields(client):
    body = client.get(f"{BASE}/me", headers=bearer(register(client))).json()
    assert set(body) == {"id", "email", "name", "email_verified", "created_at"}


def test_an_existing_hash_still_verifies_after_a_restart(client, session, make_user):
    """Hashes are self-describing, so accounts created under any earlier settings keep working."""
    make_user("legacy@example.com", password_hash=hash_password(PASSWORD))
    assert login(TestClient(app), email="legacy@example.com").status_code == 200


def test_a_revoked_token_gets_no_leeway_even_if_revoked_a_moment_ago(client, session):
    """The two-tab leeway is for *rotation*. After sign-out the token is dead at once."""
    register(client)
    copy = client.cookies.get(REFRESH_COOKIE)
    client.post(f"{BASE}/logout")  # revoked a fraction of a second ago
    thief = TestClient(app)
    thief.cookies.set(REFRESH_COOKIE, copy, path="/api/v1/auth")
    assert thief.post(f"{BASE}/refresh").json()["error"]["code"] == "session_revoked"
