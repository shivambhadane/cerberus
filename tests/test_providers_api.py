"""Connecting a platform account: the OAuth flow's security, and the lifecycle of a connection."""

import base64
import hashlib
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

import providers
from api.main import app, get_session
from core.crypto import get_cipher
from core.models import OAuthState, utcnow
from tests.helpers import auth_for
from tests.provider_fakes import CF_ACCOUNT, cloudflare_routes, netlify_routes, vercel_routes
from tests.provider_helpers import V1, begin, browser, connect, connections, finish, outcome


@pytest.fixture
def world(session, make_user, fake_http):
    app.dependency_overrides[get_session] = lambda: session
    alice, bob = make_user("alice@example.com"), make_user("bob@example.com")
    vercel_routes(fake_http)
    netlify_routes(fake_http)
    cloudflare_routes(fake_http)
    yield {"session": session, "alice": alice, "bob": bob, "http": fake_http}
    app.dependency_overrides.clear()


# --- starting a connection ------------------------------------------------------------------------


def test_starting_needs_a_signed_in_user(world):
    assert TestClient(app).post(f"{V1}/providers/vercel/connect").status_code == 401


def test_starting_returns_only_the_providers_url_and_sets_a_browser_cookie(world):
    client = browser(world["alice"])
    response = client.post(f"{V1}/providers/netlify/connect")
    assert response.status_code == 200 and set(response.json()) == {"authorization_url"}
    assert response.json()["authorization_url"].startswith("https://app.netlify.com/authorize?")
    assert "netlify-client-secret" not in response.text  # the client secret never leaves the server
    cookie = response.headers["set-cookie"].lower()
    assert "cerberus_oauth=" in cookie and "httponly" in cookie
    assert "samesite=lax" in cookie and "path=/api/v1/providers" in cookie and "max-age=600" in cookie


def test_the_redirect_uri_is_exact_and_never_taken_from_the_request(world):
    url, _ = begin(browser(world["alice"]), "netlify")
    assert parse_qs(urlsplit(url).query)["redirect_uri"] == [
        "https://api.cerberus.test/api/v1/providers/netlify/callback"
    ]
    hostile = browser(world["alice"]).post(
        f"{V1}/providers/netlify/connect",
        headers={
            **auth_for(world["alice"]),
            "Host": "evil.example",
            "Origin": "https://evil.example",
            "Referer": "https://evil.example",
        },
    )
    assert "evil.example" not in hostile.json()["authorization_url"]


def test_every_flow_gets_its_own_unguessable_state(world):
    states = {begin(browser(world["alice"]))[1] for _ in range(5)}
    assert len(states) == 5 and all(len(s) >= 40 for s in states)


def test_only_hashes_are_stored_so_the_table_cannot_complete_a_flow(world):
    client = browser(world["alice"])
    _, state = begin(client)
    row = world["session"].scalar(select(OAuthState))
    nonce = client.cookies.get("cerberus_oauth")
    assert state not in (row.state_hash, row.browser_hash) and nonce not in (row.state_hash, row.browser_hash)
    assert len(row.state_hash) == len(row.browser_hash) == 64


def test_an_unknown_provider_is_a_404(world):
    assert browser(world["alice"]).post(f"{V1}/providers/github/connect").status_code == 404
    assert (
        browser(world["alice"])
        .get(f"{V1}/providers/github/callback", params={"code": "c", "state": "s"})
        .status_code
        == 404
    )


def test_a_provider_the_operator_has_not_set_up_says_so(world, monkeypatch):
    monkeypatch.setenv("NETLIFY_CLIENT_SECRET", "")
    response = browser(world["alice"]).post(f"{V1}/providers/netlify/connect")
    assert response.status_code == 503 and response.json()["error"]["code"] == "provider_not_configured"
    listed = {
        p["provider"]: p["configured"]
        for p in browser(world["alice"]).get(f"{V1}/providers").json()["providers"]
    }
    assert listed == {"vercel": True, "netlify": False, "cloudflare": True}


def test_without_an_encryption_key_nothing_is_stored_in_the_clear(world, monkeypatch):
    """No key means no connections at all, never connections with plaintext tokens."""
    monkeypatch.delenv("PROVIDER_TOKEN_ENCRYPTION_KEY")
    response = browser(world["alice"]).post(f"{V1}/providers/vercel/connect")
    assert response.status_code == 503 and response.json()["error"]["code"] == "provider_not_configured"
    assert all(
        not p["configured"] for p in browser(world["alice"]).get(f"{V1}/providers").json()["providers"]
    )


def test_there_is_a_cap_on_unfinished_attempts(world):
    client = browser(world["alice"])
    for _ in range(10):
        begin(client)
    response = client.post(f"{V1}/providers/vercel/connect")
    assert response.status_code == 429 and response.json()["error"]["code"] == "too_many_pending"


def test_cloudflare_pkce_challenge_matches_the_stored_verifier(world):
    client = browser(world["alice"])
    url, _ = begin(client, "cloudflare")
    challenge = parse_qs(urlsplit(url).query)["code_challenge"][0]
    row = world["session"].scalar(select(OAuthState))
    verifier = get_cipher().decrypt(row.code_verifier_encrypted, row.id)
    assert (
        challenge
        == base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    assert verifier not in row.code_verifier_encrypted  # stored sealed, not readable from the table


# --- the callback: what must be refused -----------------------------------------------------------


def refused(response, world):
    assert outcome(response) == {"provider": outcome(response)["provider"], "error": "invalid_state"}
    assert connections(world["session"]) == []
    assert not world["http"].calls_to("oauth")  # no provider call was made on a refused callback


def test_a_callback_with_no_state_is_refused(world):
    client = browser(world["alice"])
    begin(client)
    refused(finish(client, "vercel", None), world)


def test_a_callback_with_no_code_is_refused(world):
    client = browser(world["alice"])
    _, state = begin(client)
    refused(finish(client, "vercel", state, code=None), world)


def test_a_callback_with_an_invented_state_is_refused(world):
    client = browser(world["alice"])
    begin(client)
    refused(finish(client, "vercel", "state-i-made-up"), world)


def test_a_callback_from_a_browser_that_never_started_the_flow_is_refused(world):
    """A link forwarded to someone else: their browser has no cookie."""
    _, state = begin(browser(world["alice"]))
    refused(finish(TestClient(app), "vercel", state), world)


def test_a_callback_for_another_users_flow_is_refused(world):
    """Bob starts a flow of his own (so his browser holds a real cookie), then presents Alice's state."""
    _, alices_state = begin(browser(world["alice"]))
    bob = browser(world["bob"])
    begin(bob)
    refused(finish(bob, "vercel", alices_state), world)
    assert all(c.user_id != world["bob"].id for c in connections(world["session"]))


def test_a_wrong_cookie_value_is_refused(world):
    alice = browser(world["alice"])
    _, state = begin(alice)
    alice.cookies.set("cerberus_oauth", "x" * 43, path="/api/v1/providers")
    refused(finish(alice, "vercel", state), world)


def test_a_state_started_for_one_provider_cannot_complete_another(world):
    alice = browser(world["alice"])
    _, state = begin(alice, "vercel")
    refused(finish(alice, "netlify", state), world)


def test_an_expired_state_is_refused(world):
    alice = browser(world["alice"])
    _, state = begin(alice)
    world["session"].scalar(select(OAuthState)).expires_at = utcnow() - timedelta(seconds=1)
    world["session"].flush()
    refused(finish(alice, "vercel", state), world)


def test_a_state_works_once_and_a_replay_is_refused(world):
    alice = browser(world["alice"])
    _, state = begin(alice)
    assert outcome(finish(alice, "vercel", state))["connected"] == "1"
    assert len(world["http"].calls_to("/v2/oauth/access_token")) == 1
    replay = finish(alice, "vercel", state)
    assert outcome(replay)["error"] == "invalid_state"
    assert len(world["http"].calls_to("/v2/oauth/access_token")) == 1  # no second exchange
    assert len(connections(world["session"])) == 1


def test_a_state_is_burned_even_when_the_exchange_fails(world):
    alice = browser(world["alice"])
    _, state = begin(alice)
    world["http"].route(
        "POST", "https://api.vercel.com/v2/oauth/access_token", (400, {"error": "invalid_grant"})
    )
    assert outcome(finish(alice, "vercel", state, code="bad"))["error"] == "authorization_failed"
    world["http"].route("POST", "https://api.vercel.com/v2/oauth/access_token", (200, {"access_token": "t"}))
    assert (
        outcome(finish(alice, "vercel", state, code="good"))["error"] == "invalid_state"
    )  # no second chance


def test_a_disabled_account_cannot_complete_a_flow(world):
    alice = browser(world["alice"])
    _, state = begin(alice)
    world["alice"].is_active = False
    world["session"].flush()
    assert outcome(finish(alice, "vercel", state))["error"] == "invalid_state"


def test_the_provider_denying_consent_stores_nothing(world):
    alice = browser(world["alice"])
    begin(alice)
    response = alice.get(
        f"{V1}/providers/vercel/callback", params={"error": "access_denied"}, follow_redirects=False
    )
    assert outcome(response)["error"] == "access_denied" and connections(world["session"]) == []


def test_an_authorization_code_the_provider_rejects_is_reported_and_stores_nothing(world):
    alice = browser(world["alice"])
    _, state = begin(alice)
    world["http"].route(
        "POST", "https://api.vercel.com/v2/oauth/access_token", (400, {"error": "invalid_grant"})
    )
    assert outcome(finish(alice, "vercel", state, code="forged"))["error"] == "authorization_failed"
    assert connections(world["session"]) == []


def test_a_provider_outage_during_the_exchange_is_handled(world):
    alice = browser(world["alice"])
    _, state = begin(alice)
    world["http"].route("POST", "https://api.vercel.com/v2/oauth/access_token", (503, {}))
    assert outcome(finish(alice, "vercel", state))["error"] == "provider_unavailable"
    assert connections(world["session"]) == []


def test_a_failure_reading_the_account_after_the_exchange_stores_nothing(world):
    alice = browser(world["alice"])
    _, state = begin(alice)
    world["http"].route("GET", "https://api.vercel.com/v2/user", (500, {}))
    assert outcome(finish(alice, "vercel", state))["error"] == "provider_unavailable"
    assert connections(world["session"]) == []


def test_the_outcome_reported_to_the_browser_never_contains_a_token_or_the_code(world):
    alice = browser(world["alice"])
    _, state = begin(alice)
    response = finish(alice, "vercel", state, code="SECRET-CODE-123")
    for secret in ("SECRET-CODE-123", "vercel-secret-token-AAA", "vercel-client-secret", state):
        assert secret not in response.headers["location"] and secret not in response.text


def test_the_flow_cookie_is_cleared_once_the_callback_is_handled(world):
    alice = browser(world["alice"])
    _, state = begin(alice)
    assert "max-age=0" in finish(alice, "vercel", state).headers["set-cookie"].lower()


# --- what a completed connection looks like -------------------------------------------------------


def test_a_completed_connection_is_stored_encrypted_and_under_the_users_id(world):
    connect(world["alice"])
    (row,) = connections(world["session"])
    assert (row.user_id, row.provider, row.provider_account_id) == (world["alice"].id, "vercel", "usr_alice")
    assert row.access_token_encrypted != "vercel-secret-token-AAA"
    assert "vercel-secret-token-AAA" not in row.access_token_encrypted
    assert get_cipher().decrypt(row.access_token_encrypted, row.id) == "vercel-secret-token-AAA"


def test_the_account_identity_comes_from_the_provider_not_the_browser(world):
    """The callback has no parameter that names an account; a forged one changes nothing."""
    alice = browser(world["alice"])
    _, state = begin(alice)
    outcome(
        finish(alice, "vercel", state, account_id="usr_someone_else", provider_account_id="usr_someone_else")
    )
    assert connections(world["session"])[0].provider_account_id == "usr_alice"


def test_no_response_ever_contains_a_token_or_client_secret(world):
    alice = connect(world["alice"])
    (row,) = connections(world["session"])
    bodies = [
        alice.get(f"{V1}/providers").text,
        alice.get(f"{V1}/connections").text,
        alice.get(f"{V1}/connections/{row.id}/projects").text,
    ]
    for body in bodies:
        for secret in (
            "vercel-secret-token-AAA",
            "vercel-client-secret",
            "encrypted",
            "access_token",
            "refresh_token",
        ):
            assert secret not in body, secret


def test_connections_list_shape(world):
    alice = connect(world["alice"])
    (connection,) = alice.get(f"{V1}/connections").json()
    assert set(connection) == {"id", "provider", "label", "connected_at", "scopes"}
    assert connection["provider"] == "vercel" and connection["label"] == "alice"
    listed = {p["provider"]: p for p in alice.get(f"{V1}/providers").json()["providers"]}
    assert len(listed["vercel"]["connections"]) == 1 and listed["netlify"]["connections"] == []


def test_reconnecting_the_same_account_updates_it_rather_than_duplicating(world):
    connect(world["alice"])
    connect(world["alice"])
    assert len(connections(world["session"])) == 1


def test_one_user_can_connect_several_accounts_of_one_provider(world):
    connect(world["alice"])
    vercel_routes(world["http"], team=True)  # the same provider, now installed on a team
    connect(world["alice"])
    rows = connections(world["session"])
    assert {r.provider_account_id for r in rows} == {"usr_alice", "team_erp"} and len(rows) == 2


def test_each_provider_can_be_connected(world):
    for name in ("vercel", "netlify", "cloudflare"):
        connect(world["alice"], name)
    assert {r.provider for r in connections(world["session"])} == {"vercel", "netlify", "cloudflare"}
    cf = next(r for r in connections(world["session"]) if r.provider == "cloudflare")
    assert cf.refresh_token_encrypted and "cf-refresh-token-EEE" not in cf.refresh_token_encrypted
    assert cf.provider_account_id == "cf_alice" and cf.token_expires_at is not None


def test_listing_projects_shows_only_verifiable_hostnames(world):
    alice = connect(world["alice"])
    (row,) = connections(world["session"])
    body = alice.get(f"{V1}/connections/{row.id}/projects").json()
    assert body["connection"]["provider"] == "vercel"
    (project,) = body["projects"]
    assert project["hostnames"] == ["college-erp.vercel.app"] and project["verified_hostnames"] == []


def test_a_provider_rejecting_the_stored_token_is_a_409_not_a_401(world):
    """A 401 here would sign the person out of Cerberus over a problem with their Vercel connection."""
    alice = connect(world["alice"])
    (row,) = connections(world["session"])
    world["http"].route("GET", "https://api.vercel.com/v9/projects", (401, {}))
    response = alice.get(f"{V1}/connections/{row.id}/projects")
    assert response.status_code == 409 and response.json()["error"]["code"] == "connection_expired"


def test_a_provider_outage_is_a_503(world):
    alice = connect(world["alice"])
    (row,) = connections(world["session"])
    world["http"].route("GET", "https://api.vercel.com/v9/projects", (500, {}))
    response = alice.get(f"{V1}/connections/{row.id}/projects")
    assert response.status_code == 503 and response.json()["error"]["code"] == "provider_unavailable"


def test_cloudflare_tokens_are_refreshed_when_they_are_about_to_expire(world):
    alice = connect(world["alice"], "cloudflare")
    (row,) = connections(world["session"])
    row.token_expires_at = utcnow() - timedelta(minutes=1)
    world["session"].flush()
    world["http"].route(
        "POST",
        "https://dash.cloudflare.com/oauth2/token",
        (200, {"access_token": "cf-NEW-access", "refresh_token": "cf-NEW-refresh", "expires_in": 3600}),
    )
    assert alice.get(f"{V1}/connections/{row.id}/projects").status_code == 200
    assert get_cipher().decrypt(row.access_token_encrypted, row.id) == "cf-NEW-access"
    assert get_cipher().decrypt(row.refresh_token_encrypted, row.id) == "cf-NEW-refresh"
    used = [c.headers["Authorization"] for c in world["http"].calls_to(f"accounts/{CF_ACCOUNT}/pages")]
    assert used and all(h == "Bearer cf-NEW-access" for h in used)  # the new token is the one used


def test_an_expired_token_that_cannot_be_refreshed_asks_the_user_to_reconnect(world):
    alice = connect(world["alice"], "netlify")
    (row,) = connections(world["session"])
    row.token_expires_at = utcnow() - timedelta(minutes=1)
    world["session"].flush()
    response = alice.get(f"{V1}/connections/{row.id}/projects")
    assert response.status_code == 409 and response.json()["error"]["code"] == "connection_expired"


def test_disconnecting_deletes_the_stored_tokens(world):
    alice = connect(world["alice"])
    (row,) = connections(world["session"])
    response = alice.post(f"{V1}/connections/{row.id}/disconnect")
    assert response.status_code == 200 and response.json() == {"disconnected": True, "targets_reset": 0}
    assert connections(world["session"]) == []
    assert alice.get(f"{V1}/connections").json() == []


def test_a_ciphertext_moved_to_another_connection_row_does_not_work(world):
    """Write access to the database is not enough to make one user's token usable as another's."""
    connect(world["alice"])
    connect(world["bob"], "vercel")
    a, b = sorted(connections(world["session"]), key=lambda r: r.user_id != world["alice"].id)
    b.access_token_encrypted = a.access_token_encrypted
    world["session"].flush()
    response = browser(world["bob"]).get(f"{V1}/connections/{b.id}/projects")
    assert response.status_code == 409 and response.json()["error"]["code"] == "connection_expired"


def test_the_providers_module_can_still_be_used_after_the_fake_is_removed(world):
    assert isinstance(providers.get_provider("vercel"), providers.DeploymentProvider)
