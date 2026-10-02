"""Connecting with a pasted access token (Vercel), the fallback for when its OAuth integration cannot be used.

What must hold: the token is proved by using it, stored encrypted, never returned or logged, refused without
being repeated when wrong, rate limited, and everything done with it passes through the same ownership and
isolation checks as an OAuth connection.
"""

import logging

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from api.main import app, get_session
from core.crypto import get_cipher
from core.models import ConnectedProvider, Domain
from tests.provider_fakes import cloudflare_routes, netlify_routes, vercel_routes
from tests.provider_helpers import V1, browser, connect, connections

TOKEN = "vcp_AbCdEf0123456789_tokenValue"
OTHER_TOKEN = "vcp_ZyXwVu9876543210_secondToken"
USER_URL = "https://api.vercel.com/v2/user"


@pytest.fixture
def world(session, make_user, fake_http, monkeypatch):
    app.dependency_overrides[get_session] = lambda: session
    monkeypatch.setattr("api.main.run_pipeline", lambda scan_id, config: None)
    alice, bob = make_user("alice@example.com"), make_user("bob@example.com")
    vercel_routes(fake_http)
    netlify_routes(fake_http)
    cloudflare_routes(fake_http)
    yield {"session": session, "alice": alice, "bob": bob, "http": fake_http, "mp": monkeypatch}
    app.dependency_overrides.clear()


def paste(client, token=TOKEN, provider="vercel", **body):
    return client.post(f"{V1}/providers/{provider}/token", json={"token": token, **body})


def error(response, code, status=400):
    assert response.status_code == status, response.text
    assert response.json()["error"]["code"] == code, response.text
    return response.json()["error"]["message"]


def rows(session):
    return list(session.scalars(select(ConnectedProvider)))


def add(client, cid, project="prj_erp", host="college-erp.vercel.app"):
    return client.post(
        f"{V1}/domains/provider", json={"connection_id": cid, "project_id": project, "hostname": host}
    )


def no_oauth_app(world):
    for key in ("VERCEL_CLIENT_ID", "VERCEL_CLIENT_SECRET", "VERCEL_INTEGRATION_SLUG"):
        world["mp"].setenv(key, "")


# --- what a successful paste does ------------------------------------------------------------------


def test_a_valid_token_connects_the_account(world):
    response = paste(browser(world["alice"]))
    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["provider"], body["method"], body["label"]) == ("vercel", "token", "alice")
    assert set(body) == {"id", "provider", "label", "connected_at", "scopes", "method"}


def test_the_account_is_whoever_the_platform_says_the_token_belongs_to(world):
    """The identity comes from asking Vercel with the token, never from the request."""
    paste(browser(world["alice"]))
    (row,) = rows(world["session"])
    assert row.provider_account_id == "usr_alice"  # from GET /v2/user
    (call,) = world["http"].calls_to("/v2/user")
    assert call.headers["Authorization"] == f"Bearer {TOKEN}"


def test_the_token_is_stored_encrypted_and_bound_to_its_row(world):
    paste(browser(world["alice"]))
    (row,) = rows(world["session"])
    assert TOKEN not in row.access_token_encrypted
    assert get_cipher().decrypt(row.access_token_encrypted, row.id) == TOKEN
    assert row.refresh_token_encrypted is None and row.token_expires_at is None
    assert (row.extra or {}).get("method") == "token"


def test_the_token_is_never_returned_by_any_endpoint(world):
    client = browser(world["alice"])
    cid = paste(client).json()["id"]
    texts = [
        client.get(f"{V1}/providers").text,
        client.get(f"{V1}/connections").text,
        client.get(f"{V1}/connections/{cid}/projects").text,
    ]
    assert all(TOKEN not in t for t in texts)


def test_the_token_never_reaches_the_logs(world, caplog):
    caplog.set_level(logging.DEBUG)
    client = browser(world["alice"])
    paste(client)
    paste(client, token="not a token")  # a refusal must not repeat it either
    assert TOKEN not in caplog.text and "not a token" not in caplog.text


def test_pasted_whitespace_and_quotes_are_trimmed(world):
    """Copy-paste brings a newline or quotes along; the token itself is what is stored."""
    assert paste(browser(world["alice"]), token=f'  "{TOKEN}"\n').status_code == 200
    (row,) = rows(world["session"])
    assert get_cipher().decrypt(row.access_token_encrypted, row.id) == TOKEN


def test_pasting_again_updates_the_same_connection_and_keeps_its_targets_verified(world):
    """A token that expired is replaced by a new one for the same account without losing verified targets."""
    client = browser(world["alice"])
    first = paste(client).json()["id"]
    add(client, first)
    second = paste(client, token=OTHER_TOKEN).json()["id"]
    assert first == second and len(rows(world["session"])) == 1
    (row,) = rows(world["session"])
    assert get_cipher().decrypt(row.access_token_encrypted, row.id) == OTHER_TOKEN
    (domain,) = world["session"].scalars(select(Domain))
    assert domain.verification_status == "verified" and domain.provider_connection_id == first


def test_the_same_account_over_oauth_and_over_a_token_is_one_connection(world):
    connect(world["alice"], "vercel")  # OAuth
    paste(browser(world["alice"]))  # the same Vercel account, now with a token
    (row,) = rows(world["session"])
    assert (row.extra or {}).get("method") == "token"


# --- a team-limited token ---------------------------------------------------------------------------


def test_a_team_token_sends_the_team_and_names_the_connection_after_it(world):
    response = paste(browser(world["alice"]), team_id="team_erp")
    assert response.status_code == 200, response.text
    assert response.json()["label"] == "ERP Team"
    (row,) = rows(world["session"])
    assert row.provider_account_id == "team_erp" and row.extra["team_id"] == "team_erp"
    assert all((c.params or {}).get("teamId") == "team_erp" for c in world["http"].calls_to("/v2/user"))


@pytest.mark.parametrize(
    "team", ["erp", "team_", "team_../../user", "team_x?teamId=other", "user_123", "cozyattacker-projects"]
)
def test_a_malformed_team_id_is_refused_before_any_request(world, team):
    """A typo in the team field is its own error: it must not read as "the token was rejected", and it must
    not spend one of the ten wrong-token attempts."""
    message = error(paste(browser(world["alice"]), team_id=team), "invalid_team_id")
    assert "team_" in message and "did not accept" not in message
    assert world["http"].calls == [] and rows(world["session"]) == []


def test_a_bad_team_id_does_not_use_up_the_wrong_token_attempts(world):
    client = browser(world["alice"])
    for _ in range(12):
        error(paste(client, team_id="not-a-team"), "invalid_team_id")
    assert paste(client).status_code == 200  # still allowed through


def test_a_real_looking_team_id_with_dashes_is_accepted(world):
    """Vercel ids are opaque; the check must not be narrower than the ids Vercel actually issues."""
    tid = "team_LLHUOMOo-Dlq_Op8wPE4k"
    world["http"].route("GET", f"https://api.vercel.com/v2/teams/{tid}", (200, {"id": tid, "name": "T"}))
    assert paste(browser(world["alice"]), team_id=tid).status_code == 200


# --- tokens that are wrong ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [401, 403])
def test_a_token_the_platform_rejects_creates_nothing_and_is_not_echoed(world, status):
    world["http"].route("GET", USER_URL, (status, {"error": {"code": "forbidden"}}))
    response = paste(browser(world["alice"]))
    message = error(response, "invalid_token")
    assert TOKEN not in response.text and "did not accept that token" in message
    assert rows(world["session"]) == []


@pytest.mark.parametrize(
    "token",
    [
        "",
        "   ",
        "short",
        "has a space in it",
        "new\nline-in-the-middle-1234",
        "x" * 513,
        "tok;en=1234567",
        "tok\x00en12345",
    ],
)
def test_a_value_that_is_not_shaped_like_a_token_is_refused_before_any_request(world, token):
    response = paste(browser(world["alice"]), token=token)
    error(response, "invalid_token")
    assert "x" * 20 not in response.text and world["http"].calls == []


def test_a_platform_outage_is_not_blamed_on_the_token(world):
    world["http"].route("GET", USER_URL, (503, {}))
    error(paste(browser(world["alice"])), "provider_unavailable", 503)


def test_wrong_tokens_are_rate_limited_but_right_ones_are_not_counted(world):
    world["http"].route("GET", USER_URL, (401, {}))
    client = browser(world["alice"])
    for _ in range(10):
        error(paste(client), "invalid_token")
    response = paste(client)
    error(response, "too_many_attempts", 429)
    assert int(response.headers["Retry-After"]) > 0
    world["http"].route("GET", USER_URL, (200, {"user": {"id": "usr_bob", "username": "bob"}}))
    assert paste(browser(world["bob"])).status_code == 200  # another person is unaffected


def test_successful_pastes_do_not_use_up_the_attempts(world):
    client = browser(world["alice"])
    assert all(paste(client).status_code == 200 for _ in range(15))


# --- who and what may use the endpoint ---------------------------------------------------------------


def test_it_needs_a_signed_in_user(world):
    assert paste(TestClient(app)).status_code == 401


def test_a_provider_without_token_support_says_so(world):
    for provider in ("netlify", "cloudflare"):
        error(paste(browser(world["alice"]), provider=provider), "not_supported")
    assert world["http"].calls == []


def test_an_unknown_provider_is_a_404(world):
    assert paste(browser(world["alice"]), provider="heroku").status_code == 404


def test_without_an_encryption_key_nothing_is_stored_in_the_clear(world):
    world["mp"].delenv("PROVIDER_TOKEN_ENCRYPTION_KEY")
    error(paste(browser(world["alice"])), "provider_not_configured", 503)
    assert rows(world["session"]) == [] and world["http"].calls == []


def test_the_connection_limit_applies(world):
    from core.provider_service import MAX_CONNECTIONS_PER_USER

    client = browser(world["alice"])
    for n in range(MAX_CONNECTIONS_PER_USER):
        world["http"].route("GET", USER_URL, (200, {"user": {"id": f"usr_{n}", "username": f"u{n}"}}))
        assert paste(client).status_code == 200
    world["http"].route("GET", USER_URL, (200, {"user": {"id": "usr_extra", "username": "x"}}))
    error(paste(client), "too_many_connections")


# --- the provider list ------------------------------------------------------------------------------


def test_the_provider_list_says_where_a_token_can_be_used(world):
    listed = {p["provider"]: p for p in browser(world["alice"]).get(f"{V1}/providers").json()["providers"]}
    assert {name: p["token_paste"] for name, p in listed.items()} == {
        "vercel": True,
        "netlify": False,
        "cloudflare": False,
    }


def test_a_token_can_be_used_where_the_oauth_app_is_not_set_up(world):
    """Only the encryption key is needed: the whole point is to work without an integration."""
    no_oauth_app(world)
    listed = browser(world["alice"]).get(f"{V1}/providers").json()["providers"]
    vercel = next(p for p in listed if p["provider"] == "vercel")
    assert (vercel["configured"], vercel["token_paste"]) == (False, True)
    error(browser(world["alice"]).post(f"{V1}/providers/vercel/connect"), "provider_not_configured", 503)
    assert paste(browser(world["alice"])).status_code == 200


def test_without_an_encryption_key_the_token_option_is_off(world):
    world["mp"].delenv("PROVIDER_TOKEN_ENCRYPTION_KEY")
    listed = browser(world["alice"]).get(f"{V1}/providers").json()["providers"]
    assert all(not p["token_paste"] for p in listed)


# --- what a token connection can do, and no more ------------------------------------------------------


def test_add_and_verify_and_scan_work_with_a_token_and_no_oauth_app(world):
    no_oauth_app(world)
    alice = browser(world["alice"])
    cid = paste(alice).json()["id"]
    projects = alice.get(f"{V1}/connections/{cid}/projects")
    assert projects.status_code == 200
    assert projects.json()["projects"][0]["hostnames"] == ["college-erp.vercel.app"]
    made = add(alice, cid)
    assert made.status_code == 200, made.text
    assert (made.json()["verification_status"], made.json()["verification_method"]) == ("verified", "vercel")
    assert alice.post(f"{V1}/scans", json={"domain_id": made.json()["id"]}).status_code == 202
    # the platform was asked with the pasted token, every time
    calls = world["http"].calls_to("/v9/projects")
    assert calls and all(c.headers["Authorization"] == f"Bearer {TOKEN}" for c in calls)


def test_the_ownership_rules_are_the_same_as_for_oauth(world):
    """A custom domain on the project, or someone else's project, is still not provable with a token."""
    world["http"].route("GET", "https://api.vercel.com/v9/projects/prj_other", (404, {}))
    alice = browser(world["alice"])
    cid = paste(alice).json()["id"]
    error(add(alice, cid, "prj_erp", "erp.college.edu"), "not_a_platform_hostname")
    error(add(alice, cid, "prj_other", "college-erp.vercel.app"), "ownership_not_proven", 403)
    error(add(alice, cid, "prj_erp", "someone-elses.vercel.app"), "ownership_not_proven", 403)
    assert all(d.verification_status != "verified" for d in world["session"].scalars(select(Domain)))


def test_a_token_revoked_later_refuses_the_scan_and_asks_for_a_new_one(world):
    alice = browser(world["alice"])
    made = add(alice, paste(alice).json()["id"]).json()
    world["http"].route("GET", "https://api.vercel.com/v9/projects/prj_erp", (401, {}))
    error(alice.post(f"{V1}/scans", json={"domain_id": made["id"]}), "connection_expired", 409)
    assert world["session"].get(Domain, made["id"]).verification_status == "verified"  # not proved false


def test_another_user_cannot_see_or_use_someones_token_connection(world):
    alice, bob = browser(world["alice"]), browser(world["bob"])
    cid = paste(alice).json()["id"]
    error(bob.get(f"{V1}/connections/{cid}/projects"), "connection_not_found", 404)
    error(bob.post(f"{V1}/connections/{cid}/disconnect"), "connection_not_found", 404)
    error(add(bob, cid), "connection_not_found", 404)
    assert bob.get(f"{V1}/connections").json() == []
    assert len(rows(world["session"])) == 1


def test_disconnecting_deletes_the_stored_token_and_takes_the_proof_away(world):
    alice = browser(world["alice"])
    cid = paste(alice).json()["id"]
    made = add(alice, cid).json()
    outcome = alice.post(f"{V1}/connections/{cid}/disconnect").json()
    assert outcome == {"disconnected": True, "targets_reset": 1}
    assert rows(world["session"]) == [] and connections(world["session"]) == []
    assert world["session"].get(Domain, made["id"]).verification_status == "pending"
