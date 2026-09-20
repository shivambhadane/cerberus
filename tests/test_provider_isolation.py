"""User A must never reach User B's provider connections, projects, targets or scans.

Everything B holds answers A exactly as a thing that does not exist would: a 404 with the same body.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from api.main import app, get_session
from core.models import ConnectedProvider, Domain, Scan
from tests.provider_fakes import cloudflare_routes, netlify_routes, vercel_routes
from tests.provider_helpers import V1, begin, browser, connect, connections, finish, outcome

MISSING = "00000000-0000-4000-8000-000000000000"


@pytest.fixture
def world(session, make_user, fake_http, monkeypatch):
    app.dependency_overrides[get_session] = lambda: session
    started: list[str] = []
    monkeypatch.setattr("api.main.run_pipeline", lambda scan_id, config: started.append(scan_id))
    alice, bob = make_user("alice@example.com"), make_user("bob@example.com")
    vercel_routes(fake_http)
    netlify_routes(fake_http)
    cloudflare_routes(fake_http)
    # Bob owns a Vercel project, is connected, and has a verified target and a scan in flight history.
    bobs = connect(bob, "vercel")
    conn = next(c for c in connections(session) if c.user_id == bob.id)
    target = bobs.post(
        f"{V1}/domains/provider",
        json={"connection_id": conn.id, "project_id": "prj_erp", "hostname": "college-erp.vercel.app"},
    ).json()
    fake_http.calls.clear()
    yield {
        "session": session,
        "alice": alice,
        "bob": bob,
        "http": fake_http,
        "scans": started,
        "bob_connection": conn.id,
        "bob_target": target["id"],
        "bobs": bobs,
    }
    app.dependency_overrides.clear()


def same_as_missing(theirs, missing):
    assert theirs.status_code == missing.status_code == 404
    assert theirs.json() == missing.json()


# --- A -> B's provider connection -----------------------------------------------------------------


def test_a_cannot_list_the_projects_of_bs_connection(world):
    alice = browser(world["alice"])
    same_as_missing(
        alice.get(f"{V1}/connections/{world['bob_connection']}/projects"),
        alice.get(f"{V1}/connections/{MISSING}/projects"),
    )
    assert not world["http"].calls  # no call to the provider was ever made with Bob's token


def test_a_cannot_disconnect_bs_connection(world):
    alice = browser(world["alice"])
    same_as_missing(
        alice.post(f"{V1}/connections/{world['bob_connection']}/disconnect"),
        alice.post(f"{V1}/connections/{MISSING}/disconnect"),
    )
    assert world["session"].get(ConnectedProvider, world["bob_connection"]) is not None
    assert world["session"].get(Domain, world["bob_target"]).verification_status == "verified"


def test_a_cannot_use_bs_connection_to_add_or_verify_a_target(world):
    alice = browser(world["alice"])
    body = {"project_id": "prj_erp", "hostname": "college-erp.vercel.app"}
    theirs = alice.post(f"{V1}/domains/provider", json={"connection_id": world["bob_connection"], **body})
    missing = alice.post(f"{V1}/domains/provider", json={"connection_id": MISSING, **body})
    same_as_missing(theirs, missing)
    assert not world["http"].calls  # Bob's token was never even decrypted for Alice


def test_a_sees_only_her_own_connections(world):
    alice = connect(world["alice"], "netlify")
    listed = alice.get(f"{V1}/connections").json()
    assert [c["provider"] for c in listed] == ["netlify"]
    providers_view = {
        p["provider"]: p["connections"] for p in alice.get(f"{V1}/providers").json()["providers"]
    }
    assert providers_view["vercel"] == [] and len(providers_view["netlify"]) == 1
    assert world["bob_connection"] not in alice.get(f"{V1}/connections").text


def test_bs_token_never_appears_in_anything_a_can_fetch(world):
    alice = connect(world["alice"], "vercel")
    for path in ("/providers", "/connections", "/domains"):
        text = alice.get(f"{V1}{path}").text
        assert "vercel-secret-token" not in text and "vercel-client-secret" not in text


# --- A -> B's flow --------------------------------------------------------------------------------


def test_a_cannot_complete_bs_authorization_flow(world):
    """Bob starts a new flow; Alice, with her own cookie from her own flow, presents Bob's state."""
    bob_browser = browser(world["bob"])
    _, bobs_state = begin(bob_browser, "netlify")
    alice = browser(world["alice"])
    begin(alice, "netlify")
    result = outcome(finish(alice, "netlify", bobs_state))
    assert result["error"] == "invalid_state"
    assert all(c.user_id != world["alice"].id for c in connections(world["session"]))
    # and Bob's own completion is unaffected by her attempt only if his state was not burned: it was,
    # which is the safe direction (he simply starts again)
    assert outcome(finish(bob_browser, "netlify", bobs_state))["error"] == "invalid_state"


# --- A -> B's target ------------------------------------------------------------------------------


def test_a_cannot_read_or_verify_bs_target(world):
    alice = browser(world["alice"])
    same_as_missing(alice.get(f"{V1}/domains/{world['bob_target']}"), alice.get(f"{V1}/domains/{MISSING}"))
    body = {"connection_id": MISSING, "project_id": "prj_erp"}
    same_as_missing(
        alice.post(f"{V1}/domains/{world['bob_target']}/verify/provider", json=body),
        alice.post(f"{V1}/domains/{MISSING}/verify/provider", json=body),
    )
    assert "college-erp.vercel.app" not in alice.get(f"{V1}/domains").text


def test_a_cannot_attach_bs_deployment_to_her_own_account(world):
    """Alice connects her own Vercel account and asks to verify Bob's project and hostname."""
    http = world["http"]
    alice = connect(world["alice"], "vercel")
    conn = next(c for c in connections(world["session"]) if c.user_id == world["alice"].id)
    # Vercel would not show Alice's token Bob's project (only Bob's token sees prj_erp).
    http.route("GET", "https://api.vercel.com/v9/projects/prj_erp", (404, {}))
    response = alice.post(
        f"{V1}/domains/provider",
        json={"connection_id": conn.id, "project_id": "prj_erp", "hostname": "college-erp.vercel.app"},
    )
    assert response.status_code == 403 and response.json()["error"]["code"] == "ownership_not_proven"
    assert [d.user_id for d in world["session"].scalars(select(Domain))] == [
        world["bob"].id
    ]  # still only Bob's


def test_even_if_a_platform_shows_both_users_the_project_only_the_first_verifier_holds_it(world):
    alice = connect(world["alice"], "vercel")
    conn = next(c for c in connections(world["session"]) if c.user_id == world["alice"].id)
    response = alice.post(
        f"{V1}/domains/provider",
        json={"connection_id": conn.id, "project_id": "prj_erp", "hostname": "college-erp.vercel.app"},
    )
    assert response.status_code == 409 and response.json()["error"]["code"] == "domain_already_verified"
    assert world["session"].get(Domain, world["bob_target"]).user_id == world["bob"].id


# --- A -> B's scan --------------------------------------------------------------------------------


def test_a_cannot_scan_bs_verified_target(world):
    alice = browser(world["alice"])
    same_as_missing(
        alice.post(f"{V1}/scans", json={"domain_id": world["bob_target"]}),
        alice.post(f"{V1}/scans", json={"domain_id": MISSING}),
    )
    assert world["scans"] == [] and world["session"].scalars(select(Scan)).first() is None
    assert not world["http"].calls  # and no provider call was made on her behalf


def test_a_cannot_see_bs_scans_or_findings_for_it(world):
    world["bobs"].post(f"{V1}/scans", json={"domain_id": world["bob_target"]})
    alice = browser(world["alice"])
    assert alice.get(f"{V1}/scans").json()["total"] == 0
    assert alice.get(f"{V1}/overview").json()["scans_total"] == 0


def test_bs_scan_still_works_for_bob(world):
    assert world["bobs"].post(f"{V1}/scans", json={"domain_id": world["bob_target"]}).status_code == 202


def test_anonymous_callers_get_nothing(world):
    anon = TestClient(app)
    for path in ("/providers", "/connections", f"/connections/{world['bob_connection']}/projects"):
        assert anon.get(f"{V1}{path}").status_code == 401, path
    assert anon.post(f"{V1}/connections/{world['bob_connection']}/disconnect").status_code == 401
    assert anon.post(f"{V1}/providers/vercel/connect").status_code == 401
