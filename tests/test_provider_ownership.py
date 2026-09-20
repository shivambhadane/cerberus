"""Proving a deployment is yours through Vercel, Netlify or Cloudflare Pages, and what happens after.

The rule under test: a target becomes verified only if the platform, asked with the caller's own token,
lists that platform hostname on a project that token can see. Nothing the browser sends is believed.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from api.main import app, get_session
from core.models import ConnectedProvider, Domain, Scan
from tests.provider_fakes import (
    CF_ACCOUNT,
    cloudflare_routes,
    netlify_routes,
    vercel_routes,
)
from tests.provider_helpers import V1, browser, connect, connections

SITE_ID = "0e6d5c9a-1111-4222-8333-444455556666"


@pytest.fixture
def world(session, make_user, fake_http, monkeypatch):
    app.dependency_overrides[get_session] = lambda: session
    started: list[str] = []
    monkeypatch.setattr("api.main.run_pipeline", lambda scan_id, config: started.append(scan_id))
    alice, bob = make_user("alice@example.com"), make_user("bob@example.com")
    vercel_routes(fake_http)
    netlify_routes(fake_http)
    cloudflare_routes(fake_http)
    yield {"session": session, "alice": alice, "bob": bob, "http": fake_http, "scans": started}
    app.dependency_overrides.clear()


def conn_id(session, user, provider="vercel") -> str:
    rows = [c for c in connections(session) if c.user_id == user.id and c.provider == provider]
    return rows[-1].id


def add(client, connection_id, project_id, hostname, **extra):
    body = {"connection_id": connection_id, "project_id": project_id, "hostname": hostname, **extra}
    return client.post(f"{V1}/domains/provider", json=body)


def domains(session, user=None):
    stmt = select(Domain) if user is None else select(Domain).where(Domain.user_id == user.id)
    return list(session.scalars(stmt))


# --- the three happy paths ------------------------------------------------------------------------


def test_vercel_owner_can_verify_their_project_and_scan_it(world):
    alice = connect(world["alice"], "vercel")
    response = add(alice, conn_id(world["session"], world["alice"]), "prj_erp", "college-erp.vercel.app")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["domain"] == "college-erp.vercel.app"
    assert (body["verification_status"], body["verification_method"]) == ("verified", "vercel")
    assert body["provider"] == "vercel" and body["provider_project_id"] == "prj_erp"
    assert body["verified_at"] and body["verification"] is None  # no DNS record to publish

    scan = alice.post(f"{V1}/scans", json={"domain_id": body["id"]})
    assert scan.status_code == 202
    assert world["session"].get(Scan, scan.json()["scan_id"]).target_domain == "college-erp.vercel.app"
    assert world["scans"] == [scan.json()["scan_id"]]


def test_netlify_owner_can_verify_their_site_and_scan_it(world):
    alice = connect(world["alice"], "netlify")
    response = add(
        alice, conn_id(world["session"], world["alice"], "netlify"), SITE_ID, "campus-portal.netlify.app"
    )
    assert response.status_code == 200, response.text
    assert (
        response.json()["verification_method"] == "netlify"
        and response.json()["verification_status"] == "verified"
    )
    assert alice.post(f"{V1}/scans", json={"domain_id": response.json()["id"]}).status_code == 202


def test_cloudflare_owner_can_verify_their_pages_project_and_scan_it(world):
    alice = connect(world["alice"], "cloudflare")
    response = add(
        alice,
        conn_id(world["session"], world["alice"], "cloudflare"),
        f"{CF_ACCOUNT}:docs-site",
        "docs-site.pages.dev",
    )
    assert response.status_code == 200, response.text
    assert response.json()["verification_method"] == "cloudflare"
    assert response.json()["provider_project_id"] == f"{CF_ACCOUNT}:docs-site"
    assert alice.post(f"{V1}/scans", json={"domain_id": response.json()["id"]}).status_code == 202


def test_the_target_is_listed_like_any_other_and_shows_how_it_was_proven(world):
    alice = connect(world["alice"], "vercel")
    add(alice, conn_id(world["session"], world["alice"]), "prj_erp", "college-erp.vercel.app")
    (listed,) = alice.get(f"{V1}/domains").json()["domains"]
    assert listed["provider"] == "vercel" and listed["verification"] is None
    assert "cerberus-verify" not in alice.get(f"{V1}/domains").text  # no DNS token for a platform target


def test_adding_it_again_is_idempotent(world):
    alice = connect(world["alice"], "vercel")
    cid = conn_id(world["session"], world["alice"])
    first = add(alice, cid, "prj_erp", "college-erp.vercel.app").json()
    second = add(alice, cid, "prj_erp", "college-erp.vercel.app").json()
    assert first["id"] == second["id"] and len(domains(world["session"], world["alice"])) == 1


# --- what must be rejected ------------------------------------------------------------------------


def rejected(response, code, status=403):
    assert response.status_code == status, response.text
    assert response.json()["error"]["code"] == code


def test_a_project_id_that_does_not_exist_is_rejected(world):
    alice = connect(world["alice"], "vercel")
    rejected(
        add(alice, conn_id(world["session"], world["alice"]), "prj_invented", "college-erp.vercel.app"),
        "ownership_not_proven",
    )
    assert domains(world["session"]) == []


def test_a_hostname_the_project_does_not_have_is_rejected(world):
    alice = connect(world["alice"], "vercel")
    rejected(
        add(alice, conn_id(world["session"], world["alice"]), "prj_erp", "somebody-elses.vercel.app"),
        "ownership_not_proven",
    )
    assert domains(world["session"]) == []


def test_a_project_belonging_to_another_account_is_rejected(world):
    """Alice's token cannot see Bob's project: Vercel answers 404 for it, so it cannot be verified."""
    http = world["http"]
    alice = connect(world["alice"], "vercel")
    http.route(
        "GET",
        "https://api.vercel.com/v9/projects/prj_bobs",
        lambda call: (
            (404, {})
            if call.headers["Authorization"] == "Bearer vercel-secret-token-AAA"
            else (200, {"id": "prj_bobs"})
        ),
    )
    rejected(
        add(alice, conn_id(world["session"], world["alice"]), "prj_bobs", "bobs-app.vercel.app"),
        "ownership_not_proven",
    )
    assert domains(world["session"]) == []


def test_a_hostname_from_a_different_project_of_mine_is_rejected(world):
    """The hostname must belong to the project named in the request, not merely to some project of mine."""
    vercel_routes(
        world["http"],
        {
            "prj_erp": [{"name": "college-erp.vercel.app", "verified": True}],
            "prj_blog": [{"name": "my-blog.vercel.app", "verified": True}],
        },
    )
    alice = connect(world["alice"], "vercel")
    cid = conn_id(world["session"], world["alice"])
    rejected(add(alice, cid, "prj_erp", "my-blog.vercel.app"), "ownership_not_proven")
    assert add(alice, cid, "prj_blog", "my-blog.vercel.app").status_code == 200


def test_a_custom_domain_on_the_project_is_not_accepted_here(world):
    """Attaching a domain to a project does not prove you own it. Only DNS can."""
    alice = connect(world["alice"], "vercel")
    rejected(
        add(alice, conn_id(world["session"], world["alice"]), "prj_erp", "erp.college.edu"),
        "not_a_platform_hostname",
        400,
    )


def test_an_unverified_vercel_domain_is_not_accepted(world):
    alice = connect(world["alice"], "vercel")
    rejected(
        add(alice, conn_id(world["session"], world["alice"]), "prj_erp", "unverified.vercel.app"),
        "ownership_not_proven",
    )


@pytest.mark.parametrize("apex", ["vercel.app", "netlify.app", "pages.dev"])
def test_the_platform_itself_can_never_be_verified(world, apex):
    alice = connect(world["alice"], "vercel")
    rejected(
        add(alice, conn_id(world["session"], world["alice"]), "prj_erp", apex), "not_a_platform_hostname", 400
    )


def test_another_platforms_hostname_cannot_be_verified_through_this_connection(world):
    alice = connect(world["alice"], "vercel")
    rejected(
        add(alice, conn_id(world["session"], world["alice"]), "prj_erp", "campus-portal.netlify.app"),
        "not_a_platform_hostname",
        400,
    )


@pytest.mark.parametrize("bad_project", ["../../v2/user", "prj_erp?teamId=other", "prj erp", "", "x" * 300])
def test_a_project_id_cannot_redirect_the_request(world, bad_project):
    alice = connect(world["alice"], "vercel")
    response = add(alice, conn_id(world["session"], world["alice"]), bad_project, "college-erp.vercel.app")
    assert response.status_code in (403, 422)
    assert (
        not world["http"].calls_to("/v2/user") or len(world["http"].calls_to("/v2/user")) == 1
    )  # only the connect-time call


def test_fields_the_browser_might_add_to_claim_an_account_are_ignored(world):
    """`provider_account_id`, `owner`, `verified`... none of them is read. Only the platform decides."""
    alice = connect(world["alice"], "vercel")
    response = add(
        alice,
        conn_id(world["session"], world["alice"]),
        "prj_erp",
        "somebody-elses.vercel.app",
        provider_account_id="usr_alice",
        verified=True,
        user_id=world["alice"].id,
        verification_status="verified",
    )
    rejected(response, "ownership_not_proven")
    assert domains(world["session"]) == []


def test_an_unknown_connection_is_a_404(world):
    alice = browser(world["alice"])
    rejected(
        add(alice, "no-such-connection", "prj_erp", "college-erp.vercel.app"), "connection_not_found", 404
    )


def test_verifying_needs_a_signed_in_user(world):
    body = {"connection_id": "x", "project_id": "y", "hostname": "z.vercel.app"}
    assert TestClient(app).post(f"{V1}/domains/provider", json=body).status_code == 401


def test_a_provider_refusing_the_token_is_a_409_and_creates_nothing(world):
    """Not a 401: that would sign the person out of Cerberus."""
    alice = connect(world["alice"], "vercel")
    world["http"].route("GET", "https://api.vercel.com/v9/projects/prj_erp", (401, {}))
    rejected(
        add(alice, conn_id(world["session"], world["alice"]), "prj_erp", "college-erp.vercel.app"),
        "connection_expired",
        409,
    )
    assert domains(world["session"]) == []


def test_a_provider_outage_is_a_503_and_creates_nothing(world):
    alice = connect(world["alice"], "vercel")
    world["http"].route("GET", "https://api.vercel.com/v9/projects/prj_erp", (500, {}))
    rejected(
        add(alice, conn_id(world["session"], world["alice"]), "prj_erp", "college-erp.vercel.app"),
        "provider_unavailable",
        503,
    )
    assert domains(world["session"]) == []


# --- DNS stays as it was --------------------------------------------------------------------------


@pytest.mark.parametrize("host", ["my-app.vercel.app", "site.netlify.app", "docs.pages.dev", "vercel.app"])
def test_a_platform_hostname_typed_into_the_dns_form_is_sent_to_the_right_flow(world, host):
    """Nobody can publish a TXT record on vercel.app, so a DNS claim would sit pending forever."""
    alice = browser(world["alice"])
    response = alice.post(f"{V1}/domains", json={"domain": host})
    rejected(response, "use_provider", 400)
    assert "Connect your" in response.json()["error"]["message"]


def test_a_custom_domain_still_verifies_with_dns_exactly_as_before(world, monkeypatch):
    from core import verification

    alice = browser(world["alice"])
    created = alice.post(f"{V1}/domains", json={"domain": "example.com"}).json()
    assert created["verification_method"] == "dns_txt" and created["verification"]["record_name"]
    monkeypatch.setattr(
        verification, "lookup_txt", lambda name, timeout=8.0: [created["verification"]["record_value"]]
    )
    assert alice.post(f"{V1}/domains/{created['id']}/verify").json()["verified"] is True
    assert alice.post(f"{V1}/scans", json={"domain_id": created["id"]}).status_code == 202


def test_a_dns_verified_scan_makes_no_provider_call(world, monkeypatch):
    from core import verification

    alice = browser(world["alice"])
    created = alice.post(f"{V1}/domains", json={"domain": "example.com"}).json()
    monkeypatch.setattr(
        verification, "lookup_txt", lambda name, timeout=8.0: [created["verification"]["record_value"]]
    )
    alice.post(f"{V1}/domains/{created['id']}/verify")
    world["http"].calls.clear()
    assert alice.post(f"{V1}/scans", json={"domain_id": created["id"]}).status_code == 202
    assert world["http"].calls == []


def test_a_platform_verified_target_cannot_be_dns_verified(world):
    alice = connect(world["alice"], "vercel")
    made = add(alice, conn_id(world["session"], world["alice"]), "prj_erp", "college-erp.vercel.app").json()
    rejected(alice.post(f"{V1}/domains/{made['id']}/verify"), "wrong_method", 400)


# --- verifying an existing target -----------------------------------------------------------------


def test_an_existing_unverified_target_can_be_verified_through_a_platform(world):
    alice = connect(world["alice"], "vercel")
    row = Domain(user_id=world["alice"].id, domain="college-erp.vercel.app")
    world["session"].add(row)
    world["session"].flush()
    response = alice.post(
        f"{V1}/domains/{row.id}/verify/provider",
        json={"connection_id": conn_id(world["session"], world["alice"]), "project_id": "prj_erp"},
    )
    assert response.status_code == 200 and response.json()["verification_method"] == "vercel"
    assert response.json()["id"] == row.id and len(domains(world["session"], world["alice"])) == 1


def test_that_route_verifies_the_targets_own_hostname_not_one_from_the_request(world):
    alice = connect(world["alice"], "vercel")
    row = Domain(user_id=world["alice"].id, domain="not-on-this-project.vercel.app")
    world["session"].add(row)
    world["session"].flush()
    rejected(
        alice.post(
            f"{V1}/domains/{row.id}/verify/provider",
            json={
                "connection_id": conn_id(world["session"], world["alice"]),
                "project_id": "prj_erp",
                "hostname": "college-erp.vercel.app",
            },
        ),
        "ownership_not_proven",
    )
    assert world["session"].get(Domain, row.id).verification_status == "pending"


def test_the_first_account_to_prove_a_hostname_owns_it(world):
    """Two people on one Vercel team both see the project. Whoever verifies first holds it."""
    alice, bob = connect(world["alice"], "vercel"), connect(world["bob"], "vercel")
    assert (
        add(alice, conn_id(world["session"], world["alice"]), "prj_erp", "college-erp.vercel.app").status_code
        == 200
    )
    rejected(
        add(bob, conn_id(world["session"], world["bob"]), "prj_erp", "college-erp.vercel.app"),
        "domain_already_verified",
        409,
    )


# --- a verification must not outlive the ownership it recorded ------------------------------------


@pytest.fixture
def verified(world):
    alice = connect(world["alice"], "vercel")
    made = add(alice, conn_id(world["session"], world["alice"]), "prj_erp", "college-erp.vercel.app").json()
    world["http"].calls.clear()
    return {"client": alice, "domain_id": made["id"]}


def scan(verified):
    return verified["client"].post(f"{V1}/scans", json={"domain_id": verified["domain_id"]})


def status(world, verified):
    return world["session"].get(Domain, verified["domain_id"]).verification_status


def test_every_scan_re_asks_the_platform(world, verified):
    assert scan(verified).status_code == 202
    assert world["http"].calls_to("/v9/projects/prj_erp")  # the check happened, right now


def test_a_deleted_project_stops_being_scannable_and_the_target_becomes_failed(world, verified):
    world["http"].route("GET", "https://api.vercel.com/v9/projects/prj_erp", (404, {}))
    rejected(scan(verified), "ownership_lost")
    assert status(world, verified) == "failed"
    rejected(scan(verified), "domain_not_verified")  # and stays refused
    assert world["scans"] == []


def test_a_hostname_re_registered_by_someone_else_is_no_longer_ours(world, verified):
    """The project still exists but no longer lists the hostname: someone else holds that name now."""
    vercel_routes(world["http"], {"prj_erp": [{"name": "another-name.vercel.app", "verified": True}]})
    rejected(scan(verified), "ownership_lost")
    assert status(world, verified) == "failed"


def test_a_platform_outage_refuses_the_scan_but_does_not_revoke(world, verified):
    world["http"].route("GET", "https://api.vercel.com/v9/projects/prj_erp", (503, {}))
    rejected(scan(verified), "provider_unavailable", 503)
    assert status(world, verified) == "verified"


def test_a_revoked_token_refuses_the_scan_and_asks_to_reconnect(world, verified):
    world["http"].route("GET", "https://api.vercel.com/v9/projects/prj_erp", (401, {}))
    rejected(scan(verified), "connection_expired", 409)
    assert status(world, verified) == "verified"  # nothing proved it false; it just cannot be confirmed


def test_disconnecting_takes_the_proof_away_from_the_targets_it_verified(world, verified):
    cid = conn_id(world["session"], world["alice"])
    response = verified["client"].post(f"{V1}/connections/{cid}/disconnect")
    assert response.json() == {"disconnected": True, "targets_reset": 1}
    assert status(world, verified) == "pending"
    rejected(scan(verified), "domain_not_verified")
    assert world["session"].scalars(select(ConnectedProvider)).first() is None


def test_after_disconnecting_the_hostname_is_free_for_its_real_owner(world, verified):
    verified["client"].post(f"{V1}/connections/{conn_id(world['session'], world['alice'])}/disconnect")
    bob = connect(world["bob"], "vercel")
    assert (
        add(bob, conn_id(world["session"], world["bob"]), "prj_erp", "college-erp.vercel.app").status_code
        == 200
    )


def test_a_lost_target_can_be_verified_again_once_it_is_true_again(world, verified):
    world["http"].route("GET", "https://api.vercel.com/v9/projects/prj_erp", (404, {}))
    scan(verified)
    vercel_routes(world["http"])  # the project is back
    cid = conn_id(world["session"], world["alice"])
    again = verified["client"].post(
        f"{V1}/domains/{verified['domain_id']}/verify/provider",
        json={"connection_id": cid, "project_id": "prj_erp"},
    )
    assert again.status_code == 200 and status(world, verified) == "verified"
    assert scan(verified).status_code == 202


def test_a_scan_of_an_unverified_target_is_still_refused(world):
    row = Domain(user_id=world["alice"].id, domain="pending.vercel.app")
    world["session"].add(row)
    world["session"].flush()
    rejected(browser(world["alice"]).post(f"{V1}/scans", json={"domain_id": row.id}), "domain_not_verified")


def test_there_is_still_no_authorized_flag(world, verified):
    old = verified["client"].post(
        f"{V1}/scans", json={"target_domain": "college-erp.vercel.app", "authorized": True}
    )
    assert old.status_code == 422
