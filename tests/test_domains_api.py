"""Claiming a domain and proving it. DNS is replaced, so nothing here touches the network."""

import pytest
from fastapi.testclient import TestClient

from api.domains import MAX_DOMAINS_PER_USER
from api.main import app, get_session
from core import verification
from core.models import Domain, Scan, utcnow
from tests.helpers import auth_for


@pytest.fixture
def world(session, make_user):
    alice, bob = make_user("alice@example.com"), make_user("bob@example.com")
    app.dependency_overrides[get_session] = lambda: session
    yield {
        "alice": TestClient(app, headers=auth_for(alice)),
        "bob": TestClient(app, headers=auth_for(bob)),
        "anon": TestClient(app),
        "users": {"alice": alice, "bob": bob},
        "session": session,
    }
    app.dependency_overrides.clear()


def add(client, name="example.com"):
    return client.post("/api/v1/domains", json={"domain": name})


def publishing(monkeypatch, *records):
    """Make DNS answer with these TXT strings, and record what was asked."""
    asked: list[str] = []

    def lookup(name, timeout=8.0):
        asked.append(name)
        return list(records)

    monkeypatch.setattr(verification, "lookup_txt", lookup)
    return asked


def dns_says(monkeypatch, exc):
    def lookup(name, timeout=8.0):
        raise exc(name)

    monkeypatch.setattr(verification, "lookup_txt", lookup)


# --- claiming -------------------------------------------------------------------------------

def test_adding_a_domain_starts_pending_with_instructions(world):
    response = add(world["alice"], "Example.COM.")
    assert response.status_code == 201
    body = response.json()
    assert body["domain"] == "example.com"  # normalised
    assert body["verification_status"] == "pending" and body["verified_at"] is None
    v = body["verification"]
    assert v["method"] == "dns_txt" and v["record_type"] == "TXT"
    assert v["record_name"] == "_cerberus-challenge.example.com"
    assert v["record_value"].startswith("cerberus-verify=") and len(v["record_value"]) > 30


@pytest.mark.parametrize("bad", [
    "", "https://example.com", "example.com/path", "example.com:443", "*.example.com",
    "127.0.0.1", "localhost", "user@example.com", "exa mple.com",
])
def test_things_that_are_not_bare_domains_are_refused(world, bad):
    response = add(world["alice"], bad)
    assert response.status_code in (400, 422)
    if response.status_code == 400:
        assert response.json()["error"]["code"] == "invalid_domain"


def test_a_domain_cannot_be_added_twice_by_the_same_user(world):
    assert add(world["alice"]).status_code == 201
    again = add(world["alice"], "EXAMPLE.com")
    assert again.status_code == 409 and again.json()["error"]["code"] == "domain_exists"


def test_two_users_may_both_claim_the_same_domain_with_different_tokens(world):
    a, b = add(world["alice"]).json(), add(world["bob"]).json()
    assert a["id"] != b["id"]
    assert a["verification"]["record_value"] != b["verification"]["record_value"]


def test_there_is_a_cap_on_domains_per_user(world):
    for i in range(MAX_DOMAINS_PER_USER):
        assert add(world["alice"], f"d{i}.example.com").status_code == 201
    over = add(world["alice"], "one-too-many.example.com")
    assert over.status_code == 400 and over.json()["error"]["code"] == "domain_limit"
    assert add(world["bob"], "d0.example.com").status_code == 201  # per user, not global


def test_domains_need_a_signed_in_user(world):
    assert world["anon"].get("/api/v1/domains").status_code == 401
    assert world["anon"].post("/api/v1/domains", json={"domain": "example.com"}).status_code == 401


# --- reading ---------------------------------------------------------------------------------

def test_listing_shows_only_my_domains_newest_first(world):
    add(world["alice"], "first.example.com")
    add(world["alice"], "second.example.com")
    add(world["bob"], "bobs.example.com")
    body = world["alice"].get("/api/v1/domains").json()
    assert body["total"] == 2
    assert {d["domain"] for d in body["domains"]} == {"first.example.com", "second.example.com"}


def test_another_users_domain_is_indistinguishable_from_a_missing_one(world):
    theirs = add(world["bob"], "bobs.example.com").json()["id"]
    a = world["alice"].get(f"/api/v1/domains/{theirs}")
    b = world["alice"].get("/api/v1/domains/no-such-id")
    assert a.status_code == b.status_code == 404
    assert a.json() == b.json()


def test_the_verification_token_is_never_shown_to_anyone_else(world):
    token = add(world["bob"]).json()["verification"]["record_value"]
    assert token not in world["alice"].get("/api/v1/domains").text
    assert token not in world["anon"].get("/api/v1/domains").text


# --- verifying -------------------------------------------------------------------------------

def test_publishing_the_record_verifies_the_domain(world, monkeypatch):
    created = add(world["alice"]).json()
    asked = publishing(monkeypatch, "v=spf1 -all", created["verification"]["record_value"])

    response = world["alice"].post(f"/api/v1/domains/{created['id']}/verify")

    assert response.status_code == 200
    body = response.json()
    assert body["verified"] is True and body["reason"] == "verified"
    assert body["domain"]["verification_status"] == "verified" and body["domain"]["verified_at"]
    assert asked == ["_cerberus-challenge.example.com"]
    assert world["alice"].get(f"/api/v1/domains/{created['id']}").json()["verification_status"] == "verified"


def test_a_missing_record_is_a_normal_answer_not_an_error(world, monkeypatch):
    created = add(world["alice"]).json()
    dns_says(monkeypatch, verification.RecordNotFound)
    response = world["alice"].post(f"/api/v1/domains/{created['id']}/verify")
    assert response.status_code == 200
    body = response.json()
    assert body["verified"] is False and body["reason"] == "record_not_found"
    assert body["domain"]["verification_status"] == "pending"
    assert "_cerberus-challenge.example.com" in body["detail"]


def test_a_wrong_value_does_not_verify(world, monkeypatch):
    created = add(world["alice"]).json()
    publishing(monkeypatch, "cerberus-verify=somebody-elses-token")
    body = world["alice"].post(f"/api/v1/domains/{created['id']}/verify").json()
    assert body["verified"] is False and body["reason"] == "token_mismatch"


def test_an_unreachable_resolver_is_not_reported_as_a_missing_record(world, monkeypatch):
    created = add(world["alice"]).json()
    dns_says(monkeypatch, verification.LookupUnavailable)
    body = world["alice"].post(f"/api/v1/domains/{created['id']}/verify").json()
    assert body["reason"] == "lookup_failed" and body["domain"]["verification_status"] == "pending"


def test_a_verified_domain_is_not_looked_up_again(world, monkeypatch):
    created = add(world["alice"]).json()
    publishing(monkeypatch, created["verification"]["record_value"])
    world["alice"].post(f"/api/v1/domains/{created['id']}/verify")
    asked = publishing(monkeypatch)  # now DNS would say nothing
    body = world["alice"].post(f"/api/v1/domains/{created['id']}/verify").json()
    assert body["verified"] is True and asked == []


def test_you_cannot_verify_a_domain_that_is_not_yours(world, monkeypatch):
    theirs = add(world["bob"]).json()
    publishing(monkeypatch, theirs["verification"]["record_value"])
    assert world["alice"].post(f"/api/v1/domains/{theirs['id']}/verify").status_code == 404


def test_the_first_to_prove_control_owns_the_domain(world, monkeypatch):
    a, b = add(world["alice"]).json(), add(world["bob"]).json()
    publishing(monkeypatch, a["verification"]["record_value"], b["verification"]["record_value"])

    assert world["alice"].post(f"/api/v1/domains/{a['id']}/verify").json()["verified"] is True
    late = world["bob"].post(f"/api/v1/domains/{b['id']}/verify")

    assert late.status_code == 409 and late.json()["error"]["code"] == "domain_already_verified"
    assert world["bob"].get(f"/api/v1/domains/{b['id']}").json()["verification_status"] == "pending"


def test_only_the_dns_owner_can_verify_because_the_token_is_secret(world, monkeypatch):
    """Bob knows Alice claimed example.com but not her token, so he cannot publish it."""
    a = add(world["alice"]).json()
    add(world["bob"])
    publishing(monkeypatch)  # nothing published: the real DNS owner has not acted
    assert world["bob"].post(f"/api/v1/domains/{a['id']}/verify").status_code == 404
    assert world["alice"].post(f"/api/v1/domains/{a['id']}/verify").json()["verified"] is False


def test_verification_attempts_are_rate_limited(world, monkeypatch):
    created = add(world["alice"]).json()
    dns_says(monkeypatch, verification.RecordNotFound)
    codes = [world["alice"].post(f"/api/v1/domains/{created['id']}/verify").status_code for _ in range(31)]
    assert codes[:30] == [200] * 30 and codes[30] == 429


# --- the whole path: claim -> verify -> scan ---------------------------------------------------

def test_a_domain_can_be_scanned_only_after_it_is_verified(world, monkeypatch):
    started: list[str] = []
    monkeypatch.setattr("api.main.run_pipeline", lambda scan_id, config: started.append(scan_id))
    created = add(world["alice"]).json()

    before = world["alice"].post("/api/v1/scans", json={"domain_id": created["id"]})
    assert before.status_code == 403 and before.json()["error"]["code"] == "domain_not_verified"

    publishing(monkeypatch, created["verification"]["record_value"])
    world["alice"].post(f"/api/v1/domains/{created['id']}/verify")

    after = world["alice"].post("/api/v1/scans", json={"domain_id": created["id"]})
    assert after.status_code == 202 and started == [after.json()["scan_id"]]
    scan = world["session"].get(Scan, after.json()["scan_id"])
    assert scan.target_domain == "example.com" and scan.user_id == world["users"]["alice"].id


def test_losing_verified_status_stops_scanning(world, monkeypatch):
    """Nothing caches the verdict: the scan check reads the domain's current status."""
    monkeypatch.setattr("api.main.run_pipeline", lambda scan_id, config: None)
    created = add(world["alice"]).json()
    domain = world["session"].get(Domain, created["id"])
    domain.verification_status, domain.verified_at = "verified", utcnow()
    world["session"].flush()
    assert world["alice"].post("/api/v1/scans", json={"domain_id": created["id"]}).status_code == 202

    for scan in world["session"].query(Scan):  # let the next scan start
        scan.status = "completed"
    domain.verification_status = "failed"
    world["session"].flush()
    assert world["alice"].post("/api/v1/scans", json={"domain_id": created["id"]}).status_code == 403


def test_testbeds_listing_and_add(world):
    alice = world["alice"]
    resp = alice.get("/api/v1/domains/testbeds")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 5
    ids = [t["id"] for t in data["testbeds"]]
    assert "testasp" in ids
    assert "apache-lab" in ids
    assert "juice-shop" in ids
    assert "dvwa" in ids

    # Add testasp
    post_resp = alice.post("/api/v1/domains/testbeds/testasp")
    assert post_resp.status_code == 200
    target = post_resp.json()
    assert target["domain"] == "testasp.vulnweb.com"
    assert target["verification_status"] == "verified"
    assert target["verification_method"] == "testbed"

    # Listing testbeds now shows already_added=True for testasp
    after_resp = alice.get("/api/v1/domains/testbeds")
    testasp = next(t for t in after_resp.json()["testbeds"] if t["id"] == "testasp")
    assert testasp["already_added"] is True
    assert testasp["domain_id"] == target["id"]

    # Bob can also add testasp without colliding on unique verified owner
    bob = world["bob"]
    bob_resp = bob.post("/api/v1/domains/testbeds/testasp")
    assert bob_resp.status_code == 200
    assert bob_resp.json()["verification_status"] == "verified"

