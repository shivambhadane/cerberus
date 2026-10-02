from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient

from api.main import app, get_session
from core.models import Asset, AssetCriticality, CveEnrichment, Domain, Finding, Scan, Tenant, utcnow
from core.security import create_access_token
from tests.helpers import auth_for


@pytest.fixture
def client(session, make_user):
    """A signed-in client. `client.user` is its owner; `client.tenant` the legacy tenant."""
    tenant = Tenant(name="test")
    session.add(tenant)
    session.flush()
    user = make_user()

    asset = Asset(tenant_id=tenant.id, user_id=user.id, hostname="api.example.com", port=443,
                  protocol="tcp", ip_address="203.0.113.10", technology="nginx/1.24.0")
    session.add(asset)
    session.flush()
    session.add(AssetCriticality(asset_id=asset.id, level="high", reason="production API"))

    session.add(CveEnrichment(cve_id="CVE-2021-0001", cvss_score=6.5, kev_listed=True,
                              kev_date_added=date(2023, 11, 1), epss_score=0.94,
                              description="actively exploited flaw"))
    session.add(CveEnrichment(cve_id="CVE-2021-0002", cvss_score=9.8, kev_listed=False, epss_score=0.01))
    session.flush()

    session.add(Finding(asset_id=asset.id, cve_id="CVE-2021-0001", risk_score=98.0,
                        reasoning="Actively exploited (CISA KEV).", status="open"))
    session.add(Finding(asset_id=asset.id, cve_id="CVE-2021-0002", risk_score=31.6,
                        reasoning="No evidence of exploitation.", status="open"))
    session.flush()

    app.dependency_overrides[get_session] = lambda: session
    test_client = TestClient(app, headers=auth_for(user))
    test_client.user, test_client.tenant = user, tenant
    yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def anon(client):
    """The same app with no credentials (depends on `client` for the database override)."""
    return TestClient(app)


def test_healthz_needs_no_auth(anon):
    assert anon.get("/healthz").json() == {"status": "ok"}


def test_missing_token_is_rejected(anon):
    response = anon.get("/api/v1/findings")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


def test_findings_are_ranked_by_risk(client):
    body = client.get("/api/v1/findings").json()
    assert body["total"] == 2
    assert [f["cve_id"] for f in body["findings"]] == ["CVE-2021-0001", "CVE-2021-0002"]


def test_kev_only_filter(client):
    body = client.get("/api/v1/findings?kev_only=true").json()
    assert [f["cve_id"] for f in body["findings"]] == ["CVE-2021-0001"]


def test_min_risk_score_filter(client):
    body = client.get("/api/v1/findings?min_risk_score=50").json()
    assert body["total"] == 1


def test_finding_detail_includes_reasoning_and_enrichment(client):
    listed = client.get("/api/v1/findings").json()["findings"][0]
    detail = client.get(f"/api/v1/findings/{listed['id']}").json()
    assert detail["kev_listed"] is True
    assert detail["asset"]["hostname"] == "api.example.com"
    assert detail["reasoning"]


def test_unknown_finding_returns_404(client):
    response = client.get("/api/v1/findings/nope")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_status_can_be_updated(client):
    listed = client.get("/api/v1/findings").json()["findings"][0]
    response = client.patch(f"/api/v1/findings/{listed['id']}", json={"status": "resolved"})
    assert response.json()["status"] == "resolved"


def test_invalid_status_is_rejected(client):
    listed = client.get("/api/v1/findings").json()["findings"][0]
    response = client.patch(f"/api/v1/findings/{listed['id']}", json={"status": "bogus"})
    assert response.status_code == 400


def test_assets_are_listed(client):
    body = client.get("/api/v1/assets").json()
    assert body["total"] == 1
    assert body["assets"][0]["technology"] == "nginx/1.24.0"


# --- scanning: a verified domain, not a claim ----------------------------------------------------

@pytest.fixture
def domains(client, session, make_user):
    """example.com (verified, mine), pending.example.org (mine, unverified), and a verified
    domain that belongs to somebody else."""
    other = make_user("other@example.com")
    mine = Domain(user_id=client.user.id, domain="example.com", verification_status="verified",
                  verified_at=utcnow())
    pending = Domain(user_id=client.user.id, domain="pending.example.org")
    theirs = Domain(user_id=other.id, domain="theirs.example.net", verification_status="verified",
                    verified_at=utcnow())
    session.add_all([mine, pending, theirs])
    session.flush()
    return {"mine": mine, "pending": pending, "theirs": theirs, "other": other}


@pytest.fixture
def no_pipeline(monkeypatch):
    """Record what would run instead of running a scan."""
    started: list[str] = []
    monkeypatch.setattr("api.main.run_pipeline", lambda scan_id, config: started.append(scan_id))
    return started


def test_a_verified_domain_can_be_scanned(client, domains, no_pipeline, session):
    """The endpoint must create its row on the request's own session: opening a second write
    transaction here deadlocks on SQLite."""
    response = client.post("/api/v1/scans", json={"domain_id": domains["mine"].id})

    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "pending" and body["profile"] == "safe"
    assert no_pipeline == [body["scan_id"]]

    scan = session.get(Scan, body["scan_id"])
    assert scan.target_domain == "example.com"  # the target comes from the verified domain
    assert (scan.user_id, scan.domain_id) == (client.user.id, domains["mine"].id)


def test_a_new_scan_has_no_progress_until_the_pipeline_writes_some(client, domains, no_pipeline):
    """Never a fabricated 0%: a scan the background task has not touched yet reports no
    progress at all, not an empty-but-present one."""
    response = client.post("/api/v1/scans", json={"domain_id": domains["mine"].id})
    body = client.get(f"/api/v1/scans/{response.json()['scan_id']}").json()
    assert body["progress"] is None


def test_scan_progress_is_exposed_once_the_pipeline_records_it(
    client, domains, no_pipeline, session, monkeypatch
):
    from core.pipeline import _record_stage

    class _OneSession:
        def __enter__(self): return session
        def __exit__(self, *_a): return False

    monkeypatch.setattr("core.pipeline.session_scope", lambda: _OneSession())

    response = client.post("/api/v1/scans", json={"domain_id": domains["mine"].id})
    scan_id = response.json()["scan_id"]
    _record_stage(scan_id, "asset_discovery", {"subdomains": 2})

    body = client.get(f"/api/v1/scans/{scan_id}").json()
    assert body["progress"]["completed"] == ["asset_discovery"]
    assert body["progress"]["current"] == "dns_resolution"
    assert body["progress"]["counts"] == {"subdomains": 2}

    listing = client.get("/api/v1/scans").json()
    mine = next(s for s in listing["scans"] if s["scan_id"] == scan_id)
    assert mine["progress"]["completed"] == ["asset_discovery"]  # the list endpoint carries it too


def test_there_is_no_authorised_flag_to_send(client, domains, no_pipeline):
    """The old request ({target_domain, authorized: true}) is gone: a claim is not evidence."""
    old = client.post("/api/v1/scans", json={"target_domain": "example.com", "authorized": True})
    assert old.status_code == 422
    assert no_pipeline == []


def test_an_unverified_domain_is_refused_with_what_to_do(client, domains, no_pipeline):
    response = client.post("/api/v1/scans", json={"domain_id": domains["pending"].id})
    assert response.status_code == 403
    error = response.json()["error"]
    assert error["code"] == "domain_not_verified"
    assert "verify" in error["message"].lower()
    assert no_pipeline == []


def test_someone_elses_domain_looks_like_no_domain(client, domains, no_pipeline):
    """Even a verified one: the answer must not reveal that it exists, or whose it is."""
    theirs = client.post("/api/v1/scans", json={"domain_id": domains["theirs"].id})
    missing = client.post("/api/v1/scans", json={"domain_id": "no-such-id"})
    assert theirs.status_code == missing.status_code == 404
    assert theirs.json() == missing.json()
    assert no_pipeline == []


def test_a_scan_needs_a_signed_in_user(client, domains, anon, no_pipeline):
    assert anon.post("/api/v1/scans", json={"domain_id": domains["mine"].id}).status_code == 401
    assert no_pipeline == []


def test_a_second_scan_while_one_is_running_is_rejected(client, domains, no_pipeline):
    payload = {"domain_id": domains["mine"].id}
    assert client.post("/api/v1/scans", json=payload).status_code == 202
    conflict = client.post("/api/v1/scans", json=payload)
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "scan_in_progress"


def test_one_users_running_scan_does_not_block_another_user(client, domains, no_pipeline, session):
    session.add(Scan(tenant_id=client.tenant.id, user_id=domains["other"].id,
                     target_domain="theirs.example.net", status="discovering"))
    session.flush()
    assert client.post("/api/v1/scans", json={"domain_id": domains["mine"].id}).status_code == 202


def test_scan_defaults_to_the_safe_profile(client, domains, no_pipeline):
    response = client.post("/api/v1/scans", json={"domain_id": domains["mine"].id})
    assert response.json()["profile"] == "safe"


def test_intrusive_profile_is_refused_without_opt_in(client, domains, no_pipeline):
    response = client.post("/api/v1/scans", json={"domain_id": domains["mine"].id, "profile": "thorough"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_profile"


def test_intrusive_profile_is_accepted_with_explicit_opt_in(client, domains, no_pipeline):
    response = client.post(
        "/api/v1/scans",
        json={"domain_id": domains["mine"].id, "profile": "thorough", "accept_profile": True},
    )
    assert response.status_code == 202
    assert response.json()["profile"] == "thorough"


def test_unknown_profile_is_refused(client, domains, no_pipeline):
    response = client.post("/api/v1/scans", json={"domain_id": domains["mine"].id, "profile": "yolo"})
    assert response.status_code == 400


def test_a_disabled_account_can_do_nothing(client, domains, no_pipeline, session):
    """Not even with a token that has not expired yet."""
    client.user.is_active = False
    session.flush()
    assert client.get("/api/v1/findings").status_code == 401
    assert client.post("/api/v1/scans", json={"domain_id": domains["mine"].id}).status_code == 401


# --- authentication hardening ---------------------------------------------------------------

def test_only_the_bearer_scheme_is_accepted(client, anon):
    token = client.headers["Authorization"].split(" ", 1)[1]
    assert anon.get("/api/v1/findings", headers={"Authorization": f"Basic {token}"}).status_code == 401
    assert anon.get("/api/v1/findings", headers={"Authorization": token}).status_code == 401
    assert anon.get("/api/v1/findings", headers={"Authorization": f"bearer {token}"}).status_code == 401


GARBAGE = ["Bearer ", "Bearer", "", "Bearer null", "Bearer a.b.c", "Bearer " + "x" * 300]


@pytest.mark.parametrize("header", GARBAGE)
def test_garbage_credentials_are_rejected(client, anon, header):
    response = anon.get("/api/v1/findings", headers={"Authorization": header})
    assert response.status_code == 401
    assert response.json()["error"]["code"] in {"unauthorized", "token_invalid"}


def test_a_token_signed_with_a_different_secret_is_rejected(client, anon):
    forged = create_access_token(
        client.user.id, "an-attacker-chosen-secret-" + "z" * 30, timedelta(minutes=15)
    )
    response = anon.get("/api/v1/findings", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401 and response.json()["error"]["code"] == "token_invalid"


def test_an_expired_token_says_so_so_the_client_can_refresh(client, anon):
    import os

    stale = create_access_token(client.user.id, os.environ["API_SECRET_KEY"], timedelta(minutes=15),
                                now=utcnow() - timedelta(hours=1))
    response = anon.get("/api/v1/findings", headers={"Authorization": f"Bearer {stale}"})
    assert response.status_code == 401 and response.json()["error"]["code"] == "token_expired"


def test_a_valid_token_for_a_user_who_no_longer_exists_is_rejected(client, anon, session):
    session.delete(client.user)
    session.flush()
    assert client.get("/api/v1/findings").status_code == 401


def test_the_shared_api_key_no_longer_authenticates(anon):
    """The old model: the API_SECRET_KEY itself was the bearer token."""
    import os

    key = os.environ["API_SECRET_KEY"]
    response = anon.get("/api/v1/findings", headers={"Authorization": f"Bearer {key}"})
    assert response.status_code == 401


def test_the_api_refuses_to_start_with_an_unusable_secret(monkeypatch):
    from api.main import check_api_secret

    monkeypatch.delenv("CERBERUS_ALLOW_INSECURE_DEV", raising=False)
    for weak in ("", "change-me", "short-secret", "x" * 31):
        monkeypatch.setenv("API_SECRET_KEY", weak)
        with pytest.raises(RuntimeError, match="API_SECRET_KEY"):
            check_api_secret()


def test_a_real_secret_starts_and_the_dev_escape_hatch_is_explicit(monkeypatch):
    from api.main import check_api_secret

    monkeypatch.setenv("API_SECRET_KEY", "a-real-random-secret-of-sufficient-length-1234")
    check_api_secret()  # no error

    monkeypatch.setenv("API_SECRET_KEY", "change-me")
    monkeypatch.setenv("CERBERUS_ALLOW_INSECURE_DEV", "1")
    check_api_secret()  # explicit opt-out for throwaway local use
