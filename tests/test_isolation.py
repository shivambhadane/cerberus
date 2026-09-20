"""One user must never see, or touch, another user's data through any endpoint.

Two users each own a full set of records (asset, finding, scan, evidence, criticality). Every read
must return only the caller's; every direct reference to the other user's record must look exactly
like a record that does not exist.
"""

from datetime import date

import pytest
from fastapi.testclient import TestClient

from api.main import app, get_session
from core.models import (
    Asset,
    AssetCriticality,
    CveEnrichment,
    Domain,
    Finding,
    ObservationRecord,
    Scan,
    Tenant,
    utcnow,
)
from tests.helpers import auth_for


@pytest.fixture
def two_users(session, make_user):
    tenant = Tenant(name="shared")  # the legacy tenant is shared: ownership must not depend on it
    session.add(tenant)
    session.add_all([
        CveEnrichment(cve_id="CVE-2021-0001", cvss_score=9.8, kev_listed=True,
                      kev_date_added=date(2023, 1, 1)),
        CveEnrichment(cve_id="CVE-2022-0002", cvss_score=5.0, kev_listed=False),
    ])
    session.flush()

    def build(name, host, cve, risk):
        user = make_user(f"{name}@example.com")
        domain = Domain(user_id=user.id, domain=f"{name}.example", verification_status="verified",
                        verified_at=utcnow())
        session.add(domain)
        session.flush()
        scan = Scan(tenant_id=tenant.id, user_id=user.id, domain_id=domain.id, target_domain=domain.domain,
                    status="completed")
        session.add(scan)
        session.flush()
        asset = Asset(tenant_id=tenant.id, user_id=user.id, domain_id=domain.id,
                      discovered_by_scan_id=scan.id, hostname=host, port=443, protocol="tcp")
        session.add(asset)
        session.flush()
        session.add(AssetCriticality(asset_id=asset.id, level="medium", reason="test"))
        finding = Finding(asset_id=asset.id, cve_id=cve, risk_score=risk, status="open")
        session.add(finding)
        session.add(ObservationRecord(scan_id=scan.id, kind="open_port", target=f"{host}:443",
                                      source_tool="nmap", data={}))
        session.flush()
        return {"user": user, "domain": domain, "scan": scan, "asset": asset, "finding": finding,
                "client": TestClient(app, headers=auth_for(user))}

    app.dependency_overrides[get_session] = lambda: session
    world = {"alice": build("alice", "alice.example", "CVE-2021-0001", 90.0),
             "bob": build("bob", "bob.example", "CVE-2022-0002", 40.0)}
    world["session"] = session
    yield world
    app.dependency_overrides.clear()


def test_each_user_lists_only_their_own_findings(two_users):
    for me, other in (("alice", "bob"), ("bob", "alice")):
        body = two_users[me]["client"].get("/api/v1/findings").json()
        assert [f["id"] for f in body["findings"]] == [two_users[me]["finding"].id]
        assert body["total"] == 1
        assert two_users[other]["finding"].id not in str(body)


def test_a_search_cannot_reach_across_users(two_users):
    """The other user's host, CVE and even a query naming them return nothing."""
    alice = two_users["alice"]["client"]
    assert alice.get("/api/v1/findings?q=bob.example").json()["total"] == 0
    assert alice.get("/api/v1/findings?q=CVE-2022-0002").json()["total"] == 0
    assert alice.get(f"/api/v1/findings?asset_id={two_users['bob']['asset'].id}").json()["total"] == 0


def test_another_users_finding_looks_like_a_missing_one(two_users):
    alice, theirs = two_users["alice"]["client"], two_users["bob"]["finding"].id
    got, missing = alice.get(f"/api/v1/findings/{theirs}"), alice.get("/api/v1/findings/nope")
    assert got.status_code == missing.status_code == 404
    assert got.json()["error"]["code"] == missing.json()["error"]["code"]


def test_you_cannot_change_another_users_finding(two_users, session):
    alice, theirs = two_users["alice"]["client"], two_users["bob"]["finding"]
    assert alice.patch(f"/api/v1/findings/{theirs.id}", json={"status": "resolved"}).status_code == 404
    assert theirs.status == "open"


def test_each_user_lists_only_their_own_assets(two_users):
    body = two_users["alice"]["client"].get("/api/v1/assets").json()
    assert [a["hostname"] for a in body["assets"]] == ["alice.example"] and body["total"] == 1
    bobs_scan = two_users["bob"]["scan"].id
    assert two_users["alice"]["client"].get(f"/api/v1/assets?scan_id={bobs_scan}").json()["total"] == 0


def test_you_cannot_change_another_users_criticality(two_users, session):
    alice, theirs = two_users["alice"]["client"], two_users["bob"]["asset"]
    response = alice.patch(f"/api/v1/assets/{theirs.id}/criticality", json={"level": "critical"})
    assert response.status_code == 404
    tag = session.query(AssetCriticality).filter_by(asset_id=theirs.id).one()
    assert tag.level == "medium" and tag.source != "manual"


def test_each_user_lists_only_their_own_scans(two_users):
    body = two_users["alice"]["client"].get("/api/v1/scans").json()
    assert [s["scan_id"] for s in body["scans"]] == [two_users["alice"]["scan"].id] and body["total"] == 1


def test_another_users_scan_looks_like_a_missing_one(two_users):
    alice = two_users["alice"]["client"]
    theirs = alice.get(f"/api/v1/scans/{two_users['bob']['scan'].id}")
    missing = alice.get("/api/v1/scans/nope")
    assert theirs.status_code == missing.status_code == 404
    assert alice.get(f"/api/v1/scans/{two_users['alice']['scan'].id}").status_code == 200


def test_evidence_is_confined_to_your_own_scans(two_users):
    alice = two_users["alice"]["client"]
    own = alice.get("/api/v1/observations").json()
    assert [o["target"] for o in own["observations"]] == ["alice.example:443"]
    assert alice.get(f"/api/v1/observations?scan_id={two_users['bob']['scan'].id}").json()["total"] == 0
    assert alice.get("/api/v1/observations?target=bob.example:443").json()["total"] == 0


def test_the_overview_counts_only_your_own_data(two_users):
    a = two_users["alice"]["client"].get("/api/v1/overview").json()
    b = two_users["bob"]["client"].get("/api/v1/overview").json()
    assert (a["findings"]["active"], a["findings"]["actively_exploited"], a["assets"]["total"]) == (1, 1, 1)
    assert (b["findings"]["active"], b["findings"]["actively_exploited"], b["assets"]["total"]) == (1, 0, 1)
    assert a["scans_total"] == b["scans_total"] == 1
    assert a["last_scan"]["scan_id"] == two_users["alice"]["scan"].id
    assert a["findings"]["by_risk_band"]["critical"] == 1 and b["findings"]["by_risk_band"]["critical"] == 0


def test_unowned_legacy_data_is_visible_to_no_one(two_users, session):
    """Rows from before accounts existed have no owner, so nobody sees them until they are claimed."""
    tenant = session.query(Tenant).one()
    orphan = Asset(tenant_id=tenant.id, hostname="legacy.example", port=80, protocol="tcp")
    session.add(orphan)
    session.flush()
    session.add(Finding(asset_id=orphan.id, cve_id="CVE-2021-0001", risk_score=99.0, status="open"))
    session.add(Scan(tenant_id=tenant.id, target_domain="legacy.example", status="completed"))
    session.flush()
    for who in ("alice", "bob"):
        client = two_users[who]["client"]
        assert client.get("/api/v1/findings?q=legacy").json()["total"] == 0
        assert "legacy.example" not in client.get("/api/v1/assets").text
        assert "legacy.example" not in client.get("/api/v1/scans").text
        assert client.get("/api/v1/overview").json()["assets"]["total"] == 1


def test_a_users_scan_can_only_use_their_own_domain(two_users):
    alice = two_users["alice"]["client"]
    theirs = alice.post("/api/v1/scans", json={"domain_id": two_users["bob"]["domain"].id})
    assert theirs.status_code == 404


def test_shared_reference_data_is_readable_by_any_signed_in_user(two_users):
    for who in ("alice", "bob"):
        assert two_users[who]["client"].get("/api/v1/enrichment/status").status_code == 200


def test_every_data_endpoint_refuses_anonymous_callers(two_users):
    anon = TestClient(app)
    for path in ("/api/v1/findings", "/api/v1/assets", "/api/v1/scans", "/api/v1/observations",
                 "/api/v1/overview", "/api/v1/enrichment/status", "/api/v1/domains", "/api/v1/auth/me"):
        assert anon.get(path).status_code == 401, path
    for path, body in (("/api/v1/scans", {"domain_id": "x"}), ("/api/v1/domains", {"domain": "example.com"})):
        assert anon.post(path, json=body).status_code == 401, path
