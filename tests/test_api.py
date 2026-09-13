from datetime import date

import pytest
from fastapi.testclient import TestClient

from api.main import app, get_session
from core.models import Asset, AssetCriticality, CveEnrichment, Finding, Tenant

AUTH = {"Authorization": "Bearer test-key"}


@pytest.fixture
def client(session):
    tenant = Tenant(name="test")
    session.add(tenant)
    session.flush()

    asset = Asset(tenant_id=tenant.id, hostname="api.example.com", port=443, protocol="tcp",
                  ip_address="203.0.113.10", technology="nginx/1.24.0")
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
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_healthz_needs_no_auth(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_missing_token_is_rejected(client):
    response = client.get("/api/v1/findings")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


def test_findings_are_ranked_by_risk(client):
    body = client.get("/api/v1/findings", headers=AUTH).json()
    assert body["total"] == 2
    assert [f["cve_id"] for f in body["findings"]] == ["CVE-2021-0001", "CVE-2021-0002"]


def test_kev_only_filter(client):
    body = client.get("/api/v1/findings?kev_only=true", headers=AUTH).json()
    assert [f["cve_id"] for f in body["findings"]] == ["CVE-2021-0001"]


def test_min_risk_score_filter(client):
    body = client.get("/api/v1/findings?min_risk_score=50", headers=AUTH).json()
    assert body["total"] == 1


def test_finding_detail_includes_reasoning_and_enrichment(client):
    listed = client.get("/api/v1/findings", headers=AUTH).json()["findings"][0]
    detail = client.get(f"/api/v1/findings/{listed['id']}", headers=AUTH).json()
    assert detail["kev_listed"] is True
    assert detail["asset"]["hostname"] == "api.example.com"
    assert detail["reasoning"]


def test_unknown_finding_returns_404(client):
    response = client.get("/api/v1/findings/nope", headers=AUTH)
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_status_can_be_updated(client):
    listed = client.get("/api/v1/findings", headers=AUTH).json()["findings"][0]
    response = client.patch(f"/api/v1/findings/{listed['id']}", headers=AUTH, json={"status": "resolved"})
    assert response.json()["status"] == "resolved"


def test_invalid_status_is_rejected(client):
    listed = client.get("/api/v1/findings", headers=AUTH).json()["findings"][0]
    response = client.patch(f"/api/v1/findings/{listed['id']}", headers=AUTH, json={"status": "bogus"})
    assert response.status_code == 400


def test_scan_requires_authorization_attestation(client):
    response = client.post("/api/v1/scans", headers=AUTH,
                           json={"target_domain": "example.com", "authorized": False})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"


def test_assets_are_listed(client):
    body = client.get("/api/v1/assets", headers=AUTH).json()
    assert body["total"] == 1
    assert body["assets"][0]["technology"] == "nginx/1.24.0"


def test_authorized_scan_is_accepted(client, monkeypatch):
    """The scan endpoint must create its row on the request's own session.

    Opening a second write transaction here deadlocks on SQLite, so this exercises
    the create_scan_record path rather than start_scan.
    """
    started: list[str] = []
    monkeypatch.setattr("api.main.run_pipeline", lambda scan_id, config: started.append(scan_id))

    response = client.post(
        "/api/v1/scans", headers=AUTH, json={"target_domain": "example.com", "authorized": True}
    )

    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "pending"
    assert started == [body["scan_id"]]


def test_second_scan_while_one_is_running_is_rejected(client, monkeypatch):
    monkeypatch.setattr("api.main.run_pipeline", lambda scan_id, config: None)
    payload = {"target_domain": "example.com", "authorized": True}

    assert client.post("/api/v1/scans", headers=AUTH, json=payload).status_code == 202
    conflict = client.post("/api/v1/scans", headers=AUTH, json=payload)

    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "scan_in_progress"


def test_scan_defaults_to_the_safe_profile(client, monkeypatch):
    monkeypatch.setattr("api.main.run_pipeline", lambda scan_id, config: None)
    response = client.post(
        "/api/v1/scans", headers=AUTH, json={"target_domain": "example.com", "authorized": True}
    )
    assert response.status_code == 202
    assert response.json()["profile"] == "safe"


def test_intrusive_profile_is_refused_without_opt_in(client, monkeypatch):
    monkeypatch.setattr("api.main.run_pipeline", lambda scan_id, config: None)
    response = client.post(
        "/api/v1/scans",
        headers=AUTH,
        json={"target_domain": "example.com", "authorized": True, "profile": "thorough"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_profile"


def test_intrusive_profile_is_accepted_with_explicit_opt_in(client, monkeypatch):
    monkeypatch.setattr("api.main.run_pipeline", lambda scan_id, config: None)
    response = client.post(
        "/api/v1/scans",
        headers=AUTH,
        json={
            "target_domain": "example.com",
            "authorized": True,
            "profile": "thorough",
            "accept_profile": True,
        },
    )
    assert response.status_code == 202
    assert response.json()["profile"] == "thorough"


def test_unknown_profile_is_refused(client, monkeypatch):
    monkeypatch.setattr("api.main.run_pipeline", lambda scan_id, config: None)
    response = client.post(
        "/api/v1/scans",
        headers=AUTH,
        json={"target_domain": "example.com", "authorized": True, "profile": "yolo"},
    )
    assert response.status_code == 400
