"""API behaviour behind the dashboard: search, filters, sorting, scan history, warnings,
evidence-by-target, and editing asset criticality."""

from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient

from api.main import app, get_session
from core.adapters import Endpoint, Observation, ObservationKind
from core.models import (
    Asset,
    AssetCriticality,
    CveEnrichment,
    Finding,
    ObservationRecord,
    Scan,
    Tenant,
    utcnow,
)
from tests.helpers import auth_for


@pytest.fixture
def world(session, make_user):
    tenant = Tenant(name="t")
    session.add(tenant)
    session.flush()
    user = make_user()

    web = Asset(tenant_id=tenant.id, user_id=user.id, hostname="api.example.com", port=443, protocol="tcp",
                technology="nginx/1.24.0", discovered_by_tool="nmap")
    db = Asset(tenant_id=tenant.id, user_id=user.id, hostname="db.example.com", port=5432, protocol="tcp")
    session.add_all([web, db])
    session.flush()
    session.add(AssetCriticality(asset_id=web.id, level="high", reason="hostname says api"))

    session.add_all([
        CveEnrichment(cve_id="CVE-2021-0001", cvss_score=6.5, kev_listed=True,
                      kev_date_added=date(2023, 11, 1), epss_score=0.94),
        CveEnrichment(cve_id="CVE-2021-0002", cvss_score=9.8, kev_listed=False, epss_score=0.01),
        CveEnrichment(cve_id="CVE-2022-0003", cvss_score=None, kev_listed=False, epss_score=None),
    ])
    session.flush()
    findings = {
        "kev": Finding(asset_id=web.id, cve_id="CVE-2021-0001", risk_score=90.0, status="open",
                       detection_method="active_detection", detected_by_tool="nuclei"),
        "quiet": Finding(asset_id=web.id, cve_id="CVE-2021-0002", risk_score=30.0, status="open",
                         detection_method="version_inference"),
        "nocvss": Finding(asset_id=db.id, cve_id="CVE-2022-0003", risk_score=10.0, status="resolved",
                          detection_method="version_inference"),
    }
    session.add_all(findings.values())
    session.flush()

    scan = Scan(tenant_id=tenant.id, user_id=user.id, target_domain="example.com", profile="safe",
                status="completed",
                started_at=utcnow() - timedelta(hours=1), completed_at=utcnow(),
                warnings=["nuclei: nuclei timed out after 1800s"])
    older = Scan(tenant_id=tenant.id, user_id=user.id, target_domain="old.example.com", profile="passive",
                 status="failed", error="boom", started_at=utcnow() - timedelta(days=2))
    session.add_all([scan, older])
    session.flush()
    session.add_all([
        ObservationRecord(scan_id=scan.id, kind="open_port", target="api.example.com:443",
                          source_tool="nmap", data={}),
        ObservationRecord(scan_id=scan.id, kind="open_port", target="db.example.com:5432",
                          source_tool="tcp_connect", data={}),
    ])
    session.flush()

    app.dependency_overrides[get_session] = lambda: session
    yield {
        "client": TestClient(app, headers=auth_for(user)), "anon": TestClient(app), "user": user,
        "web": web, "db": db, "scan": scan, "older": older, "findings": findings, "session": session,
    }
    app.dependency_overrides.clear()


def ids(response, key="findings", field="cve_id"):
    return [row[field] for row in response.json()[key]]


# --- findings: search, filters, sorting ---------------------------------------------------------

def test_search_matches_cve_id_case_insensitively(world):
    r = world["client"].get("/api/v1/findings?q=cve-2021-0001")
    assert ids(r) == ["CVE-2021-0001"]


def test_search_matches_hostname(world):
    r = world["client"].get("/api/v1/findings?q=DB.example")
    assert ids(r) == ["CVE-2022-0003"]


def test_active_status_hides_resolved_findings(world):
    r = world["client"].get("/api/v1/findings?status=active")
    assert set(ids(r)) == {"CVE-2021-0001", "CVE-2021-0002"}
    assert r.json()["total"] == 2


def test_status_accepts_a_list_and_rejects_unknown_values(world):
    ok = world["client"].get("/api/v1/findings?status=resolved,open")
    assert ok.json()["total"] == 3
    bad = world["client"].get("/api/v1/findings?status=bogus")
    assert bad.status_code == 400 and "bogus" in bad.json()["error"]["message"]


def test_filter_by_detection_method(world):
    r = world["client"].get("/api/v1/findings?detection_method=active_detection")
    assert ids(r) == ["CVE-2021-0001"]
    assert world["client"].get("/api/v1/findings?detection_method=nope").status_code == 422


def test_filter_by_asset(world):
    r = world["client"].get(f"/api/v1/findings?asset_id={world['db'].id}")
    assert ids(r) == ["CVE-2022-0003"]


def test_sort_by_cvss_puts_missing_values_last_in_both_directions(world):
    """A finding with no CVSS must not float to the top just because NULL sorts oddly."""
    desc = world["client"].get("/api/v1/findings?sort=cvss_score&order=desc")
    asc = world["client"].get("/api/v1/findings?sort=cvss_score&order=asc")
    assert ids(desc) == ["CVE-2021-0002", "CVE-2021-0001", "CVE-2022-0003"]
    assert ids(asc) == ["CVE-2021-0001", "CVE-2021-0002", "CVE-2022-0003"]


def test_pagination_walks_every_finding_exactly_once(world):
    seen = []
    for offset in (0, 1, 2):
        r = world["client"].get(f"/api/v1/findings?limit=1&offset={offset}")
        assert r.json()["total"] == 3
        seen += ids(r)
    assert sorted(seen) == ["CVE-2021-0001", "CVE-2021-0002", "CVE-2022-0003"]


def test_findings_carry_the_asset_id_for_linking(world):
    r = world["client"].get("/api/v1/findings?q=0001")
    assert r.json()["findings"][0]["asset_id"] == world["web"].id


# --- scans: history and warnings ----------------------------------------------------------------

def test_scan_history_is_newest_first_with_observation_counts(world):
    r = world["client"].get("/api/v1/scans").json()
    assert r["total"] == 2
    assert [s["target_domain"] for s in r["scans"]] == ["example.com", "old.example.com"]
    assert r["scans"][0]["observation_count"] == 2
    assert r["scans"][1]["observation_count"] == 0


def test_warnings_reach_the_api(world):
    listed = world["client"].get("/api/v1/scans").json()["scans"][0]
    assert listed["warnings"] == ["nuclei: nuclei timed out after 1800s"]
    single = world["client"].get(f"/api/v1/scans/{world['scan'].id}").json()
    assert single["warnings"] == ["nuclei: nuclei timed out after 1800s"]
    assert world["client"].get(f"/api/v1/scans/{world['older'].id}").json()["warnings"] == []


def test_scan_history_paginates(world):
    r = world["client"].get("/api/v1/scans?limit=1&offset=1").json()
    assert [s["target_domain"] for s in r["scans"]] == ["old.example.com"]


def test_scan_history_requires_auth(world):
    assert world["anon"].get("/api/v1/scans").status_code == 401


# --- evidence behind one asset -----------------------------------------------------------------

def test_observations_can_be_filtered_to_one_target(world):
    r = world["client"].get("/api/v1/observations?target=api.example.com:443").json()
    assert r["total"] == 1
    assert r["observations"][0]["source_tool"] == "nmap"


# --- assets: criticality ------------------------------------------------------------------------

def test_assets_report_criticality_source_and_finding_counts(world):
    rows = {a["hostname"]: a for a in world["client"].get("/api/v1/assets").json()["assets"]}
    assert rows["api.example.com"]["criticality"] == "high"
    assert rows["api.example.com"]["criticality_source"] == "heuristic"
    assert rows["api.example.com"]["finding_count"] == 2
    assert rows["db.example.com"]["criticality"] is None
    assert rows["db.example.com"]["finding_count"] == 1


def test_setting_criticality_marks_it_manual_and_rescores_that_asset(world):
    client, web = world["client"], world["web"]
    r = client.patch(f"/api/v1/assets/{web.id}/criticality",
                     json={"level": "critical", "reason": "customer-facing checkout"})

    assert r.status_code == 200
    body = r.json()
    assert (body["criticality"], body["criticality_source"]) == ("critical", "manual")
    assert body["criticality_reason"] == "customer-facing checkout"

    scored = client.get(f"/api/v1/findings?asset_id={web.id}").json()["findings"]
    assert all(f["risk_score"] not in (90.0, 30.0) for f in scored)  # recomputed, not the fixtures
    assert all("business-critical asset" in f["reasoning"].lower() for f in scored)


def test_editing_one_asset_does_not_rescore_another(world):
    client = world["client"]
    client.patch(f"/api/v1/assets/{world['web'].id}/criticality", json={"level": "low"})
    untouched = client.get(f"/api/v1/findings?asset_id={world['db'].id}").json()["findings"]
    assert untouched[0]["risk_score"] == 10.0


def test_criticality_can_be_set_on_an_asset_that_had_none(world):
    r = world["client"].patch(f"/api/v1/assets/{world['db'].id}/criticality",
                              json={"level": "high"})
    assert r.json()["criticality"] == "high"
    assert r.json()["criticality_reason"] == "set manually"  # a default so the score can explain itself


def test_invalid_criticality_and_unknown_asset_are_rejected(world):
    client = world["client"]
    assert client.patch(f"/api/v1/assets/{world['web'].id}/criticality",
                        json={"level": "apocalyptic"}).status_code == 400
    assert client.patch("/api/v1/assets/nope/criticality",
                        json={"level": "high"}).status_code == 404


def test_a_manual_criticality_survives_a_rescan(world):
    """The point of marking it manual: a re-scan re-runs the hostname heuristic, and must not
    clobber a person's decision."""
    from core.models import Tenant
    from discovery.runner import DiscoveryResult
    from ingestion.normalize import ingest_assets

    session, web = world["session"], world["web"]
    world["client"].patch(f"/api/v1/assets/{web.id}/criticality",
                          json={"level": "critical", "reason": "decided"})

    tenant = session.query(Tenant).one()
    endpoint = Endpoint(web.hostname, "203.0.113.10", web.port, "tcp")
    result = DiscoveryResult(
        observations=[Observation(kind=ObservationKind.OPEN_PORT, target=str(endpoint),
                                  source_tool="tcp_connect",
                                  data={"hostname": web.hostname, "port": web.port})],
        endpoints=[endpoint],
    )
    ingest_assets(session, tenant.id, world["scan"].id, result, user_id=world["user"].id)

    tag = session.query(AssetCriticality).filter_by(asset_id=web.id).one()
    assert (tag.level, tag.source, tag.reason) == ("critical", "manual", "decided")


def test_criticality_requires_auth(world):
    r = world["anon"].patch(f"/api/v1/assets/{world['web'].id}/criticality", json={"level": "high"})
    assert r.status_code == 401


def test_finding_detail_says_where_the_criticality_came_from(world):
    """Regression: the dashboard labelled a person's decision "inferred from hostname" because
    the detail response did not say which it was."""
    client, web = world["client"], world["web"]
    finding_id = client.get(f"/api/v1/findings?asset_id={web.id}").json()["findings"][0]["id"]

    before = client.get(f"/api/v1/findings/{finding_id}").json()
    assert before["asset_criticality_source"] == "heuristic"

    client.patch(f"/api/v1/assets/{web.id}/criticality",
                 json={"level": "critical", "reason": "customer-facing checkout"})
    after = client.get(f"/api/v1/findings/{finding_id}").json()
    assert after["asset_criticality"] == "critical"
    assert after["asset_criticality_source"] == "manual"
    assert after["asset_criticality_reason"] == "customer-facing checkout"


def test_finding_detail_includes_the_developer_friendly_explanation(world):
    client, web = world["client"], world["web"]
    finding_id = client.get(f"/api/v1/findings?asset_id={web.id}").json()["findings"][0]["id"]

    body = client.get(f"/api/v1/findings/{finding_id}").json()
    explanation = body["explanation"]
    assert set(explanation) == {
        "what_we_found", "what_is_the_problem", "why_it_matters", "how_it_was_detected",
        "how_serious", "why_this_priority", "what_to_do", "how_to_verify",
    }
    assert web.hostname in explanation["what_we_found"]
    assert explanation["how_it_was_detected"]["host"] == web.hostname
    assert explanation["how_serious"]["risk_score"] == body["risk_score"]
    assert explanation["why_this_priority"] == body["reasoning"]  # the same tested sentence, not a new one
    # updating the finding still returns a fresh, consistent explanation
    status = client.patch(f"/api/v1/findings/{finding_id}", json={"status": "acknowledged"}).json()
    assert status["explanation"]["how_serious"]["risk_score"] == status["risk_score"]


# --- overview -----------------------------------------------------------------------------------

@pytest.mark.parametrize("score,band", [
    (100.0, "critical"), (80.0, "critical"), (79.9, "high"), (60.0, "high"),
    (59.9, "medium"), (40.0, "medium"), (39.9, "low"), (0.0, "low"), (None, "unscored"),
])
def test_risk_bands_have_exact_boundaries(score, band):
    from scoring.engine import risk_band

    assert risk_band(score) == band


def test_overview_counts_only_active_findings(world):
    """The fixture has three findings; one is resolved and must not be counted."""
    body = world["client"].get("/api/v1/overview").json()
    findings = body["findings"]

    assert findings["active"] == 2
    assert findings["actively_exploited"] == 1
    assert findings["confirmed"] == 1
    assert findings["by_detection"] == {"active_detection": 1, "version_inference": 1}
    assert findings["by_risk_band"] == {"critical": 1, "high": 0, "medium": 0, "low": 1, "unscored": 0}


def test_overview_bands_always_sum_to_the_active_total(world):
    findings = world["client"].get("/api/v1/overview").json()["findings"]
    assert sum(findings["by_risk_band"].values()) == findings["active"]
    assert sum(findings["by_detection"].values()) == findings["active"]


def test_overview_counts_unscored_findings_separately(world):
    session, web = world["session"], world["web"]
    session.add(CveEnrichment(cve_id="CVE-2023-0004"))
    session.flush()
    session.add(Finding(asset_id=web.id, cve_id="CVE-2023-0004", risk_score=None, status="open"))
    session.flush()

    findings = world["client"].get("/api/v1/overview").json()["findings"]
    assert findings["by_risk_band"]["unscored"] == 1
    assert findings["active"] == 3


def test_overview_reports_assets_scans_and_the_latest_scan(world):
    body = world["client"].get("/api/v1/overview").json()

    assert body["assets"]["total"] == 2
    assert body["assets"]["by_criticality"] == {"low": 0, "medium": 0, "high": 1, "critical": 0, "unset": 1}
    assert body["scans_total"] == 2
    assert body["last_scan"]["target_domain"] == "example.com"  # newest, not the older failed one
    assert body["last_scan"]["observation_count"] == 2
    assert body["last_scan"]["warnings"] == ["nuclei: nuclei timed out after 1800s"]


def test_overview_reflects_a_criticality_edit_immediately(world):
    client = world["client"]
    client.patch(f"/api/v1/assets/{world['db'].id}/criticality", json={"level": "low"})

    crit = client.get("/api/v1/overview").json()["assets"]["by_criticality"]
    assert crit["low"] == 1 and crit["unset"] == 0


def test_overview_of_an_empty_account_is_all_zeros(session, make_user):
    app.dependency_overrides[get_session] = lambda: session
    try:
        body = TestClient(app, headers=auth_for(make_user())).get("/api/v1/overview").json()
    finally:
        app.dependency_overrides.clear()

    assert body["findings"]["active"] == 0
    assert body["assets"]["total"] == 0
    assert body["last_scan"] is None
    assert sum(body["findings"]["by_risk_band"].values()) == 0


def test_overview_requires_auth(world):
    assert world["anon"].get("/api/v1/overview").status_code == 401


# --- timestamps carry their zone -----------------------------------------------------------------

def test_every_timestamp_is_sent_as_utc_with_a_zone(world):
    """Regression: SQLite hands datetimes back without their zone, and the API sent them bare
    (`2026-09-20T06:24:23`). A browser reads that as *its own* local time, so a scan started a
    minute ago showed as "6 h ago" to anyone in India (UTC+5:30)."""
    from datetime import datetime

    world["session"].expire_all()  # force a reload from SQLite, which returns naive datetimes
    client = world["client"]
    scans = client.get("/api/v1/scans").json()["scans"]
    finding = client.get("/api/v1/findings").json()["findings"][0]
    asset = client.get("/api/v1/assets").json()["assets"][0]
    observation = client.get("/api/v1/observations").json()["observations"][0]

    for field in (scans[0]["started_at"], scans[0]["completed_at"], finding["detected_at"],
                  asset["first_seen_at"], asset["last_seen_at"], observation["observed_at"]):
        assert field.endswith(("Z", "+00:00")), field
        assert datetime.fromisoformat(field.replace("Z", "+00:00")).utcoffset().total_seconds() == 0


def test_a_scan_started_now_is_reported_as_now(world):
    """The number that matters: the instant in the JSON equals the instant it happened."""
    from datetime import UTC, datetime

    session = world["session"]
    fresh = Scan(tenant_id=world["scan"].tenant_id, user_id=world["user"].id, target_domain="now.example.com",
                 status="completed", started_at=utcnow(), completed_at=utcnow())
    session.add(fresh)
    session.flush()
    session.expire_all()

    latest = world["client"].get("/api/v1/scans").json()["scans"][0]
    assert latest["target_domain"] == "now.example.com"
    age = datetime.now(UTC) - datetime.fromisoformat(latest["started_at"].replace("Z", "+00:00"))
    assert abs(age.total_seconds()) < 10, age
