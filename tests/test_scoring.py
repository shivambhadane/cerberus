from datetime import date

from core.models import CveEnrichment
from scoring.engine import score_finding


def make_cve(**kwargs) -> CveEnrichment:
    defaults = dict(cve_id="CVE-0000-0001", cvss_score=7.0, kev_listed=False, epss_score=0.01)
    return CveEnrichment(**{**defaults, **kwargs})


def test_actively_exploited_medium_severity_outranks_quiet_critical():
    """The core product claim: exploitation in the wild beats raw severity."""
    exploited = make_cve(cvss_score=6.5, kev_listed=True, kev_date_added=date(2023, 11, 1), epss_score=0.94)
    quiet = make_cve(cve_id="CVE-0000-0002", cvss_score=9.8, kev_listed=False, epss_score=0.01)

    hot = score_finding(exploited, "high", None, 443)
    cold = score_finding(quiet, "high", None, 443)

    assert hot.risk_score > cold.risk_score


def test_kev_listing_is_explained_in_reasoning():
    result = score_finding(make_cve(kev_listed=True, kev_date_added=date(2023, 11, 1)), "high", None, 443)
    assert "CISA KEV" in result.reasoning
    assert "2023-11-01" in result.reasoning


def test_public_exploit_scores_between_kev_and_nothing():
    kev = score_finding(make_cve(kev_listed=True), "medium", None, 443).risk_score
    poc = score_finding(make_cve(has_public_exploit=True), "medium", None, 443).risk_score
    nothing = score_finding(make_cve(), "medium", None, 443).risk_score
    assert kev > poc > nothing


def test_asset_criticality_shifts_score():
    cve = make_cve(kev_listed=True)
    low = score_finding(cve, "low", None, 443).risk_score
    critical = score_finding(cve, "critical", None, 443).risk_score
    assert critical > low


def test_management_port_raises_exposure():
    cve = make_cve()
    web = score_finding(cve, "medium", None, 443).risk_score
    database = score_finding(cve, "medium", None, 5432).risk_score
    assert database > web


def test_no_exploitation_evidence_is_stated_explicitly():
    result = score_finding(make_cve(epss_score=0.001), "medium", None, 443)
    assert "No evidence of exploitation" in result.reasoning


def test_missing_enrichment_does_not_crash():
    bare = CveEnrichment(cve_id="CVE-0000-0003", cvss_score=None, kev_listed=False, epss_score=None)
    result = score_finding(bare, "medium", None, 443)
    assert 0 <= result.risk_score <= 100
    assert result.reasoning
