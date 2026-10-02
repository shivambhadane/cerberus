"""The developer-friendly explanation (scoring/explain.py): deterministic, built only from
stored data, and never claiming a patched version Cerberus does not actually know."""

from core.adapters import DetectionMethod
from core.models import Asset, AssetCriticality, CveEnrichment, Finding
from scoring.explain import explain


def make(technology="Apache httpd/2.4.49", description="A path traversal flaw.", kev_listed=False,
         criticality_level=None, detection_method=DetectionMethod.VERSION_INFERENCE,
         detected_by_tool=None, risk_score=70.0, cvss_score=9.8, epss_score=0.9):
    finding = Finding(
        asset_id="a1", cve_id="CVE-2021-41773", risk_score=risk_score, reasoning="a reasoning sentence",
        status="open", detection_method=detection_method, detected_by_tool=detected_by_tool,
    )
    cve = CveEnrichment(
        cve_id="CVE-2021-41773", cvss_score=cvss_score, kev_listed=kev_listed, epss_score=epss_score,
        description=description,
    )
    asset = Asset(id="a1", tenant_id="t1", hostname="api.example.com", port=443, technology=technology)
    criticality = AssetCriticality(asset_id="a1", level=criticality_level) if criticality_level else None
    return finding, cve, asset, criticality


def test_what_we_found_names_the_technology_and_the_cve():
    explanation = explain(*make())
    assert "api.example.com:443" in explanation.what_we_found
    assert "Apache httpd/2.4.49" in explanation.what_we_found
    assert "CVE-2021-41773" in explanation.what_we_found


def test_what_we_found_without_a_known_technology_does_not_invent_one():
    explanation = explain(*make(technology=None))
    assert "api.example.com:443" in explanation.what_we_found
    assert "running" not in explanation.what_we_found  # nothing to name


def test_what_is_the_problem_uses_the_real_nvd_description():
    explanation = explain(*make(description="A specific, real CVE description from NVD."))
    assert explanation.what_is_the_problem == "A specific, real CVE description from NVD."


def test_what_is_the_problem_is_honest_when_nvd_gave_no_description():
    explanation = explain(*make(description=None))
    assert "limited information" in explanation.what_is_the_problem
    assert "CVE-2021-41773" in explanation.what_is_the_problem


def test_why_it_matters_mentions_kev_only_when_actually_kev_listed():
    exploited = explain(*make(kev_listed=True))
    quiet = explain(*make(kev_listed=False))
    assert "actively" in exploited.why_it_matters.lower()
    assert "actively" not in quiet.why_it_matters.lower()


def test_why_it_matters_mentions_criticality_only_when_high_or_critical():
    critical = explain(*make(criticality_level="critical"))
    low = explain(*make(criticality_level="low"))
    none_set = explain(*make(criticality_level=None))
    assert "critical criticality" in critical.why_it_matters
    assert "criticality" not in low.why_it_matters
    assert "criticality" not in none_set.why_it_matters


def test_how_it_was_detected_carries_the_real_stored_fields_not_new_ones():
    explanation = explain(*make(
        technology="nginx/1.18.0", detection_method=DetectionMethod.ACTIVE_DETECTION,
        detected_by_tool="nuclei",
    ))
    d = explanation.how_it_was_detected
    assert (d.host, d.port, d.technology) == ("api.example.com", 443, "nginx/1.18.0")
    assert d.detection_method == DetectionMethod.ACTIVE_DETECTION
    assert d.detected_by_tool == "nuclei"


def test_how_serious_carries_the_real_numbers_not_recomputed_ones():
    explanation = explain(*make(risk_score=83.6, cvss_score=9.8, epss_score=0.97, kev_listed=True,
                                 criticality_level="high"))
    s = explanation.how_serious
    assert (s.risk_score, s.cvss_score, s.epss_score) == (83.6, 9.8, 0.97)
    assert s.kev_listed is True
    assert s.asset_criticality == "high"


def test_why_this_priority_is_the_existing_tested_reasoning_sentence_not_a_new_one():
    """Part 8 asks for a deterministic explanation "based on actual stored signals" - that
    sentence already exists and is already tested (scoring/engine.py); this must reuse it
    rather than risk a second, differently-worded explanation drifting from the real score."""
    finding, cve, asset, crit = make()
    finding.reasoning = "Actively exploited (CISA KEV); high-criticality asset."
    assert explain(finding, cve, asset, crit).why_this_priority == finding.reasoning


def test_what_to_do_never_invents_a_patched_version(): # the core non-hallucination requirement
    explanation = explain(*make(technology="Apache httpd/2.4.49"))
    assert "2.4.49" in explanation.what_to_do  # the version Cerberus actually detected
    assert "does not store a confirmed patched-version number" in explanation.what_to_do
    assert "2.4.50" not in explanation.what_to_do  # never guesses the fixed version
    assert "2.4.51" not in explanation.what_to_do
    assert "2.4.52" not in explanation.what_to_do


def test_what_to_do_without_a_known_technology_is_still_honest_not_fabricated():
    explanation = explain(*make(technology=None))
    assert "could not identify" in explanation.what_to_do
    assert "CVE-2021-41773" in explanation.what_to_do


def test_how_to_verify_points_at_rescanning():
    explanation = explain(*make())
    assert "scan" in explanation.how_to_verify.lower()
