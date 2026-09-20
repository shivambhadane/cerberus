import json
from pathlib import Path

import pytest

from core.profiles import PASSIVE, SAFE, THOROUGH, ProfileViolation, ScanProfile, get_profile
from core.scope import Scope
from discovery.adapters.nuclei import NucleiScanner

SCANNER = NucleiScanner()
SCOPE = Scope(domain="example.com")


def result(**overrides) -> str:
    base = {
        "template-id": "CVE-2021-41773",
        "info": {
            "name": "Apache HTTP Server 2.4.49 - Path Traversal",
            "severity": "critical",
            "tags": ["cve", "cve2021", "apache", "lfi"],
            "description": "Path traversal in Apache 2.4.49.",
            "classification": {
                "cve-id": ["CVE-2021-41773"],
                "cwe-id": ["CWE-22"],
                "cvss-score": 7.5,
            },
        },
        "type": "http",
        "host": "https://api.example.com:443",
        "matched-at": "https://api.example.com:443/cgi-bin/.%2e/etc/passwd",
        "matcher-name": "status",
        "timestamp": "2026-09-14T10:00:00Z",
    }
    base.update(overrides)
    return json.dumps(base)


def tamper(profile: ScanProfile, **fields) -> ScanProfile:
    """Bypass __post_init__ to simulate a profile mutated after construction."""
    clone = ScanProfile(
        name=profile.name, description=profile.description,
        allowed_tags=profile.allowed_tags, allowed_protocols=profile.allowed_protocols,
        severities=profile.severities, rate_limit=profile.rate_limit,
        concurrency=profile.concurrency,
    )
    for key, value in fields.items():
        object.__setattr__(clone, key, value)
    return clone


# --- profile is the only control surface -----------------------------------------------

def test_safe_profile_builds_an_executable_command(tmp_path: Path):
    command = SCANNER.build_command(tmp_path / "t.txt", tmp_path / "o.jsonl", SAFE)

    assert command[0] == "nuclei"
    assert "-jsonl" in command and "-list" in command
    joined = " ".join(command)
    assert "-tags cve,exposure,misconfig,ssl,takeover,tech" in joined
    assert "-severity medium,high,critical" in joined


def test_thorough_profile_requires_explicit_acceptance():
    with pytest.raises(ProfileViolation, match="explicitly"):
        get_profile("thorough")
    assert get_profile("thorough", opted_in=True) is THOROUGH


def test_thorough_still_excludes_everything_forbidden(tmp_path: Path):
    joined = " ".join(SCANNER.build_command(tmp_path / "t", tmp_path / "o", THOROUGH))
    for forbidden in ("dos", "fuzz", "intrusive", "brute-force"):
        assert forbidden in joined.split("-exclude-tags ")[1].split(" ")[0]
    assert "code,file" in joined


def test_passive_profile_never_invokes_nuclei():
    assert SCANNER.run([], SCOPE, PASSIVE) == []


def test_rate_and_concurrency_come_from_the_profile(tmp_path: Path):
    profile = ScanProfile(
        name="custom", description="", allowed_tags=frozenset({"cve"}),
        allowed_protocols=frozenset({"http"}), severities=("high",),
        rate_limit=3, concurrency=2, timeout_seconds=7, retries=4,
    )
    command = SCANNER.build_command(tmp_path / "t", tmp_path / "o", profile)

    assert command[command.index("-rate-limit") + 1] == "3"
    assert command[command.index("-concurrency") + 1] == "2"
    assert command[command.index("-timeout") + 1] == "7"
    assert command[command.index("-retries") + 1] == "4"


def test_explicit_template_ids_pin_the_selection(tmp_path: Path):
    profile = ScanProfile(
        name="pinned", description="", allowed_tags=frozenset({"cve"}),
        allowed_protocols=frozenset({"http"}), severities=("critical",),
        template_ids=frozenset({"CVE-2021-41773"}),
    )
    command = SCANNER.build_command(tmp_path / "t", tmp_path / "o", profile)

    assert command[command.index("-id") + 1] == "CVE-2021-41773"
    assert "-tags" not in command


# --- the safety floor survives tampering -----------------------------------------------

@pytest.mark.parametrize("tag", ["dos", "ddos", "fuzz", "fuzzing", "intrusive", "brute-force", "bruteforce"])
def test_forbidden_tags_are_refused_even_on_a_mutated_profile(tmp_path: Path, tag):
    profile = tamper(SAFE, allowed_tags=frozenset({"cve", tag}))
    with pytest.raises(ProfileViolation):
        SCANNER.build_command(tmp_path / "t", tmp_path / "o", profile)


@pytest.mark.parametrize("protocol", ["code", "file"])
def test_forbidden_types_are_refused_even_on_a_mutated_profile(tmp_path: Path, protocol):
    profile = tamper(SAFE, allowed_protocols=frozenset({"http", protocol}))
    with pytest.raises(ProfileViolation):
        SCANNER.build_command(tmp_path / "t", tmp_path / "o", profile)


# --- results are filtered on the way back in -------------------------------------------

def test_multi_tag_template_containing_a_forbidden_tag_is_discarded():
    raw = result(info={
        "name": "Some DoS check", "severity": "high",
        "tags": ["cve", "apache", "dos"], "classification": {},
    })
    assert SCANNER.parse(raw, SAFE, SCOPE) == []


@pytest.mark.parametrize("protocol", ["code", "file"])
def test_forbidden_result_types_are_discarded(protocol):
    assert SCANNER.parse(result(type=protocol), SAFE, SCOPE) == []


def test_out_of_scope_results_are_discarded():
    raw = result(host="https://evilexample.com", **{"matched-at": "https://evilexample.com/x"})
    assert SCANNER.parse(raw, SAFE, SCOPE) == []


# --- malformed input --------------------------------------------------------------------

@pytest.mark.parametrize("raw", [
    "",
    "   \n  \n",
    "not json at all",
    '{"template-id": "x", "info": {',          # truncated
    '["unexpected", "list"]',                   # wrong shape
    '{"info": {"name": "no template id"}}',     # missing id
])
def test_malformed_output_never_raises(raw):
    assert SCANNER.parse(raw, SAFE, SCOPE) == []


def test_valid_lines_survive_alongside_malformed_ones():
    raw = "\n".join(["garbage", result(), '{"broken": '])
    assert len(SCANNER.parse(raw, SAFE, SCOPE)) == 1


def test_string_tags_are_tolerated():
    raw = result(info={"name": "n", "severity": "high", "tags": "cve,apache", "classification": {}})
    assert len(SCANNER.parse(raw, SAFE, SCOPE)) == 1


# --- duplicates --------------------------------------------------------------------------

def test_identical_detections_are_deduplicated():
    assert len(SCANNER.parse("\n".join([result(), result()]), SAFE, SCOPE)) == 1


def test_same_template_at_a_different_location_is_kept():
    other = result(**{"matched-at": "https://api.example.com:443/other"})
    assert len(SCANNER.parse("\n".join([result(), other]), SAFE, SCOPE)) == 2


# --- mapping into Cerberus observations ---------------------------------------------------

def test_result_maps_to_a_complete_observation():
    observation = SCANNER.parse(result(), SAFE, SCOPE)[0]

    assert observation.kind == "vulnerability"
    assert observation.source_tool == "nuclei"
    assert observation.target == "api.example.com:443"

    data = observation.data
    assert data["template_id"] == "CVE-2021-41773"
    assert data["template_name"] == "Apache HTTP Server 2.4.49 - Path Traversal"
    assert data["severity"] == "critical"
    assert data["cve_ids"] == ["CVE-2021-41773"]
    assert data["cwe_ids"] == ["CWE-22"]
    assert data["cvss_score"] == 7.5
    assert data["tags"] == ["cve", "cve2021", "apache", "lfi"]
    assert data["technology"] == "apache"
    assert data["matched_at"].endswith("/etc/passwd")
    assert data["profile"] == "safe"
    assert observation.raw  # evidence retained
    assert observation.observed_at.year == 2026


def test_missing_classification_does_not_lose_the_detection():
    raw = result(info={"name": "n", "severity": "low", "tags": ["exposure"]})
    observation = SCANNER.parse(raw, SAFE, SCOPE)[0]

    assert observation.data["cve_ids"] == []
    assert observation.data["cwe_ids"] == []
    assert observation.data["severity"] == "low"


# --- detections become findings ------------------------------------------------------------

def _asset(session, hostname="api.example.com", port=443):
    from core.models import Asset, Tenant

    tenant = Tenant(name="t")
    session.add(tenant)
    session.flush()
    asset = Asset(tenant_id=tenant.id, hostname=hostname, port=port, protocol="tcp",
                  technology="Apache httpd/2.4.49")
    session.add(asset)
    session.flush()
    return asset


def test_detection_creates_a_finding_marked_active(session):
    from enrichment.matcher import record_active_detections

    asset = _asset(session)
    observations = SCANNER.parse(result(), SAFE, SCOPE)
    findings = record_active_detections(session, [asset], observations)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.cve_id == "CVE-2021-41773"
    assert finding.detection_method == "active_detection"
    assert finding.detected_by_tool == "nuclei"
    assert "nuclei template" in finding.evidence
    assert "not evidence of compromise" in finding.evidence


def test_active_detection_supersedes_an_inferred_finding(session):
    from core.models import Finding
    from enrichment.cache import get_or_create
    from enrichment.matcher import record_active_detections

    asset = _asset(session)
    get_or_create(session, "CVE-2021-41773")
    session.add(Finding(asset_id=asset.id, cve_id="CVE-2021-41773",
                        detection_method="version_inference"))
    session.flush()

    record_active_detections(session, [asset], SCANNER.parse(result(), SAFE, SCOPE))

    rows = session.query(Finding).filter_by(asset_id=asset.id).all()
    assert len(rows) == 1  # upgraded, not duplicated
    assert rows[0].detection_method == "active_detection"


def test_detection_without_a_cve_creates_no_finding(session):
    from core.models import Finding
    from enrichment.matcher import record_active_detections

    asset = _asset(session)
    raw = result(info={"name": "Exposed panel", "severity": "low", "tags": ["exposure"]})
    record_active_detections(session, [asset], SCANNER.parse(raw, SAFE, SCOPE))

    assert session.query(Finding).count() == 0


def test_detection_on_an_unknown_asset_is_ignored(session):
    from core.models import Finding
    from enrichment.matcher import record_active_detections

    asset = _asset(session, hostname="other.example.com", port=8443)
    record_active_detections(session, [asset], SCANNER.parse(result(), SAFE, SCOPE))

    assert session.query(Finding).count() == 0


def test_active_detection_is_reported_in_the_reasoning_without_changing_the_score():
    from core.models import CveEnrichment
    from scoring.engine import score_finding

    cve = CveEnrichment(cve_id="CVE-2021-41773", cvss_score=9.8, kev_listed=True, epss_score=0.99)
    inferred = score_finding(cve, "high", None, 443, detection_method="version_inference")
    detected = score_finding(cve, "high", None, 443, detection_method="active_detection")

    assert detected.risk_score == inferred.risk_score
    assert "confirmed by active probe" in detected.reasoning
    assert "confirmed by active probe" not in inferred.reasoning


# --- a failed run must not look like "found nothing" -----------------------------------------

def test_nonzero_exit_raises_instead_of_returning_no_detections(monkeypatch):
    import subprocess

    from core.proc import ScannerError

    monkeypatch.setattr(SCANNER, "is_available", lambda: True)
    monkeypatch.setattr(
        "discovery.adapters.nuclei.run_tool",
        lambda *a, **k: subprocess.CompletedProcess([], 2, "", "[FTL] could not load templates"),
    )
    from core.adapters import Endpoint

    with pytest.raises(ScannerError, match="exited 2.*could not load templates"):
        SCANNER.run([Endpoint("api.example.com", "203.0.113.10", 443)], SCOPE, SAFE)


def test_timeout_propagates_as_a_scanner_error(monkeypatch):
    from core.adapters import Endpoint
    from core.proc import ScannerError

    def timeout(*a, **k):
        raise ScannerError("nuclei timed out after 1800s")

    monkeypatch.setattr(SCANNER, "is_available", lambda: True)
    monkeypatch.setattr("discovery.adapters.nuclei.run_tool", timeout)

    with pytest.raises(ScannerError, match="timed out"):
        SCANNER.run([Endpoint("api.example.com", "203.0.113.10", 443)], SCOPE, SAFE)


# --- real nuclei output ---------------------------------------------------------------------
# tests/fixtures/nuclei_real_cve_2021_41773.jsonl is a record captured from nuclei v3.11.1
# running against the Docker lab, with only the bulky request/response bodies trimmed. The
# hand-written fixtures above assumed a shape that real nuclei does not emit; these tests
# exist so that cannot happen again.

REAL = (Path(__file__).parent / "fixtures" / "nuclei_real_cve_2021_41773.jsonl").read_text()
LAB_SCOPE = Scope(domain="127.0.0.1", allow_private_addresses=True)


def test_real_record_keeps_the_port():
    """Real nuclei emits a bare host with the port in a separate field."""
    observation = SCANNER.parse(REAL, SAFE, LAB_SCOPE)[0]
    assert observation.target == "127.0.0.1:18081"


def test_real_record_identifiers_are_upper_cased():
    """Nuclei writes `cve-2021-41773`; unnormalised, it never joins to KEV/EPSS data."""
    data = SCANNER.parse(REAL, SAFE, LAB_SCOPE)[0].data
    assert data["cve_ids"] == ["CVE-2021-41773"]
    assert data["cwe_ids"] == ["CWE-22"]


def test_real_record_maps_the_rest_of_the_fields():
    observation = SCANNER.parse(REAL, SAFE, LAB_SCOPE)[0]
    data = observation.data
    assert data["template_id"] == "CVE-2021-41773"
    assert data["severity"] == "high"
    assert data["technology"] == "apache"
    assert data["matched_at"].endswith("/etc/passwd")
    assert data["cvss_score"] == 7.5
    assert observation.observed_at.year == 2026  # nanosecond-precision +05:30 timestamp parsed


@pytest.mark.parametrize("fields,expected", [
    ({"host": "127.0.0.1", "port": "18081"}, "127.0.0.1:18081"),                    # real nuclei
    ({"host": "api.example.com:8443"}, "api.example.com:8443"),                     # port inside host
    ({"host": "https://api.example.com:443"}, "api.example.com:443"),               # scheme + port
    ({"host": "api.example.com", "scheme": "https"}, "api.example.com:443"),        # default https
    ({"host": "api.example.com", "scheme": "http"}, "api.example.com:80"),          # default http
    ({"host": "", "url": "http://api.example.com:9000"}, "api.example.com:9000"),   # url only
])
def test_target_is_derived_from_every_output_shape(fields, expected):
    from discovery.adapters.nuclei import _target_from

    assert _target_from(fields) == expected


def test_a_real_detection_matches_its_asset_end_to_end(session):
    """The chain that was broken: real record -> observation -> asset match -> finding."""
    from core.models import Asset, CveEnrichment, Finding, Tenant
    from enrichment.matcher import record_active_detections

    tenant = Tenant(name="t")
    session.add(tenant)
    session.flush()
    asset = Asset(tenant_id=tenant.id, hostname="127.0.0.1", port=18081, protocol="tcp")
    session.add(asset)
    # KEV data is keyed by upper-case id; the finding must land on that same row.
    session.add(CveEnrichment(cve_id="CVE-2021-41773", kev_listed=True, epss_score=0.99))
    session.flush()

    observations = SCANNER.parse(REAL, SAFE, LAB_SCOPE)
    findings = record_active_detections(session, [asset], observations)

    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-2021-41773"
    assert findings[0].detection_method == "active_detection"
    assert session.query(CveEnrichment).count() == 1  # no stray lower-case duplicate row
    assert session.query(Finding).count() == 1
