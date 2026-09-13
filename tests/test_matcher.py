import pytest

from core.models import CveEnrichment
from enrichment.matcher import _kev_fallback, _version_candidates, parse_technology


@pytest.mark.parametrize(
    "banner,product,version",
    [
        ("nginx/1.24.0", "nginx", "1.24.0"),
        ("Apache/2.4.49", "apache", "2.4.49"),
        ("Apache/2.4.49 (Ubuntu)", "apache", "2.4.49"),
        ("OpenSSH/8.9p1", "openssh", "8.9p1"),
        ("Apache", "apache", None),
        # nmap -sV reports vendor-prefixed names; losing the version here would
        # match every CVE for the product regardless of the version in use.
        ("Apache httpd/2.4.49", "apache httpd", "2.4.49"),
        ("Apache Tomcat", "apache tomcat", None),
        ("Microsoft IIS httpd/10.0", "microsoft iis httpd", "10.0"),
    ],
)
def test_parse_technology(banner, product, version):
    assert parse_technology(banner) == (product, version)


def test_version_candidates_fall_back_to_numeric_core():
    assert _version_candidates("8.9p1") == ["8.9p1", "8.9", None]
    assert _version_candidates("1.24.0") == ["1.24.0", None]
    assert _version_candidates(None) == [None]


def test_kev_fallback_matches_on_product_name(session):
    session.add(CveEnrichment(cve_id="CVE-2021-40438", kev_listed=True, product="Apache HTTP Server"))
    session.add(CveEnrichment(cve_id="CVE-2020-0001", kev_listed=True, product="Windows"))
    session.flush()

    assert _kev_fallback(session, "apache") == ["CVE-2021-40438"]
