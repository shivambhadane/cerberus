import logging

from enrichment.sources import NVD_PAGE_SIZE, NvdClient


def cve(n: int) -> dict:
    return {"cve": {"id": f"CVE-2021-{n:05d}", "metrics": {}, "descriptions": [], "references": []}}


def paged_nvd(total: int):
    """A stand-in for NVD's paging: honours startIndex/resultsPerPage and reports totalResults."""
    calls: list[dict] = []
    client = NvdClient()

    def fake_get(path, params):
        calls.append(dict(params))
        start, size = params["startIndex"], params["resultsPerPage"]
        ids = range(start, min(start + size, total))
        return {"totalResults": total, "vulnerabilities": [cve(i) for i in ids]}

    client._get = fake_get
    return client, calls


def test_every_page_is_fetched():
    """Regression: only the first page was read, silently dropping 19 of the 69 CVEs NVD lists
    for Apache 2.4.49 - any of which could have been KEV-listed."""
    client, calls = paged_nvd(total=69)
    found = client.cves_for_cpe("cpe:2.3:a:apache:http_server", "2.4.49", limit=500)

    assert len(found) == 69
    assert len({c.cve_id for c in found}) == 69  # no page overlap


def test_multiple_pages_are_requested_when_results_exceed_a_page():
    client, calls = paged_nvd(total=NVD_PAGE_SIZE * 2 + 5)
    found = client.cves_for_cpe("cpe:2.3:a:x:y", None, limit=1000)

    assert len(found) == NVD_PAGE_SIZE * 2 + 5
    assert [c["startIndex"] for c in calls] == [0, NVD_PAGE_SIZE, NVD_PAGE_SIZE * 2]


def test_a_single_page_result_makes_a_single_request():
    client, calls = paged_nvd(total=7)
    assert len(client.cves_for_cpe("cpe:2.3:a:x:y", "1.0")) == 7
    assert len(calls) == 1


def test_hitting_the_cap_is_logged_never_silent(caplog):
    client, _ = paged_nvd(total=300)
    with caplog.at_level(logging.WARNING, logger="enrichment.sources"):
        found = client.cves_for_cpe("cpe:2.3:a:x:y", None, limit=120)

    assert len(found) == 120
    assert any("only 120 were retrieved" in r.message and "300" in r.message for r in caplog.records)


def test_complete_results_produce_no_warning(caplog):
    client, _ = paged_nvd(total=40)
    with caplog.at_level(logging.WARNING, logger="enrichment.sources"):
        client.cves_for_cpe("cpe:2.3:a:x:y", None)
    assert not caplog.records


def test_a_failed_page_returns_what_was_retrieved_and_warns(caplog):
    client = NvdClient()
    pages = iter([
        {"totalResults": 300, "vulnerabilities": [cve(i) for i in range(200)]},
        None,  # the second request fails
    ])
    client._get = lambda path, params: next(pages)

    with caplog.at_level(logging.WARNING, logger="enrichment.sources"):
        found = client.cves_for_cpe("cpe:2.3:a:x:y", None)

    assert len(found) == 200
    assert any("incomplete" in r.message for r in caplog.records)


def test_cve_ids_are_normalised_to_upper_case():
    client = NvdClient()
    client._get = lambda path, params: {
        "totalResults": 1,
        "vulnerabilities": [
            {"cve": {"id": "cve-2021-41773", "metrics": {}, "descriptions": [], "references": []}}
        ],
    }
    assert client.cves_for_cpe("cpe:2.3:a:x:y", None)[0].cve_id == "CVE-2021-41773"
