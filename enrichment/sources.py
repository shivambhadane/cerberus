from __future__ import annotations

import logging
import threading
import time
from collections import Counter
from dataclasses import dataclass
from datetime import date

import requests

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_BASE = "https://services.nvd.nist.gov/rest/json"

EPSS_BATCH = 100
USER_AGENT = "cerberus-asm"

MAX_CPE_CANDIDATES = 3
# Large enough that vendor ranking reflects the whole dictionary, not the first page.
CPE_PAGE_SIZE = 2000

# Banner names that differ from their CPE product name.
PRODUCT_ALIASES: dict[str, tuple[str, str]] = {
    "apache": ("apache http server", "http_server"),
    "httpd": ("apache http server", "http_server"),
    # nmap -sV reports vendor-prefixed product names.
    "apache httpd": ("apache http server", "http_server"),
    "iis": ("internet information services", "internet_information_services"),
    "microsoft-iis": ("internet information services", "internet_information_services"),
    "openssh": ("openssh", "openssh"),
}


@dataclass(frozen=True)
class KevRecord:
    cve_id: str
    vendor: str
    product: str
    date_added: date | None
    description: str


@dataclass(frozen=True)
class NvdCve:
    cve_id: str
    cvss_score: float | None
    description: str
    has_public_exploit: bool


def fetch_kev(timeout: int = 60) -> dict[str, KevRecord]:
    """CISA Known Exploited Vulnerabilities catalogue."""
    resp = requests.get(KEV_URL, timeout=timeout, headers={"User-Agent": USER_AGENT})
    resp.raise_for_status()
    records: dict[str, KevRecord] = {}
    for row in resp.json().get("vulnerabilities", []):
        cve_id = row.get("cveID")
        if not cve_id:
            continue
        try:
            added = date.fromisoformat(row["dateAdded"]) if row.get("dateAdded") else None
        except ValueError:
            added = None
        records[cve_id] = KevRecord(
            cve_id=cve_id,
            vendor=row.get("vendorProject", ""),
            product=row.get("product", ""),
            date_added=added,
            description=row.get("shortDescription", ""),
        )
    log.info("fetched %d KEV records", len(records))
    return records


def fetch_epss(cve_ids: list[str], timeout: int = 45) -> dict[str, float]:
    """EPSS exploitation-probability scores, queried in batches."""
    scores: dict[str, float] = {}
    for i in range(0, len(cve_ids), EPSS_BATCH):
        batch = cve_ids[i : i + EPSS_BATCH]
        try:
            resp = requests.get(
                EPSS_URL,
                params={"cve": ",".join(batch), "limit": EPSS_BATCH},
                timeout=timeout,
                headers={"User-Agent": USER_AGENT},
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            log.warning("EPSS batch %d failed (%s); continuing", i // EPSS_BATCH, exc)
            continue
        for row in resp.json().get("data", []):
            try:
                scores[row["cve"]] = float(row["epss"])
            except (KeyError, TypeError, ValueError):
                continue
    log.info("fetched %d EPSS scores", len(scores))
    return scores


class NvdClient:
    """NVD 2.0 client with the public rate limit applied.

    NVD allows 5 requests / 30s anonymously and 50 / 30s with an API key.
    """

    def __init__(self, api_key: str | None = None, timeout: int = 45):
        self.api_key = api_key
        self.timeout = timeout
        self._interval = 0.7 if api_key else 6.5
        self._lock = threading.Lock()
        self._last_call = 0.0
        self._cpe_cache: dict[str, list[str]] = {}

    def _get(self, path: str, params: dict) -> dict | None:
        with self._lock:
            wait = self._interval - (time.monotonic() - self._last_call)
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.monotonic()

        headers = {"User-Agent": USER_AGENT}
        if self.api_key:
            headers["apiKey"] = self.api_key
        try:
            resp = requests.get(f"{NVD_BASE}/{path}", params=params, timeout=self.timeout, headers=headers)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            log.warning("NVD request failed (%s): %s", path, exc)
            return None

    def resolve_cpe(self, product: str) -> list[str]:
        """Resolve a fingerprinted product name to candidate cpe vendor:product bases.

        A product can appear under several vendors (nginx is published under both
        igor_sysoev and f5, and only the latter carries CVEs), so this returns every
        plausible base ordered by how many dictionary entries back it. The caller
        tries them in order.
        """
        key = product.lower()
        if key in self._cpe_cache:
            return self._cpe_cache[key]

        search_term, expected_product = PRODUCT_ALIASES.get(key, (product, key))
        data = self._get("cpes/2.0", {"keywordSearch": search_term, "resultsPerPage": CPE_PAGE_SIZE})

        acceptable = _acceptable_products(key, expected_product)
        counts: Counter[str] = Counter()
        if data:
            for entry in data.get("products", []):
                parts = entry["cpe"]["cpeName"].split(":")
                if len(parts) > 5 and parts[2] == "a" and parts[4].lower() in acceptable:
                    counts[f"cpe:2.3:a:{parts[3]}:{parts[4]}"] += 1

        bases = [base for base, _ in counts.most_common(MAX_CPE_CANDIDATES)]
        self._cpe_cache[key] = bases
        log.info("resolved product %r -> %s", product, bases or "no CPE match")
        return bases

    def cves_for_cpe(self, cpe_base: str, version: str | None, limit: int = 50) -> list[NvdCve]:
        """Version-aware CVE lookup. NVD applies the affected-version ranges itself."""
        match = f"{cpe_base}:{version}:*:*:*:*:*:*:*" if version else f"{cpe_base}:*:*:*:*:*:*:*:*"
        data = self._get("cves/2.0", {"virtualMatchString": match, "resultsPerPage": limit})
        if not data:
            return []

        out: list[NvdCve] = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            out.append(
                NvdCve(
                    cve_id=cve["id"],
                    cvss_score=_primary_cvss(cve.get("metrics", {})),
                    description=_english_description(cve.get("descriptions", [])),
                    has_public_exploit=_has_exploit_reference(cve.get("references", [])),
                )
            )
        return out

    def fetch_cve(self, cve_id: str) -> NvdCve | None:
        data = self._get("cves/2.0", {"cveId": cve_id})
        if not data or not data.get("vulnerabilities"):
            return None
        cve = data["vulnerabilities"][0]["cve"]
        return NvdCve(
            cve_id=cve["id"],
            cvss_score=_primary_cvss(cve.get("metrics", {})),
            description=_english_description(cve.get("descriptions", [])),
            has_public_exploit=_has_exploit_reference(cve.get("references", [])),
        )


def _acceptable_products(key: str, expected_product: str) -> set[str]:
    """CPE product names that a fingerprint could reasonably mean.

    Fingerprints arrive vendor-prefixed ("apache tomcat") while CPE names them by
    product alone ("tomcat"), so accept the trailing words as well as the full name.
    """
    acceptable = {expected_product}
    words = key.split()
    if len(words) > 1:
        acceptable.add("_".join(words))
        acceptable.add("_".join(words[1:]))
        acceptable.add(words[-1])
    return acceptable


def _primary_cvss(metrics: dict) -> float | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            return entries[0].get("cvssData", {}).get("baseScore")
    return None


def _english_description(descriptions: list[dict]) -> str:
    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "")
    return ""


def _has_exploit_reference(references: list[dict]) -> bool:
    return any("Exploit" in (ref.get("tags") or []) for ref in references)
