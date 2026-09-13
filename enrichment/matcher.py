from __future__ import annotations

import logging
import re
from collections import defaultdict
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.adapters import DetectionMethod, Observation, ObservationKind
from core.models import Asset, CveEnrichment, Finding
from enrichment.cache import apply_epss, apply_nvd, get_or_create
from enrichment.sources import NvdClient

log = logging.getLogger(__name__)

# Product names can contain spaces ("Apache httpd/2.4.49" from nmap -sV), so the
# product group allows them; non-greedy matching stops at the first version-like token.
TECH_RE = re.compile(r"^(?P<product>[A-Za-z][\w\-. ]*?)[/ ]v?(?P<version>\d[\w.\-]*)")
VERSION_CORE_RE = re.compile(r"^(\d+(?:\.\d+){0,2})")

MAX_CVES_PER_TECH = 50
MAX_LOOKUPS = 5
MAX_CVSS_BACKFILL = 10


def parse_technology(technology: str) -> tuple[str, str | None]:
    """'nginx/1.24.0 ' -> ('nginx', '1.24.0'); 'Apache' -> ('apache', None)."""
    value = technology.strip()
    match = TECH_RE.match(value)
    if not match:
        return value.split("/")[0].strip().lower(), None
    return match.group("product").strip().lower(), match.group("version")


def _version_candidates(version: str | None) -> list[str | None]:
    """Try the exact version, then its numeric core (8.9p1 -> 8.9), then unversioned."""
    if not version:
        return [None]
    candidates: list[str | None] = [version]
    core = VERSION_CORE_RE.match(version)
    if core and core.group(1) != version:
        candidates.append(core.group(1))
    candidates.append(None)
    return candidates


def _kev_fallback(session: Session, product: str) -> list[str]:
    """When NVD has no CPE for a product, match against KEV product names."""
    rows = session.scalars(
        select(CveEnrichment).where(CveEnrichment.kev_listed.is_(True), CveEnrichment.product.isnot(None))
    ).all()
    token = product.lower()
    return [r.cve_id for r in rows if token in (r.product or "").lower()]


@dataclass(frozen=True)
class MatchEvidence:
    """How a set of CVEs came to be associated with a technology."""

    cve_ids: list[str]
    method: str
    cpe_base: str | None
    matched_version: str | None

    def describe(self, technology: str, source_tool: str | None) -> str:
        seen_by = f" (identified by {source_tool})" if source_tool else ""
        if self.cpe_base is None:
            return (
                f"Technology {technology!r}{seen_by} matched against CISA KEV product names; "
                "no CPE entry resolved, so this is a product-level match."
            )
        if self.matched_version:
            return (
                f"Technology {technology!r}{seen_by} resolved to {self.cpe_base}; "
                f"NVD reports this CVE as affecting version {self.matched_version}."
            )
        return (
            f"Technology {technology!r}{seen_by} resolved to {self.cpe_base}, but no version was "
            "detected, so every CVE for the product is reported. Treat as low precision."
        )


def _lookup_cves(
    session: Session,
    nvd: NvdClient,
    technology: str,
    product: str,
    version: str | None,
) -> MatchEvidence:
    """Find CVEs for a product/version, trying each candidate CPE vendor in turn.

    A product can resolve to several vendors and only one usually carries CVEs, so
    candidates are tried until one produces hits, bounded by MAX_LOOKUPS.
    """
    attempts = 0
    for base in nvd.resolve_cpe(product):
        for candidate in _version_candidates(version):
            if attempts >= MAX_LOOKUPS:
                break
            attempts += 1
            cves = nvd.cves_for_cpe(base, candidate, limit=MAX_CVES_PER_TECH)
            if cves:
                for cve in cves:
                    apply_nvd(session, cve)
                log.info(
                    "%s -> %d CVEs (%s, version %s)", technology, len(cves), base, candidate or "any"
                )
                return MatchEvidence(
                    cve_ids=[c.cve_id for c in cves],
                    method=DetectionMethod.VERSION_INFERENCE,
                    cpe_base=base,
                    matched_version=candidate,
                )

    fallback = _kev_fallback(session, product)
    if fallback:
        log.info("%s -> %d CVEs via KEV product fallback", technology, len(fallback))
        _backfill_cvss(session, nvd, fallback)
    return MatchEvidence(
        cve_ids=fallback,
        method=DetectionMethod.VERSION_INFERENCE,
        cpe_base=None,
        matched_version=None,
    )


def _backfill_cvss(session: Session, nvd: NvdClient, cve_ids: list[str]) -> None:
    """KEV records carry no CVSS, so fetch it for the few CVEs matched that way."""
    missing = [
        row.cve_id
        for row in session.scalars(
            select(CveEnrichment).where(CveEnrichment.cve_id.in_(cve_ids), CveEnrichment.cvss_score.is_(None))
        )
    ][:MAX_CVSS_BACKFILL]
    for cve_id in missing:
        cve = nvd.fetch_cve(cve_id)
        if cve:
            apply_nvd(session, cve)


def record_active_detections(
    session: Session,
    assets: list[Asset],
    observations: list[Observation],
) -> list[Finding]:
    """Turn nuclei detections into findings evidenced by an actual probe response.

    A detection means the template's matcher fired against this target. That is
    stronger evidence than a version match, but it is still evidence of a *detected
    weakness*, not proof the host is compromised - correlation with KEV, EPSS and
    asset criticality is what scoring does with it afterwards.
    """
    by_target: dict[str, Asset] = {f"{a.hostname}:{a.port}": a for a in assets}
    findings: list[Finding] = []

    for obs in observations:
        if obs.kind != ObservationKind.VULNERABILITY:
            continue
        asset = by_target.get(obs.target)
        if asset is None:
            log.info("detection on %s has no matching asset; skipping", obs.target)
            continue

        cve_ids = obs.data.get("cve_ids") or []
        if not cve_ids:
            # Detections without a CVE (exposed panels, misconfiguration) are kept as
            # observations only; findings are CVE-keyed.
            continue

        template = obs.data.get("template_id")
        matched_at = obs.data.get("matched_at") or obs.target
        evidence = (
            f"Detected by nuclei template {template!r} "
            f"({obs.data.get('severity', 'unknown')} severity) matching at {matched_at}. "
            "This is detection evidence that the weakness is present and reachable, "
            "not evidence of compromise."
        )

        for cve_id in cve_ids:
            get_or_create(session, cve_id)
            session.flush()
            finding = session.scalar(
                select(Finding).where(Finding.asset_id == asset.id, Finding.cve_id == cve_id)
            )
            if finding is None:
                finding = Finding(asset_id=asset.id, cve_id=cve_id)
                session.add(finding)
            # Active detection always supersedes an inferred finding for the same CVE.
            finding.detection_method = DetectionMethod.ACTIVE_DETECTION
            finding.detected_by_tool = obs.source_tool
            finding.evidence = evidence
            findings.append(finding)

    session.flush()
    if findings:
        log.info("recorded %d actively-detected findings", len(findings))
    return findings


def match_findings(session: Session, assets: list[Asset], nvd: NvdClient) -> list[Finding]:
    """Map each asset's fingerprinted technology to CVEs and create findings."""
    by_tech: dict[str, list[Asset]] = defaultdict(list)
    for asset in assets:
        if asset.technology:
            by_tech[asset.technology].append(asset)

    if not by_tech:
        log.info("no fingerprinted technologies to match")
        return []

    findings: list[Finding] = []
    new_cve_ids: set[str] = set()

    for technology, tech_assets in by_tech.items():
        product, version = parse_technology(technology)
        evidence = _lookup_cves(session, nvd, technology, product, version)

        if not evidence.cve_ids:
            continue

        session.flush()
        new_cve_ids.update(evidence.cve_ids)
        for asset in tech_assets:
            findings.extend(_upsert_findings(session, asset, evidence))

    known = {
        r.cve_id
        for r in session.scalars(
            select(CveEnrichment).where(
                CveEnrichment.cve_id.in_(new_cve_ids), CveEnrichment.epss_score.isnot(None)
            )
        )
    }
    apply_epss(session, sorted(new_cve_ids - known))

    log.info("created/updated %d findings across %d technologies", len(findings), len(by_tech))
    return findings


def _upsert_findings(session: Session, asset: Asset, evidence: MatchEvidence) -> list[Finding]:
    existing = {
        f.cve_id: f
        for f in session.scalars(select(Finding).where(Finding.asset_id == asset.id))
    }
    description = evidence.describe(asset.technology or "unknown", asset.discovered_by_tool)

    out: list[Finding] = []
    for cve_id in evidence.cve_ids:
        finding = existing.get(cve_id)
        if finding is None:
            finding = Finding(asset_id=asset.id, cve_id=cve_id)
            session.add(finding)
        finding.detection_method = evidence.method
        finding.detected_by_tool = asset.discovered_by_tool
        finding.evidence = description
        out.append(finding)
    session.flush()
    return out
