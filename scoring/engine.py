"""Exploitability scoring.

Risk score is a weighted blend of four signals, with weights read from config.yaml:

    kev_status         is this being exploited in the wild right now?
    epss_score         how likely is exploitation in the next 30 days?
    asset_criticality  how much do we care about the affected system?
    exposure_context   how reachable is it, and how much does the flaw grant?

CVSS deliberately is not a top-level weight: severity is not danger. It enters
only through exposure_context (half of it), so a critical-severity flaw nobody
exploits still ranks below a medium-severity one under active attack.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.adapters import DetectionMethod
from core.models import Asset, AssetCriticality, CveEnrichment, Finding
from ingestion.criticality import SENSITIVE_PORTS

log = logging.getLogger(__name__)

DEFAULT_WEIGHTS = {
    "kev_status": 0.35,
    "epss_score": 0.25,
    "asset_criticality": 0.25,
    "exposure_context": 0.15,
}

CRITICALITY_VALUES = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
WEB_PORTS = {80, 443, 8000, 8080, 8443, 8888, 3000}

KEV_WEIGHT_FULL = 1.0
KEV_WEIGHT_PUBLIC_EXPLOIT = 0.4


@dataclass(frozen=True)
class ScoreResult:
    risk_score: float
    reasoning: str
    components: dict[str, float]


def _kev_component(cve: CveEnrichment) -> tuple[float, str | None]:
    if cve.kev_listed:
        added = f", added {cve.kev_date_added.isoformat()}" if cve.kev_date_added else ""
        return KEV_WEIGHT_FULL, f"actively exploited (CISA KEV{added})"
    if cve.has_public_exploit:
        return KEV_WEIGHT_PUBLIC_EXPLOIT, "public proof-of-concept exploit available"
    return 0.0, None


def _epss_component(cve: CveEnrichment) -> tuple[float, str | None]:
    if cve.epss_score is None:
        return 0.0, None
    pct = round(cve.epss_score * 100)
    if cve.epss_score >= 0.5:
        return cve.epss_score, f"{pct}% predicted exploitation probability (EPSS)"
    if cve.epss_score >= 0.05:
        return cve.epss_score, f"moderate exploitation probability ({pct}% EPSS)"
    return cve.epss_score, None


def _exposure_component(port: int, cvss: float | None) -> tuple[float, str | None]:
    """Half reachability (what the port exposes), half severity (what the flaw grants)."""
    if port in SENSITIVE_PORTS:
        reach, note = 1.0, SENSITIVE_PORTS[port].lower()
    elif port in WEB_PORTS:
        reach, note = 0.7, f"internet-facing web service on port {port}"
    else:
        reach, note = 0.5, f"exposed on port {port}"

    severity = (cvss / 10.0) if cvss is not None else 0.5
    if cvss is not None and cvss >= 9.0:
        note = f"{note}, critical severity (CVSS {cvss})"
    return 0.5 * reach + 0.5 * severity, note


def score_finding(
    cve: CveEnrichment,
    criticality_level: str,
    criticality_reason: str | None,
    port: int,
    weights: dict[str, float] | None = None,
    detection_method: str | None = None,
) -> ScoreResult:
    """Score one finding.

    `detection_method` is reported but deliberately does not change the score. How a
    weakness was found says how confident we are that it exists, not how dangerous it
    is; folding confidence into the risk number would make the weights in config.yaml
    stop describing the result.
    """
    weights = {**DEFAULT_WEIGHTS, **(weights or {})}

    kev_value, kev_note = _kev_component(cve)
    epss_value, epss_note = _epss_component(cve)
    crit_value = CRITICALITY_VALUES.get(criticality_level, 0.5)
    exposure_value, exposure_note = _exposure_component(port, cve.cvss_score)

    components = {
        "kev_status": kev_value,
        "epss_score": epss_value,
        "asset_criticality": crit_value,
        "exposure_context": exposure_value,
    }
    score = sum(components[name] * weights.get(name, 0.0) for name in components) * 100

    crit_note = (
        "business-critical asset"
        if criticality_level == "critical"
        else f"{criticality_level}-criticality asset"
    )
    if criticality_reason:
        crit_note += f" ({criticality_reason})"

    detection_note = (
        "confirmed by active probe"
        if detection_method == DetectionMethod.ACTIVE_DETECTION
        else None
    )
    notes = [n for n in (kev_note, epss_note, crit_note, exposure_note, detection_note) if n]
    summary = "; ".join(notes)
    reasoning = (summary[:1].upper() + summary[1:] + ".") if summary else "No risk signals available."
    if not kev_note and (cve.epss_score or 0) < 0.05:
        reasoning += " No evidence of exploitation in the wild."

    return ScoreResult(round(score, 1), reasoning, components)


def score_pending_findings(session: Session, weights: dict[str, float] | None = None) -> int:
    """Stage 4: (re)score every finding from current enrichment data."""
    rows = session.execute(
        select(Finding, CveEnrichment, Asset, AssetCriticality)
        .join(CveEnrichment, Finding.cve_id == CveEnrichment.cve_id)
        .join(Asset, Finding.asset_id == Asset.id)
        .outerjoin(AssetCriticality, AssetCriticality.asset_id == Asset.id)
    ).all()

    for finding, cve, asset, criticality in rows:
        level = criticality.level if criticality else "medium"
        reason = criticality.reason if criticality else None
        result = score_finding(cve, level, reason, asset.port, weights, finding.detection_method)
        finding.risk_score = result.risk_score
        finding.reasoning = result.reasoning

    log.info("scored %d findings", len(rows))
    return len(rows)
