"""Deterministic, developer-friendly finding explanations.

Not a model, not AI: every sentence here is built from fields already stored on the finding,
its CVE record and its asset - the same data `scoring/engine.py` used to build `reasoning`. This
module only re-presents it for someone who has never seen a CVE id before, in the order a
developer actually asks the questions: what did you find, what's wrong, why does it matter, how
did you find it, how bad is it, why is it ranked here, what do I do, and how do I check it worked.

Remediation is deliberately generic where Cerberus has no specific fact to offer. NVD's
affected-version ranges are queried live and never stored (see docs/code.md, "technology-to-CVE
matching"), so there is no confirmed "fixed in version X" fact on hand - inventing one would be
exactly the hallucinated remediation this module exists to avoid. What it gives instead is the
detected technology string itself and a pointer to where the real answer lives.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.models import Asset, AssetCriticality, CveEnrichment, Finding


@dataclass(frozen=True)
class Detection:
    host: str
    port: int
    technology: str | None
    detection_method: str
    detected_by_tool: str | None


@dataclass(frozen=True)
class Severity:
    risk_score: float | None
    cvss_score: float | None
    epss_score: float | None
    kev_listed: bool
    asset_criticality: str | None


@dataclass(frozen=True)
class FindingExplanation:
    what_we_found: str
    what_is_the_problem: str
    why_it_matters: str
    how_it_was_detected: Detection
    how_serious: Severity
    why_this_priority: str | None
    what_to_do: str
    how_to_verify: str


def _vendor_name(technology: str | None) -> str | None:
    """"Apache httpd/2.4.49" -> "Apache httpd". Best-effort only; falls back to the raw string."""
    if not technology:
        return None
    return technology.split("/")[0].strip() or technology


def explain(
    finding: Finding, cve: CveEnrichment, asset: Asset, criticality: AssetCriticality | None
) -> FindingExplanation:
    technology = asset.technology
    vendor = _vendor_name(technology)

    if technology:
        what_we_found = (
            f"Your server at {asset.hostname}:{asset.port} is running {technology}, "
            f"which is affected by {cve.cve_id}, a known security vulnerability."
        )
    else:
        what_we_found = (
            f"{asset.hostname}:{asset.port} is affected by {cve.cve_id}, a known security vulnerability."
        )

    what_is_the_problem = (
        cve.description.strip()
        if cve.description
        else (
            f"Cerberus has limited information about {cve.cve_id} beyond its identifier and severity "
            "score. Check the NVD record or the vendor's own advisory for the technical detail."
        )
    )

    matters = []
    matters.append("This system is reachable from the internet, so anyone can attempt to use this weakness.")
    if cve.kev_listed:
        matters.append(
            "CISA's Known Exploited Vulnerabilities catalog lists this as being actively used by "
            "attackers right now, not just theoretically possible."
        )
    if criticality and criticality.level in ("high", "critical"):
        matters.append(
            f"This asset is tagged {criticality.level} criticality, so an incident here costs more."
        )
    why_it_matters = " ".join(matters)

    what_to_do = (
        (
            f"Update {vendor} beyond the version currently detected ({technology}). Cerberus does not "
            "store a confirmed patched-version number - check the vendor's own release notes or security "
            f"advisories for {cve.cve_id} to find the exact version that fixes it, then apply it."
        )
        if technology
        else (
            f"Cerberus could not identify the exact software or version behind this finding. Review the "
            f"evidence below and consult the vendor's security advisories for {cve.cve_id} to confirm "
            "what is affected and what fixes it."
        )
    )

    how_to_verify = (
        "Apply the fix, then start a new scan of this target. If this finding no longer appears in "
        "your ranked list, it worked. If it still appears, confirm the update was actually installed "
        "and that the affected service was restarted."
    )

    return FindingExplanation(
        what_we_found=what_we_found,
        what_is_the_problem=what_is_the_problem,
        why_it_matters=why_it_matters,
        how_it_was_detected=Detection(
            host=asset.hostname,
            port=asset.port,
            technology=technology,
            detection_method=finding.detection_method,
            detected_by_tool=finding.detected_by_tool,
        ),
        how_serious=Severity(
            risk_score=finding.risk_score,
            cvss_score=cve.cvss_score,
            epss_score=cve.epss_score,
            kev_listed=cve.kev_listed,
            asset_criticality=criticality.level if criticality else None,
        ),
        # The existing, already-tested, signal-grounded sentence (scoring/engine.py) IS the
        # deterministic "why this priority" explanation Part 8 asks for - built fresh here would
        # only risk drifting from the number actually shown as the risk score.
        why_this_priority=finding.reasoning,
        what_to_do=what_to_do,
        how_to_verify=how_to_verify,
    )
