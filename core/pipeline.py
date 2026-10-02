from __future__ import annotations

import logging

from sqlalchemy import select

from core.config import Config, load_config
from core.db import get_default_tenant, init_db, session_scope
from core.models import Scan, utcnow
from core.profiles import ScanProfile, get_profile
from core.scope import Scope
from discovery.runner import run_discovery
from enrichment.cache import cache_warning
from enrichment.matcher import match_findings, record_active_detections
from enrichment.sources import NvdClient
from ingestion.normalize import ingest_assets
from scoring.engine import score_pending_findings

log = logging.getLogger(__name__)


class NotAuthorizedError(PermissionError):
    """Raised when a scan is requested without the authorization attestation."""


class ScanNotFoundError(LookupError):
    """Raised when the pipeline is handed a scan id that is not in the database."""


ACTIVE_SCAN_STATUSES = ("pending", "discovering", "enriching", "scoring")

# Every stage `scans.progress` can report, in pipeline order. A stage missing from
# progress["completed"] when the scan is done simply never ran for this profile (a passive
# profile stops after "dns_resolution") - it is never invented to fill the row in.
SCAN_STAGES = (
    "authorization", "asset_discovery", "dns_resolution", "port_service_discovery",
    "http_discovery", "vulnerability_scan", "enrichment", "risk_analysis", "report",
)


def _record_stage(scan_id: str, stage: str, counts: dict | None = None) -> None:
    """Mark `stage` complete, right now, because it actually just finished. Merges rather than
    replaces: `counts` only ever grows across a scan, and a later stage never erases an earlier
    one's numbers."""
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return
        progress = dict(scan.progress or {})
        completed = list(progress.get("completed", []))
        if stage not in completed:
            completed.append(stage)
        merged_counts = {**progress.get("counts", {}), **(counts or {})}
        # "current" is the stage after the FURTHEST one reached so far, not the first stage
        # never seen - those differ whenever a caller records stages out of declared order
        # (which should not happen, but must not point the UI backwards if it ever does).
        furthest = max((SCAN_STAGES.index(s) for s in completed if s in SCAN_STAGES), default=-1)
        next_index = furthest + 1
        scan.progress = {
            "stages": list(SCAN_STAGES),
            "completed": completed,
            "current": SCAN_STAGES[next_index] if next_index < len(SCAN_STAGES) else None,
            "counts": merged_counts,
        }


def fail_interrupted_scans(session) -> int:
    """Mark scans left active by a previous process as failed.

    Scans run inside the API process, so when it restarts (a routine deploy) any scan it was
    running is simply gone, but its row still says "discovering". The one-scan-at-a-time
    guard would then answer 409 forever and block every future scan until someone edited the
    database by hand.

    This assumes a single API process: at startup nothing else can legitimately be running a
    scan. With several workers it would wrongly fail another worker's live scan.
    """
    orphans = session.scalars(select(Scan).where(Scan.status.in_(ACTIVE_SCAN_STATUSES))).all()
    for scan in orphans:
        scan.status = "failed"
        scan.error = "interrupted: the API process restarted while this scan was running"
        scan.completed_at = utcnow()
    if orphans:
        log.warning("marked %d scan(s) interrupted by a restart as failed", len(orphans))
    return len(orphans)


def create_scan_record(
    session,
    target_domain: str,
    authorized: bool,
    tenant_id: str,
    profile: str = "safe",
    user_id: str | None = None,
    domain_id: str | None = None,
) -> str:
    """Create a pending scan row inside an existing session.

    `authorized` is the attestation the *caller* has already established. The API establishes it
    by proving the user owns a verified domain (core/ownership.py); the CLI takes it from the
    operator's `--authorized` flag. `user_id`/`domain_id` record who the scan belongs to.
    """
    if not authorized:
        raise NotAuthorizedError(
            "Scanning requires an explicit authorization attestation. "
            "See docs/RULES_OF_ENGAGEMENT.md."
        )
    scan = Scan(
        tenant_id=tenant_id, user_id=user_id, domain_id=domain_id,
        target_domain=target_domain, profile=profile, status="pending",
    )
    session.add(scan)
    session.flush()
    return scan.id


def start_scan(
    target_domain: str,
    authorized: bool,
    tenant_id: str | None = None,
    profile: str = "safe",
    user_id: str | None = None,
) -> str:
    """Create a pending scan in its own session. Callers that already hold a session
    must use create_scan_record instead - nesting a second write transaction
    deadlocks on SQLite when the outer one is holding a write lock."""
    init_db()
    with session_scope() as session:
        tid = tenant_id or get_default_tenant(session).id
        return create_scan_record(session, target_domain, authorized, tid, profile, user_id=user_id)


def run_pipeline(
    scan_id: str,
    config: Config | None = None,
    scope: Scope | None = None,
    profile: ScanProfile | None = None,
) -> dict:
    """Run discovery -> ingestion -> enrichment -> scoring for an existing scan.

    `scope` is the authorization boundary; when omitted it is derived from the scan's
    target domain, which permits that domain and its subdomains on public addresses only.
    """
    config = config or load_config()
    nvd = NvdClient(api_key=config.nvd_api_key)
    summary: dict = {
        "assets": 0, "findings": 0, "scored": 0,
        "observations": 0, "tools": [], "profile": None,
        "active_detections": 0, "tool_errors": [], "warning": None,
    }

    try:
        with session_scope() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                raise ScanNotFoundError(f"no scan with id {scan_id}")
            scan.status = "discovering"
            target, tenant_id = scan.target_domain, scan.tenant_id
            owner_id, domain_id = scan.user_id, scan.domain_id
            active_profile = profile or get_profile(scan.profile, opted_in=True)
            # Already true by construction: the API checked ownership and verification before
            # this scan was ever queued (api/main.py create_scan). Recording it is not a guess.
            scan.progress = {"stages": list(SCAN_STAGES), "completed": ["authorization"],
                              "current": "asset_discovery", "counts": {}}

            summary["warning"] = cache_warning(session, config.enrichment.refresh_interval_hours)
            if summary["warning"]:
                log.warning("%s", summary["warning"])

        is_loopback = target in ("127.0.0.1", "localhost", "::1")
        active_scope = scope or Scope(
            domain=target,
            include_subdomains=False if is_loopback else config.discovery.subdomain_enum,
            excluded_hosts=set(config.discovery.excluded_hosts),
            excluded_ports=set(config.discovery.excluded_ports),
            allow_private_addresses=config.discovery.allow_private_addresses,
            # A Test Labs target (api/domains.py: verification_method "testbed"/"lab") is always
            # exactly 127.0.0.1/localhost/::1, never a private-range IP. Grant it only the exact
            # loopback address, never the RFC1918 ranges or the cloud metadata address
            # (169.254.169.254) that a blanket allow_private_addresses would also open up.
            allow_loopback_only=is_loopback,
        )
        summary["profile"] = active_profile.name
        log.info(
            "scan %s scope=%s subdomains=%s private_addresses=%s profile=%s (%s)",
            scan_id, active_scope.domain, active_scope.include_subdomains,
            active_scope.allow_private_addresses, active_profile.name,
            "active probing" if active_profile.runs_active_probes else "passive only",
        )

        discovered = run_discovery(
            active_scope, active_profile,
            enumerate_subdomains=config.discovery.subdomain_enum,
            config=config.discovery,
            on_stage=lambda name, counts: _record_stage(scan_id, name, counts),
        )
        summary["observations"] = len(discovered.observations)
        summary["tool_errors"] = list(discovered.errors)
        summary["tools"] = sorted({o.source_tool for o in discovered.observations})

        with session_scope() as session:
            scan = session.get(Scan, scan_id)
            assets = ingest_assets(
                session, tenant_id, scan_id, discovered, user_id=owner_id, domain_id=domain_id
            )
            summary["assets"] = len(assets)
            scan.status = "enriching"
            asset_ids = [a.id for a in assets]

        with session_scope() as session:
            from core.models import Asset

            assets = [session.get(Asset, aid) for aid in asset_ids]
            findings = match_findings(session, assets, nvd)
            detected = record_active_detections(session, assets, discovered.observations)
            summary["findings"] = len(findings)
            summary["active_detections"] = len(detected)
            session.get(Scan, scan_id).status = "scoring"

        _record_stage(scan_id, "enrichment", {"findings": summary["findings"]})

        with session_scope() as session:
            summary["scored"] = score_pending_findings(session, config.scoring.weights)
            scan = session.get(Scan, scan_id)
            scan.status = "completed"
            scan.completed_at = utcnow()
            # A scan can finish and still have been degraded (a scanner timed out, the KEV
            # cache was stale). Persist that so it is visible after the terminal is gone.
            scan.warnings = [w for w in (*summary["tool_errors"], summary["warning"]) if w]

        # "scored" is deliberately the raw number score_pending_findings returned, which covers
        # every finding on the account (it re-scores against current KEV/EPSS data), not only
        # this scan's. The dashboard label says so rather than this count being narrowed here:
        # reporting a smaller, scan-scoped number would mean reporting work that did not happen.
        _record_stage(scan_id, "risk_analysis", {"scored": summary["scored"]})
        _record_stage(scan_id, "report")

    except Exception as exc:
        log.exception("scan %s failed", scan_id)
        with session_scope() as session:
            scan = session.get(Scan, scan_id)
            if scan is not None:
                scan.status = "failed"
                scan.error = str(exc)
                scan.completed_at = utcnow()
        raise

    log.info("scan %s completed: %s", scan_id, summary)
    return summary
