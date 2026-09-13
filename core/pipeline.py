from __future__ import annotations

import logging

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


def create_scan_record(
    session,
    target_domain: str,
    authorized: bool,
    tenant_id: str,
    profile: str = "safe",
) -> str:
    """Create a pending scan row inside an existing session."""
    if not authorized:
        raise NotAuthorizedError(
            "Scanning requires an explicit authorization attestation. "
            "See docs/RULES_OF_ENGAGEMENT.md."
        )
    scan = Scan(
        tenant_id=tenant_id, target_domain=target_domain, profile=profile, status="pending"
    )
    session.add(scan)
    session.flush()
    return scan.id


def start_scan(
    target_domain: str,
    authorized: bool,
    tenant_id: str | None = None,
    profile: str = "safe",
) -> str:
    """Create a pending scan in its own session. Callers that already hold a session
    must use create_scan_record instead - nesting a second write transaction
    deadlocks on SQLite when the outer one is holding a write lock."""
    init_db()
    with session_scope() as session:
        tid = tenant_id or get_default_tenant(session).id
        return create_scan_record(session, target_domain, authorized, tid, profile)


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
        "active_detections": 0, "warning": None,
    }

    try:
        with session_scope() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                raise ScanNotFoundError(f"no scan with id {scan_id}")
            scan.status = "discovering"
            target, tenant_id = scan.target_domain, scan.tenant_id
            active_profile = profile or get_profile(scan.profile, opted_in=True)

            summary["warning"] = cache_warning(session, config.enrichment.refresh_interval_hours)
            if summary["warning"]:
                log.warning("%s", summary["warning"])

        active_scope = scope or Scope(
            domain=target,
            include_subdomains=config.discovery.subdomain_enum,
            excluded_hosts=set(config.discovery.excluded_hosts),
            excluded_ports=set(config.discovery.excluded_ports),
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
        )
        summary["observations"] = len(discovered.observations)
        summary["tools"] = sorted({o.source_tool for o in discovered.observations})

        with session_scope() as session:
            scan = session.get(Scan, scan_id)
            assets = ingest_assets(session, tenant_id, scan_id, discovered)
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

        with session_scope() as session:
            summary["scored"] = score_pending_findings(session, config.scoring.weights)
            scan = session.get(Scan, scan_id)
            scan.status = "completed"
            scan.completed_at = utcnow()

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
