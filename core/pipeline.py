from __future__ import annotations

import logging

from core.config import Config, load_config
from core.db import get_default_tenant, init_db, session_scope
from core.models import Scan, utcnow
from discovery.runner import run_discovery
from enrichment.matcher import match_findings
from enrichment.sources import NvdClient
from ingestion.normalize import ingest_assets
from scoring.engine import score_pending_findings

log = logging.getLogger(__name__)


class NotAuthorizedError(PermissionError):
    """Raised when a scan is requested without the authorization attestation."""


class ScanNotFoundError(LookupError):
    """Raised when the pipeline is handed a scan id that is not in the database."""


def create_scan_record(session, target_domain: str, authorized: bool, tenant_id: str) -> str:
    """Create a pending scan row inside an existing session."""
    if not authorized:
        raise NotAuthorizedError(
            "Scanning requires an explicit authorization attestation. "
            "See docs/RULES_OF_ENGAGEMENT.md."
        )
    scan = Scan(tenant_id=tenant_id, target_domain=target_domain, status="pending")
    session.add(scan)
    session.flush()
    return scan.id


def start_scan(target_domain: str, authorized: bool, tenant_id: str | None = None) -> str:
    """Create a pending scan in its own session. Callers that already hold a session
    must use create_scan_record instead - nesting a second write transaction
    deadlocks on SQLite when the outer one is holding a write lock."""
    init_db()
    with session_scope() as session:
        tid = tenant_id or get_default_tenant(session).id
        return create_scan_record(session, target_domain, authorized, tid)


def run_pipeline(scan_id: str, config: Config | None = None) -> dict:
    """Run discovery -> ingestion -> enrichment -> scoring for an existing scan."""
    config = config or load_config()
    nvd = NvdClient(api_key=config.nvd_api_key)
    summary = {"assets": 0, "findings": 0, "scored": 0}

    try:
        with session_scope() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                raise ScanNotFoundError(f"no scan with id {scan_id}")
            scan.status = "discovering"
            target, tenant_id = scan.target_domain, scan.tenant_id

        discovered = run_discovery(target, config.discovery)

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
            summary["findings"] = len(findings)
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
