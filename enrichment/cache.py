from __future__ import annotations

import logging
from datetime import UTC, timedelta

from sqlalchemy.orm import Session

from core.models import CveEnrichment, SourceRefresh, utcnow
from enrichment.sources import KevRecord, NvdCve, fetch_epss, fetch_kev

log = logging.getLogger(__name__)


def _record_refresh(session: Session, name: str, count: int) -> None:
    row = session.get(SourceRefresh, name)
    if row is None:
        row = SourceRefresh(name=name)
        session.add(row)
    row.last_refreshed_at = utcnow()
    row.record_count = count


def get_or_create(session: Session, cve_id: str) -> CveEnrichment:
    row = session.get(CveEnrichment, cve_id)
    if row is None:
        row = CveEnrichment(cve_id=cve_id)
        session.add(row)
        session.flush()
    return row


def apply_kev(session: Session, record: KevRecord) -> CveEnrichment:
    row = get_or_create(session, record.cve_id)
    row.kev_listed = True
    row.kev_date_added = record.date_added
    row.vendor = record.vendor or row.vendor
    row.product = record.product or row.product
    row.description = row.description or record.description
    row.last_refreshed_at = utcnow()
    return row


def apply_nvd(session: Session, cve: NvdCve) -> CveEnrichment:
    row = get_or_create(session, cve.cve_id)
    if cve.cvss_score is not None:
        row.cvss_score = cve.cvss_score
    if cve.description:
        row.description = cve.description
    row.has_public_exploit = row.has_public_exploit or cve.has_public_exploit
    row.last_refreshed_at = utcnow()
    return row


def apply_epss(session: Session, cve_ids: list[str], record_refresh: bool = False) -> int:
    """Fetch and store EPSS scores for the given CVEs.

    `record_refresh` is set only by the global refresh; per-scan backfills must not
    overwrite the source-level refresh timestamp and count.
    """
    if not cve_ids:
        return 0
    scores = fetch_epss(cve_ids)
    for cve_id, score in scores.items():
        get_or_create(session, cve_id).epss_score = score
    if scores and record_refresh:
        _record_refresh(session, "epss", len(scores))
    return len(scores)


def refresh_global_sources(session: Session, include_epss: bool = True) -> dict[str, int]:
    """Stage 3: pull tenant-independent threat intelligence into the local cache."""
    kev = fetch_kev()
    for record in kev.values():
        apply_kev(session, record)
    _record_refresh(session, "kev", len(kev))
    session.flush()

    counts = {"kev": len(kev), "epss": 0}
    if include_epss:
        counts["epss"] = apply_epss(session, list(kev), record_refresh=True)

    log.info("enrichment cache refreshed: %s", counts)
    return counts


def cache_warning(session: Session, max_age_hours: int) -> str | None:
    """Warn when the KEV cache is missing or stale.

    Without it every finding scores as if it were not exploited, which silently
    inverts the ranking this tool exists to produce - so this must never fail quietly.
    """
    kev = session.get(SourceRefresh, "kev")
    if kev is None or not kev.record_count:
        return (
            "enrichment cache is empty: every finding will be scored as NOT actively "
            "exploited, so the ranking will be wrong. Run: python scripts/refresh_enrichment.py"
        )

    refreshed = kev.last_refreshed_at
    if refreshed.tzinfo is None:
        refreshed = refreshed.replace(tzinfo=UTC)
    age = utcnow() - refreshed
    if age > timedelta(hours=max_age_hours):
        hours = int(age.total_seconds() // 3600)
        return (
            f"enrichment cache is {hours}h old (limit {max_age_hours}h); newly exploited "
            "CVEs may be missing. Run: python scripts/refresh_enrichment.py"
        )
    return None
