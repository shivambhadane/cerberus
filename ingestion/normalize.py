"""Stage 2: raw observations -> normalized assets, with provenance preserved."""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.adapters import Observation, ObservationKind
from core.models import Asset, AssetCriticality, ObservationRecord, utcnow
from discovery.runner import DiscoveryResult
from ingestion.criticality import infer_criticality

log = logging.getLogger(__name__)


def persist_observations(session: Session, scan_id: str, observations: list[Observation]) -> int:
    """Store every tool observation verbatim, before any normalization."""
    for obs in observations:
        session.add(
            ObservationRecord(
                scan_id=scan_id,
                kind=obs.kind,
                target=obs.target,
                source_tool=obs.source_tool,
                source_version=obs.source_version,
                data=obs.data,
                raw=obs.raw,
                observed_at=obs.observed_at,
            )
        )
    session.flush()
    log.info("persisted %d raw observations", len(observations))
    return len(observations)


def _technology_index(result: DiscoveryResult) -> dict[str, tuple[str, str]]:
    """target -> (technology, tool). Later observations win, so a dedicated probe
    can refine what a port scanner guessed."""
    index: dict[str, tuple[str, str]] = {}
    for obs in result.observations:
        technology = obs.data.get("technology")
        if not technology:
            continue
        if obs.kind in (ObservationKind.TECHNOLOGY, ObservationKind.OPEN_PORT):
            index[obs.target] = (technology, obs.source_tool)
    return index


def ingest_assets(
    session: Session,
    tenant_id: str,
    scan_id: str,
    result: DiscoveryResult,
    user_id: str | None = None,
    domain_id: str | None = None,
) -> list[Asset]:
    """Upsert discovered endpoints, deduplicating on (owner, host, port, protocol).

    With a `user_id` the lookup is confined to that user's assets, so another user who holds the
    same host:port neither sees nor overwrites this row. Without one (the CLI, and data from before
    users existed) identity falls back to the tenant, over unowned rows only.
    """
    persist_observations(session, scan_id, result.observations)
    technologies = _technology_index(result)

    port_tools = {
        obs.target: obs.source_tool
        for obs in result.by_kind(ObservationKind.OPEN_PORT)
    }

    scope = (
        Asset.user_id == user_id
        if user_id is not None
        else (Asset.tenant_id == tenant_id) & Asset.user_id.is_(None)
    )
    existing = {(a.hostname, a.port, a.protocol): a for a in session.scalars(select(Asset).where(scope))}

    assets: list[Asset] = []
    created = updated = 0

    for endpoint in result.endpoints:
        key = (endpoint.hostname, endpoint.port, endpoint.protocol)
        technology, tech_tool = technologies.get(str(endpoint), (None, None))
        found_by = port_tools.get(str(endpoint))

        asset = existing.get(key)
        if asset is None:
            asset = Asset(
                tenant_id=tenant_id,
                user_id=user_id,
                domain_id=domain_id,
                discovered_by_scan_id=scan_id,
                hostname=endpoint.hostname,
                ip_address=endpoint.ip_address,
                port=endpoint.port,
                protocol=endpoint.protocol,
                technology=technology,
                discovered_by_tool=tech_tool or found_by,
            )
            session.add(asset)
            session.flush()
            existing[key] = asset
            created += 1
        else:
            asset.last_seen_at = utcnow()
            asset.ip_address = endpoint.ip_address or asset.ip_address
            if technology:
                asset.technology = technology
                asset.discovered_by_tool = tech_tool
            updated += 1

        _ensure_criticality(session, asset)
        assets.append(asset)

    log.info("ingested %d assets (%d new, %d refreshed)", len(assets), created, updated)
    return assets


def _ensure_criticality(session: Session, asset: Asset) -> None:
    """Apply the heuristic only when no tag exists; manual tags are never overwritten."""
    tag = session.scalar(select(AssetCriticality).where(AssetCriticality.asset_id == asset.id))
    if tag is not None:
        return
    level, reason = infer_criticality(asset.hostname, asset.port)
    session.add(AssetCriticality(asset_id=asset.id, level=level, reason=reason))
