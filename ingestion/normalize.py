from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.models import Asset, AssetCriticality, utcnow
from discovery.runner import DiscoveredAsset
from ingestion.criticality import infer_criticality

log = logging.getLogger(__name__)


def ingest_assets(
    session: Session,
    tenant_id: str,
    scan_id: str,
    discovered: list[DiscoveredAsset],
) -> list[Asset]:
    """Stage 2: upsert discovered assets, deduplicating on (tenant, host, port, protocol)."""
    existing = {
        (a.hostname, a.port, a.protocol): a
        for a in session.scalars(select(Asset).where(Asset.tenant_id == tenant_id))
    }

    assets: list[Asset] = []
    created = updated = 0

    for item in discovered:
        key = (item.hostname, item.port, item.protocol)
        asset = existing.get(key)
        if asset is None:
            asset = Asset(
                tenant_id=tenant_id,
                discovered_by_scan_id=scan_id,
                hostname=item.hostname,
                ip_address=item.ip_address,
                port=item.port,
                protocol=item.protocol,
                technology=item.technology,
            )
            session.add(asset)
            session.flush()
            existing[key] = asset
            created += 1
        else:
            asset.last_seen_at = utcnow()
            asset.ip_address = item.ip_address or asset.ip_address
            asset.technology = item.technology or asset.technology
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
