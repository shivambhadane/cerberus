from core.models import Asset, AssetCriticality, Tenant
from discovery.runner import DiscoveredAsset
from ingestion.criticality import infer_criticality
from ingestion.normalize import ingest_assets


def make_tenant(session) -> str:
    tenant = Tenant(name="test")
    session.add(tenant)
    session.flush()
    return tenant.id


def test_rescanning_does_not_duplicate_assets(session):
    tenant_id = make_tenant(session)
    discovered = [DiscoveredAsset("api.example.com", "203.0.113.10", 443, "tcp", "nginx/1.24.0")]

    ingest_assets(session, tenant_id, "scan-1", discovered)
    ingest_assets(session, tenant_id, "scan-2", discovered)

    assert session.query(Asset).count() == 1


def test_rescan_refreshes_last_seen(session):
    tenant_id = make_tenant(session)
    discovered = [DiscoveredAsset("api.example.com", "203.0.113.10", 443, "tcp", None)]

    first = ingest_assets(session, tenant_id, "scan-1", discovered)[0]
    seen_before = first.last_seen_at
    ingest_assets(session, tenant_id, "scan-2", discovered)

    assert session.query(Asset).one().last_seen_at >= seen_before


def test_distinct_ports_are_distinct_assets(session):
    tenant_id = make_tenant(session)
    ingest_assets(
        session,
        tenant_id,
        "scan-1",
        [
            DiscoveredAsset("api.example.com", "203.0.113.10", 443, "tcp", None),
            DiscoveredAsset("api.example.com", "203.0.113.10", 22, "tcp", None),
        ],
    )
    assert session.query(Asset).count() == 2


def test_manual_criticality_is_not_overwritten(session):
    tenant_id = make_tenant(session)
    discovered = [DiscoveredAsset("test.example.com", "203.0.113.10", 443, "tcp", None)]
    asset = ingest_assets(session, tenant_id, "scan-1", discovered)[0]

    tag = session.query(AssetCriticality).filter_by(asset_id=asset.id).one()
    tag.level = "critical"
    tag.reason = "manually tagged by the security team"
    session.flush()

    ingest_assets(session, tenant_id, "scan-2", discovered)
    assert session.query(AssetCriticality).filter_by(asset_id=asset.id).one().level == "critical"


def test_criticality_heuristics():
    assert infer_criticality("login.example.com", 443)[0] == "critical"
    assert infer_criticality("api.example.com", 443)[0] == "high"
    assert infer_criticality("test.example.com", 443)[0] == "low"
    assert infer_criticality("example.com", 5432)[0] == "high"
    assert infer_criticality("example.com", 443)[0] == "medium"
