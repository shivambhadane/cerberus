from core.adapters import Endpoint, Observation, ObservationKind
from core.models import Asset, AssetCriticality, ObservationRecord, Tenant
from discovery.runner import DiscoveryResult
from ingestion.criticality import infer_criticality
from ingestion.normalize import ingest_assets


def make_tenant(session) -> str:
    tenant = Tenant(name="test")
    session.add(tenant)
    session.flush()
    return tenant.id


def result_for(hostname="api.example.com", port=443, technology="nginx/1.24.0", tool="tcp_connect"):
    endpoint = Endpoint(hostname=hostname, ip_address="203.0.113.10", port=port, protocol="tcp")
    observations = [
        Observation(
            kind=ObservationKind.OPEN_PORT,
            target=f"{hostname}:{port}",
            source_tool=tool,
            data={"hostname": hostname, "ip_address": "203.0.113.10", "port": port, "protocol": "tcp"},
        )
    ]
    if technology:
        observations.append(
            Observation(
                kind=ObservationKind.TECHNOLOGY,
                target=f"{hostname}:{port}",
                source_tool="http_probe",
                data={"hostname": hostname, "port": port, "technology": technology},
                raw=f"Server: {technology}",
            )
        )
    return DiscoveryResult(observations=observations, endpoints=[endpoint])


def test_rescanning_does_not_duplicate_assets(session):
    tenant_id = make_tenant(session)
    ingest_assets(session, tenant_id, "scan-1", result_for())
    ingest_assets(session, tenant_id, "scan-2", result_for())

    assert session.query(Asset).count() == 1


def test_rescan_refreshes_last_seen(session):
    tenant_id = make_tenant(session)
    first = ingest_assets(session, tenant_id, "scan-1", result_for(technology=None))[0]
    seen_before = first.last_seen_at

    ingest_assets(session, tenant_id, "scan-2", result_for(technology=None))

    assert session.query(Asset).one().last_seen_at >= seen_before


def test_distinct_ports_are_distinct_assets(session):
    tenant_id = make_tenant(session)
    ingest_assets(session, tenant_id, "scan-1", result_for(port=443))
    ingest_assets(session, tenant_id, "scan-1", result_for(port=22, technology="openssh/8.9"))

    assert session.query(Asset).count() == 2


def test_raw_observations_are_persisted_with_their_tool(session):
    tenant_id = make_tenant(session)
    ingest_assets(session, tenant_id, "scan-1", result_for())

    records = session.query(ObservationRecord).all()
    assert {r.source_tool for r in records} == {"tcp_connect", "http_probe"}
    assert {r.kind for r in records} == {ObservationKind.OPEN_PORT, ObservationKind.TECHNOLOGY}


def test_asset_records_which_tool_identified_it(session):
    tenant_id = make_tenant(session)
    asset = ingest_assets(session, tenant_id, "scan-1", result_for())[0]

    assert asset.discovered_by_tool == "http_probe"
    assert asset.technology == "nginx/1.24.0"


def test_manual_criticality_is_not_overwritten(session):
    tenant_id = make_tenant(session)
    asset = ingest_assets(session, tenant_id, "scan-1", result_for(hostname="test.example.com"))[0]

    tag = session.query(AssetCriticality).filter_by(asset_id=asset.id).one()
    tag.level = "critical"
    tag.reason = "manually tagged by the security team"
    session.flush()

    ingest_assets(session, tenant_id, "scan-2", result_for(hostname="test.example.com"))
    assert session.query(AssetCriticality).filter_by(asset_id=asset.id).one().level == "critical"


def test_criticality_heuristics():
    assert infer_criticality("login.example.com", 443)[0] == "critical"
    assert infer_criticality("api.example.com", 443)[0] == "high"
    assert infer_criticality("test.example.com", 443)[0] == "low"
    assert infer_criticality("example.com", 5432)[0] == "high"
    assert infer_criticality("example.com", 443)[0] == "medium"


# --- ownership: an asset is one host:port per owner ---------------------------------------------

def test_two_users_holding_the_same_host_get_separate_assets(session, make_user):
    """Regression for the multi-user move: dedupe used to be per tenant, so the second user's scan
    would have found and overwritten the first user's row."""
    tenant_id = make_tenant(session)
    alice, bob = make_user("alice@example.com"), make_user("bob@example.com")

    nginx, apache = result_for(technology="nginx/1.24.0"), result_for(technology="apache/2.4.49")
    a = ingest_assets(session, tenant_id, "scan-a", nginx, user_id=alice.id)[0]
    b = ingest_assets(session, tenant_id, "scan-b", apache, user_id=bob.id)[0]

    assert a.id != b.id and session.query(Asset).count() == 2
    assert (a.user_id, b.user_id) == (alice.id, bob.id)
    assert a.technology == "nginx/1.24.0"  # bob's scan did not touch alice's row


def test_a_users_rescan_refreshes_their_own_asset_not_a_duplicate(session, make_user):
    tenant_id = make_tenant(session)
    user = make_user()
    ingest_assets(session, tenant_id, "scan-1", result_for(), user_id=user.id)
    ingest_assets(session, tenant_id, "scan-2", result_for(), user_id=user.id)
    assert session.query(Asset).filter_by(user_id=user.id).count() == 1


def test_new_assets_record_their_owner_and_domain(session, make_user):
    tenant_id = make_tenant(session)
    user = make_user()
    asset = ingest_assets(session, tenant_id, "scan-1", result_for(), user_id=user.id, domain_id="dom-1")[0]
    assert (asset.user_id, asset.domain_id) == (user.id, "dom-1")


def test_an_unowned_scan_never_touches_an_owned_asset(session, make_user):
    """The CLI without --owner has no user; it must not adopt or update someone's row."""
    tenant_id = make_tenant(session)
    user = make_user()
    nginx, apache = result_for(technology="nginx/1.24.0"), result_for(technology="apache/2.4.49")
    owned = ingest_assets(session, tenant_id, "scan-1", nginx, user_id=user.id)[0]
    unowned = ingest_assets(session, tenant_id, "scan-2", apache)[0]

    assert unowned.id != owned.id and unowned.user_id is None
    assert owned.technology == "nginx/1.24.0"
    assert session.query(Asset).count() == 2
