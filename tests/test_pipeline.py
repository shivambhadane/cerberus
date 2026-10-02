import pytest

from core.models import Scan, Tenant
from core.pipeline import NotAuthorizedError, ScanNotFoundError, create_scan_record, run_pipeline


def test_unauthorized_scan_is_refused(session):
    with pytest.raises(NotAuthorizedError):
        create_scan_record(session, "example.com", authorized=False, tenant_id="t1")

    assert session.query(Scan).count() == 0


def test_authorized_scan_creates_a_pending_row(session):
    tenant = Tenant(name="test")
    session.add(tenant)
    session.flush()

    scan_id = create_scan_record(session, "example.com", authorized=True, tenant_id=tenant.id)

    scan = session.get(Scan, scan_id)
    assert scan.status == "pending"
    assert scan.target_domain == "example.com"


def test_unknown_scan_id_raises_instead_of_crashing_on_none(monkeypatch):
    """The background task must fail loudly if its scan row is not visible yet."""
    monkeypatch.setattr("core.pipeline.session_scope", _null_session_scope)

    with pytest.raises(ScanNotFoundError):
        run_pipeline("missing-scan-id")


class _NullSession:
    def get(self, *_args):
        return None


class _NullScope:
    def __enter__(self):
        return _NullSession()

    def __exit__(self, *_args):
        return False


def _null_session_scope():
    return _NullScope()


def test_empty_cache_produces_a_warning(session):
    from enrichment.cache import cache_warning

    warning = cache_warning(session, max_age_hours=24)
    assert warning is not None
    assert "refresh_enrichment" in warning


def test_stale_cache_produces_a_warning(session):
    from datetime import timedelta

    from core.models import SourceRefresh, utcnow
    from enrichment.cache import cache_warning

    session.add(SourceRefresh(name="kev", record_count=1700, last_refreshed_at=utcnow() - timedelta(days=5)))
    session.flush()

    warning = cache_warning(session, max_age_hours=24)
    assert warning is not None
    assert "old" in warning


def test_fresh_cache_produces_no_warning(session):
    from core.models import SourceRefresh, utcnow
    from enrichment.cache import cache_warning

    session.add(SourceRefresh(name="kev", record_count=1700, last_refreshed_at=utcnow()))
    session.flush()

    assert cache_warning(session, max_age_hours=24) is None


# --- scan progress: core.pipeline._record_stage ---------------------------------------------

class _OneSession:
    """Wraps a real test session as the context manager session_scope() returns, so
    _record_stage's own `with session_scope() as session:` reaches the fixture's data."""

    def __init__(self, session):
        self._session = session

    def __enter__(self):
        return self._session

    def __exit__(self, *_args):
        return False


def _patched_session_scope(session, monkeypatch):
    monkeypatch.setattr("core.pipeline.session_scope", lambda: _OneSession(session))


def test_record_stage_marks_the_stage_done_and_points_current_at_the_next_one(session, monkeypatch):
    from core.models import Scan, Tenant
    from core.pipeline import SCAN_STAGES, _record_stage

    _patched_session_scope(session, monkeypatch)
    tenant = Tenant(name="t")
    session.add(tenant)
    session.flush()
    scan = Scan(tenant_id=tenant.id, target_domain="example.com", status="discovering")
    session.add(scan)
    session.flush()

    _record_stage(scan.id, "asset_discovery", {"subdomains": 3})

    progress = session.get(Scan, scan.id).progress
    assert progress["completed"] == ["asset_discovery"]
    assert progress["current"] == "dns_resolution"
    assert progress["counts"] == {"subdomains": 3}
    assert progress["stages"] == list(SCAN_STAGES)


def test_record_stage_counts_accumulate_and_never_go_backwards(session, monkeypatch):
    from core.models import Scan, Tenant
    from core.pipeline import _record_stage

    _patched_session_scope(session, monkeypatch)
    tenant = Tenant(name="t")
    session.add(tenant)
    session.flush()
    scan = Scan(tenant_id=tenant.id, target_domain="example.com", status="discovering")
    session.add(scan)
    session.flush()

    _record_stage(scan.id, "asset_discovery", {"subdomains": 3})
    _record_stage(scan.id, "dns_resolution", {"hosts_resolved": 2})

    progress = session.get(Scan, scan.id).progress
    assert progress["completed"] == ["asset_discovery", "dns_resolution"]
    assert progress["counts"] == {"subdomains": 3, "hosts_resolved": 2}  # the first stage's count survives
    assert progress["current"] == "port_service_discovery"


def test_record_stage_is_idempotent(session, monkeypatch):
    """A stage reported twice (should never happen, but must not corrupt the list) does not
    duplicate itself or move `current` backwards."""
    from core.models import Scan, Tenant
    from core.pipeline import _record_stage

    _patched_session_scope(session, monkeypatch)
    tenant = Tenant(name="t")
    session.add(tenant)
    session.flush()
    scan = Scan(tenant_id=tenant.id, target_domain="example.com", status="discovering")
    session.add(scan)
    session.flush()

    _record_stage(scan.id, "asset_discovery", {"subdomains": 1})
    _record_stage(scan.id, "asset_discovery", {"subdomains": 1})

    progress = session.get(Scan, scan.id).progress
    assert progress["completed"] == ["asset_discovery"]
    assert progress["current"] == "dns_resolution"


def test_record_stage_on_the_last_stage_sets_current_to_none(session, monkeypatch):
    from core.models import Scan, Tenant
    from core.pipeline import SCAN_STAGES, _record_stage

    _patched_session_scope(session, monkeypatch)
    tenant = Tenant(name="t")
    session.add(tenant)
    session.flush()
    scan = Scan(tenant_id=tenant.id, target_domain="example.com", status="discovering")
    session.add(scan)
    session.flush()

    for stage in SCAN_STAGES:
        _record_stage(scan.id, stage)

    progress = session.get(Scan, scan.id).progress
    assert progress["current"] is None
    assert progress["completed"] == list(SCAN_STAGES)


def test_record_stage_does_nothing_for_a_scan_that_no_longer_exists(session, monkeypatch):
    """A background task racing a deleted scan row must not raise - there is simply nothing
    left to record progress on."""
    from core.pipeline import _record_stage

    _patched_session_scope(session, monkeypatch)
    _record_stage("does-not-exist", "asset_discovery", {"subdomains": 1})  # must not raise


# --- scans orphaned by a restart -------------------------------------------------------------

def test_scans_left_active_by_a_restart_are_failed_not_left_blocking(session):
    """Regression: a restart mid-scan left the row 'discovering' forever, so the
    one-scan-at-a-time guard returned 409 for every future scan until the database was edited."""
    from core.models import Scan, Tenant
    from core.pipeline import fail_interrupted_scans

    tenant = Tenant(name="t")
    session.add(tenant)
    session.flush()
    for status in ("pending", "discovering", "enriching", "scoring", "completed", "failed"):
        session.add(Scan(tenant_id=tenant.id, target_domain=f"{status}.example.com", status=status))
    session.flush()

    assert fail_interrupted_scans(session) == 4

    by_domain = {s.target_domain: s for s in session.query(Scan)}
    for status in ("pending", "discovering", "enriching", "scoring"):
        scan = by_domain[f"{status}.example.com"]
        assert scan.status == "failed"
        assert "interrupted" in scan.error
        assert scan.completed_at is not None
    assert by_domain["completed.example.com"].status == "completed"  # untouched
    assert by_domain["failed.example.com"].error is None  # untouched


def test_a_reaped_scan_no_longer_blocks_new_ones(session):
    from core.models import Scan, Tenant
    from core.pipeline import ACTIVE_SCAN_STATUSES, fail_interrupted_scans

    tenant = Tenant(name="t")
    session.add(tenant)
    session.flush()
    session.add(Scan(tenant_id=tenant.id, target_domain="example.com", status="discovering"))
    session.flush()

    fail_interrupted_scans(session)

    assert session.query(Scan).filter(Scan.status.in_(ACTIVE_SCAN_STATUSES)).count() == 0
