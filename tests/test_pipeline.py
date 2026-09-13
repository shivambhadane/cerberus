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
