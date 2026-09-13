from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from core.config import load_config
from core.models import Base, Tenant

DEFAULT_TENANT_NAME = "default"

_engine = None
_Session: sessionmaker | None = None


def get_engine():
    global _engine, _Session
    if _engine is None:
        url = load_config().database_url
        kwargs = {"future": True}
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
        _engine = create_engine(url, **kwargs)
        _Session = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def init_db() -> None:
    Base.metadata.create_all(get_engine())


@contextmanager
def session_scope() -> Iterator[Session]:
    get_engine()
    assert _Session is not None
    session = _Session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_default_tenant(session: Session) -> Tenant:
    tenant = session.scalar(select(Tenant).where(Tenant.name == DEFAULT_TENANT_NAME))
    if tenant is None:
        tenant = Tenant(name=DEFAULT_TENANT_NAME)
        session.add(tenant)
        session.flush()
    return tenant
