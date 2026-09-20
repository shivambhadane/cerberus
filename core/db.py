from __future__ import annotations

import logging
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config as AlembicConfig
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import MetaData, create_engine, inspect, select
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session, sessionmaker

from core.config import ROOT, load_config
from core.models import Base, Tenant

log = logging.getLogger(__name__)

DEFAULT_TENANT_NAME = "default"

# The revision whose schema equals what `Base.metadata.create_all` produced before
# migrations existed. A database created that way is adopted at this revision.
BASELINE_REVISION = "0001"


def redact_url(url: str) -> str:
    """A database URL that is safe to print or log: the password is masked."""
    return make_url(url).render_as_string(hide_password=True)


class SchemaMismatchError(RuntimeError):
    """The database has tables but its schema does not match this version of Cerberus."""

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


def _alembic_config(engine: Engine) -> AlembicConfig:
    config = AlembicConfig(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    # ConfigParser treats % as interpolation, so a URL-encoded password must be escaped.
    url = engine.url.render_as_string(hide_password=False).replace("%", "%%")
    config.set_main_option("sqlalchemy.url", url)
    config.attributes["configure_logger"] = False  # see migrations/env.py
    return config


def _current_revision(engine: Engine) -> str | None:
    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


def schema_differences(engine: Engine) -> list:
    """Differences between the live database and the current models (empty = in sync)."""
    with engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={"compare_type": False})
        return compare_metadata(context, Base.metadata)


def describe_differences(differences: list, limit: int = 4) -> str:
    """Schema differences as a short human sentence rather than SQLAlchemy reprs."""
    parts: list[str] = []
    for diff in differences:
        item = diff[0] if isinstance(diff, list) else diff
        kind = item[0]
        if kind == "add_table":
            parts.append(f"missing table {item[1].name}")
        elif kind == "remove_table":
            parts.append(f"unexpected table {item[1].name}")
        elif kind == "add_column":
            parts.append(f"missing column {item[2]}.{item[3].name}")
        elif kind == "remove_column":
            parts.append(f"unexpected column {item[2]}.{item[3].name}")
        else:
            parts.append(str(kind).replace("_", " "))
    shown = ", ".join(parts[:limit])
    more = f" (+{len(parts) - limit} more)" if len(parts) > limit else ""
    return shown + more


def _matching_revision(engine: Engine) -> str | None:
    """The newest migration revision whose schema this (unversioned) database matches.

    A database created by create_all before migrations existed was built from whatever the
    models looked like *then*, so it may match the baseline, a later revision, or the
    current models. Each candidate is built in a scratch database and compared against the
    live one, newest first. Stamping blindly at any fixed revision is wrong both ways: at
    the baseline it re-applies migrations the database already contains; at head it hides
    columns a database is missing.
    """
    script = ScriptDirectory.from_config(_alembic_config(engine))
    for revision in script.walk_revisions():  # newest first
        with tempfile.TemporaryDirectory() as tmp:
            scratch = create_engine(f"sqlite:///{tmp}/scratch.db")
            try:
                command.upgrade(_alembic_config(scratch), revision.revision)
                expected = MetaData()
                expected.reflect(bind=scratch)
                expected.remove(expected.tables["alembic_version"])
            finally:
                scratch.dispose()
            with engine.connect() as connection:
                context = MigrationContext.configure(connection, opts={"compare_type": False})
                differences = compare_metadata(context, expected)
        if not differences:
            return revision.revision
    return None


def migrate(engine: Engine) -> None:
    """Bring a database to the latest schema.

    Three cases:
      * empty database        -> run every migration
      * migrated database     -> run whatever is pending
      * legacy database       -> created by create_all before migrations existed. It is
                                 adopted at the newest revision whose schema it matches, then
                                 upgraded from there. If it matches none, it is refused:
                                 stamping it as current while silently missing columns is
                                 exactly the failure that migrations exist to prevent.
    """
    config = _alembic_config(engine)
    # Alembic narrates every run ("Context impl SQLiteImpl", ...). The CLI runs init_db on
    # every command, so that would bury real output; migrate() logs one summary line instead.
    logging.getLogger("alembic").setLevel(logging.WARNING)
    tables = set(inspect(engine).get_table_names())

    if tables and "alembic_version" not in tables:
        revision = _matching_revision(engine)
        if revision is None:
            differences = schema_differences(engine)
            raise SchemaMismatchError(
                "This database was created before migrations existed and its schema matches "
                f"no known revision. Compared with the current models: "
                f"{describe_differences(differences)}. Back it up and recreate it, or migrate "
                "it by hand, then run `python scripts/init_db.py` again."
            )
        command.stamp(config, revision)

    before = _current_revision(engine)
    command.upgrade(config, "head")
    after = _current_revision(engine)
    if before != after:
        log.info("migrated database %s -> %s", before or "(empty)", after)


def init_db() -> None:
    migrate(get_engine())


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
