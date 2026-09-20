"""Alembic environment.

The URL comes from core.config so that migrations target exactly the database the rest of
Cerberus uses. `render_as_batch` is enabled because SQLite (the zero-setup development
database) cannot ALTER most things in place; batch mode rebuilds the table instead, and is
a no-op on PostgreSQL.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

from core.config import load_config
from core.models import Base

config = context.config
# fileConfig() resets the ROOT logger to WARNING and replaces its handlers. That is what the
# `alembic` command line wants, but when Cerberus drives migrations itself (core.db.migrate) it
# silently removed all of the application's scan logging. Cerberus opts out.
if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def _url() -> str:
    # An explicit URL (set by core.db when it drives migrations programmatically) wins.
    return config.get_main_option("sqlalchemy.url") or load_config().database_url


def run_migrations_offline() -> None:
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    url = _url()
    kwargs = {"poolclass": pool.NullPool}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(url, **kwargs)
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
