import json

import pytest
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text

from core.db import BASELINE_REVISION, SchemaMismatchError, _alembic_config, migrate, schema_differences
from core.models import Base


def head_revision(engine) -> str:
    return ScriptDirectory.from_config(_alembic_config(engine)).get_current_head()


@pytest.fixture
def engine(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'cerberus.db'}")
    yield engine
    engine.dispose()


def test_a_fresh_database_is_built_entirely_by_migrations(engine):
    migrate(engine)

    tables = set(inspect(engine).get_table_names())
    assert set(Base.metadata.tables) <= tables
    assert "alembic_version" in tables


def test_migrations_produce_exactly_the_schema_the_models_describe(engine):
    """The guard against models and migrations drifting apart: after a full upgrade, the
    live schema must be indistinguishable from the models."""
    migrate(engine)
    assert schema_differences(engine) == []


def test_running_migrations_twice_is_harmless(engine):
    migrate(engine)
    migrate(engine)
    assert schema_differences(engine) == []


def test_a_legacy_create_all_database_is_adopted_without_data_loss(engine):
    """Databases created before migrations existed (every dev database so far) must keep
    their data rather than be recreated."""
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(
            text("INSERT INTO tenants (id, name, created_at) VALUES ('t1', 'kept', '2026-09-14')")
        )

    migrate(engine)

    with engine.connect() as connection:
        assert connection.execute(text("SELECT name FROM tenants")).scalar() == "kept"
        version = connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
        # Adopted at the baseline, then upgraded: existing databases end up current, with
        # their rows carried through every table-rebuilding migration on the way.
        assert version == head_revision(engine)


def test_the_baseline_is_an_ancestor_of_head():
    """Adoption stamps BASELINE_REVISION, so it must remain a real revision."""
    engine = create_engine("sqlite://")
    script = ScriptDirectory.from_config(_alembic_config(engine))
    assert BASELINE_REVISION in {r.revision for r in script.walk_revisions()}


def test_data_survives_a_migration_that_rebuilds_tables(engine):
    """0002 changes column types, which on SQLite rebuilds the table. Rows must survive."""
    from alembic import command

    command.upgrade(_alembic_config(engine), "0001")
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO cve_enrichment (cve_id, kev_listed, has_public_exploit, vendor, product, "
                "last_refreshed_at) VALUES ('CVE-2021-41773', 1, 0, 'Apache', 'HTTP Server', '2026-09-18')"
            )
        )

    migrate(engine)  # applies 0002

    with engine.connect() as connection:
        row = connection.execute(text("SELECT product FROM cve_enrichment")).scalar()
    assert row == "HTTP Server"


def test_long_feed_text_now_fits(engine):
    """Regression: a real CISA KEV product is 179 characters; the old VARCHAR(128) made the
    enrichment refresh crash on PostgreSQL (SQLite never enforced the limit, so tests and
    local runs all passed)."""
    from core.models import CveEnrichment

    for column in ("vendor", "product"):
        assert CveEnrichment.__table__.c[column].type.length is None
    from core.models import Asset, ObservationRecord

    assert Asset.__table__.c.technology.type.length is None
    assert ObservationRecord.__table__.c.source_version.type.length is None


def test_a_drifted_legacy_database_is_refused_not_silently_stamped(engine):
    """The failure that started this: a database missing a column (scans.profile) crashed
    at the first INSERT. Stamping it as up to date would only move the crash later."""
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE tenants (id VARCHAR(36) PRIMARY KEY, name VARCHAR(255))"))

    with pytest.raises(SchemaMismatchError, match="matches no known revision"):
        migrate(engine)

    assert "alembic_version" not in inspect(engine).get_table_names()  # not stamped


def test_the_baseline_carries_the_provenance_columns(engine):
    migrate(engine)
    inspector = inspect(engine)

    finding_columns = {c["name"] for c in inspector.get_columns("findings")}
    assert {"detection_method", "detected_by_tool", "evidence"} <= finding_columns
    assert "profile" in {c["name"] for c in inspector.get_columns("scans")}
    assert "discovered_by_tool" in {c["name"] for c in inspector.get_columns("assets")}
    assert "observations" in inspector.get_table_names()


def test_migrating_does_not_reconfigure_the_applications_logging(engine):
    """Regression: Alembic's env.py called logging.config.fileConfig(), which resets the ROOT
    logger to WARNING and replaces its handlers on every init_db(). Wiring migrations in
    silently removed all of Cerberus's scan logging - a scan logged nothing at all."""
    import logging

    root = logging.getLogger()
    level, handlers = root.level, list(root.handlers)

    migrate(engine)

    assert root.level == level
    assert root.handlers == handlers


def test_migrating_is_quiet_apart_from_our_own_summary(engine, caplog):
    """The CLI runs init_db on every command; Alembic's per-run chatter would bury real output."""
    import logging

    with caplog.at_level(logging.INFO):
        migrate(engine)

    noisy = [r for r in caplog.records if r.name.startswith("alembic") and r.levelno < logging.WARNING]
    assert noisy == []
    assert any("migrated database" in r.message for r in caplog.records)


def test_an_up_to_date_database_logs_nothing_on_the_next_run(engine, caplog):
    import logging

    migrate(engine)
    caplog.clear()
    with caplog.at_level(logging.INFO):
        migrate(engine)

    assert [r for r in caplog.records if r.name.startswith(("alembic", "core.db"))] == []


def test_a_legacy_database_from_an_older_schema_is_adopted_at_the_revision_it_matches(engine):
    """The realistic case: a database created by create_all when the models looked like the
    baseline. It must be adopted at that revision and then UPGRADED - not refused for being
    behind the current models, and not stamped as current while missing columns."""
    from alembic import command

    command.upgrade(_alembic_config(engine), "0001")
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE alembic_version"))  # now indistinguishable from legacy
        connection.execute(
            text("INSERT INTO tenants (id, name, created_at) VALUES ('t1', 'kept', '2026-09-14')")
        )
        connection.execute(
            text(
                "INSERT INTO scans (id, tenant_id, target_domain, profile, status, started_at) "
                "VALUES ('s1', 't1', 'example.com', 'safe', 'completed', '2026-09-14')"
            )
        )

    migrate(engine)

    with engine.connect() as connection:
        version = connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
        assert version == head_revision(engine)
        # the columns added after the baseline now exist, and existing rows got their defaults
        assert connection.execute(text("SELECT warnings FROM scans")).scalar() in ("[]", [])
        assert connection.execute(text("SELECT name FROM tenants")).scalar() == "kept"
    assert schema_differences(engine) == []


def test_a_refusal_names_what_is_wrong_in_plain_language(engine):
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE tenants (id VARCHAR(36) PRIMARY KEY, name VARCHAR(255))"))

    with pytest.raises(SchemaMismatchError) as caught:
        migrate(engine)

    message = str(caught.value)
    assert "missing table" in message
    assert "Table(" not in message and len(message) < 500  # no SQLAlchemy repr dumps


def test_existing_scans_and_assets_survive_the_ownership_migration_unowned(engine):
    """0004 adds users and domains. A database that already holds scans keeps every row, with no
    owner: inventing a user for pre-existing data would attribute it to someone who never made it."""
    from alembic import command

    command.upgrade(_alembic_config(engine), "0003")
    with engine.begin() as connection:
        connection.execute(
            text("INSERT INTO tenants (id, name, created_at) VALUES ('t1', 'default', '2026-09-18')")
        )
        connection.execute(
            text(
                "INSERT INTO scans (id, tenant_id, target_domain, profile, status, warnings, started_at) "
                "VALUES ('s1', 't1', 'example.com', 'safe', 'completed', '[]', '2026-09-18')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO assets (id, tenant_id, discovered_by_scan_id, hostname, port, protocol, "
                "first_seen_at, last_seen_at) VALUES ('a1', 't1', 's1', 'example.com', 443, 'tcp', "
                "'2026-09-18', '2026-09-18')"
            )
        )

    migrate(engine)

    with engine.connect() as connection:
        scan = connection.execute(text("SELECT tenant_id, user_id, domain_id FROM scans")).one()
        asset = connection.execute(text("SELECT tenant_id, user_id, domain_id FROM assets")).one()
        assert connection.execute(text("SELECT count(*) FROM users")).scalar() == 0
    assert scan == ("t1", None, None) and asset == ("t1", None, None)
    assert schema_differences(engine) == []


def test_the_ownership_migration_can_be_undone(engine):
    """A downgrade must work, which needs the foreign keys to have names."""
    from alembic import command

    migrate(engine)
    command.downgrade(_alembic_config(engine), "0003")

    inspector = inspect(engine)
    assert not {"users", "domains"} & set(inspector.get_table_names())
    assert not {"user_id", "domain_id"} & {c["name"] for c in inspector.get_columns("scans")}
    assert not {"user_id", "domain_id"} & {c["name"] for c in inspector.get_columns("assets")}

    migrate(engine)  # and forward again
    assert schema_differences(engine) == []


def test_an_asset_is_one_host_port_per_owner(engine):
    """0005: two users may each hold api.example.com:443; one user may not hold it twice; and
    unowned legacy rows keep their per-tenant identity."""
    from sqlalchemy.exc import IntegrityError

    migrate(engine)
    now = "'2026-09-20'"

    def asset(connection, id_, user, host="api.example.com"):
        owner = f"'{user}'" if user else "NULL"
        connection.execute(
            text(
                "INSERT INTO assets (id, tenant_id, user_id, hostname, port, protocol, "
                "first_seen_at, last_seen_at) "
                f"VALUES ('{id_}', 't1', {owner}, '{host}', 443, 'tcp', {now}, {now})"
            )
        )

    with engine.begin() as connection:
        connection.execute(text("INSERT INTO tenants (id, name, created_at) VALUES ('t1', 'd', " + now + ")"))
        for uid in ("u1", "u2"):
            connection.execute(
                text(
                    f"INSERT INTO users (id, email, password_hash, created_at, updated_at) "
                    f"VALUES ('{uid}', '{uid}@x.com', 'h', {now}, {now})"
                )
            )
        asset(connection, "a1", "u1")
        asset(connection, "a2", "u2")  # same host:port, different owner: allowed
        asset(connection, "a3", None)
    for owner in ("u1", None):
        with pytest.raises(IntegrityError), engine.begin() as connection:
            asset(connection, f"dup-{owner}", owner)  # same owner (or both unowned): refused
    with engine.begin() as connection:
        asset(connection, "a4", None, host="other.example.com")  # unowned but a different host


# --- 0006 / 0007: profile picture, connected providers, provider-verified targets -----------------


def _seed_user_and_dns_domain(connection):
    stamp = "'2026-09-20'"
    connection.execute(
        text(
            "INSERT INTO users (id, email, password_hash, created_at, updated_at) "
            f"VALUES ('u1', 'u1@x.com', 'h', {stamp}, {stamp})"
        )
    )
    connection.execute(
        text(
            "INSERT INTO domains (id, user_id, domain, verification_token, verification_method, "
            "verification_status, verified_at, created_at, updated_at) "
            f"VALUES ('d1', 'u1', 'example.com', 'tok', 'dns_txt', 'verified', {stamp}, {stamp}, {stamp})"
        )
    )


def test_existing_users_and_dns_verified_domains_are_untouched_by_the_provider_migrations(engine):
    """0006 and 0007 are additive: a DNS-verified domain stays exactly as it was, with no provider."""
    from alembic import command

    command.upgrade(_alembic_config(engine), "0005")
    with engine.begin() as connection:
        _seed_user_and_dns_domain(connection)

    migrate(engine)

    with engine.connect() as connection:
        user = connection.execute(text("SELECT email, picture_url, auth_provider FROM users")).one()
        domain = connection.execute(
            text(
                "SELECT domain, verification_method, verification_status, provider, "
                "provider_connection_id, provider_project_id, provider_resource_id FROM domains"
            )
        ).one()
    assert user == ("u1@x.com", None, None)
    assert domain == ("example.com", "dns_txt", "verified", None, None, None, None)
    assert schema_differences(engine) == []


def test_the_provider_tables_have_the_constraints_that_make_them_safe(engine):
    from sqlalchemy.exc import IntegrityError

    migrate(engine)
    stamp = "'2026-09-20'"

    def connection_row(connection, id_, account):
        connection.execute(
            text(
                "INSERT INTO connected_providers (id, user_id, provider, provider_account_id, "
                "access_token_encrypted, created_at, updated_at) "
                f"VALUES ('{id_}', 'u1', 'vercel', '{account}', 'sealed', {stamp}, {stamp})"
            )
        )

    with engine.begin() as connection:
        _seed_user_and_dns_domain(connection)
        connection_row(connection, "c1", "acct-1")
        connection_row(connection, "c2", "acct-2")  # a second account of the same provider: allowed
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection_row(connection, "c3", "acct-1")  # the same account twice: refused
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO oauth_states (id, user_id, provider, state_hash, browser_hash, created_at, "
                f"expires_at) VALUES ('s1', 'u1', 'vercel', 'h', 'b', {stamp}, {stamp})"
            )
        )
        connection.execute(
            text(
                "INSERT INTO oauth_states (id, user_id, provider, state_hash, browser_hash, created_at, "
                f"expires_at) VALUES ('s2', 'u1', 'vercel', 'h', 'b', {stamp}, {stamp})"  # same state hash
            )
        )


def test_the_provider_migrations_can_be_undone_and_redone(engine):
    from alembic import command

    migrate(engine)
    command.downgrade(_alembic_config(engine), "0005")

    inspector = inspect(engine)
    assert not {"connected_providers", "oauth_states"} & set(inspector.get_table_names())
    domain_columns = {c["name"] for c in inspector.get_columns("domains")}
    assert (
        not {"provider", "provider_connection_id", "provider_project_id", "provider_resource_id"}
        & domain_columns
    )
    assert not {"picture_url", "auth_provider"} & {c["name"] for c in inspector.get_columns("users")}

    migrate(engine)  # and forward again
    assert schema_differences(engine) == []
    assert "connected_providers" in inspect(engine).get_table_names()


def test_the_admin_flag_is_additive_and_defaults_false(engine):
    """0009 adds one column. An existing account must come back `is_admin = 0` (false), not NULL
    and not invented as true."""
    from alembic import command

    command.upgrade(_alembic_config(engine), "0008")
    with engine.begin() as connection:
        _seed_user_and_dns_domain(connection)

    migrate(engine)
    with engine.connect() as connection:
        is_admin, email = connection.execute(
            text("SELECT is_admin, email FROM users WHERE id = 'u1'")
        ).one()
    assert (is_admin, email) == (0, "u1@x.com")
    assert schema_differences(engine) == []


def test_the_admin_flag_migration_can_be_undone_and_redone(engine):
    from alembic import command

    migrate(engine)
    command.downgrade(_alembic_config(engine), "0008")
    assert "is_admin" not in {c["name"] for c in inspect(engine).get_columns("users")}

    migrate(engine)
    assert "is_admin" in {c["name"] for c in inspect(engine).get_columns("users")}
    assert schema_differences(engine) == []


def test_scan_progress_is_additive_and_defaults_to_empty(engine):
    """0010 adds one column. A scan that finished before this column existed must come back with
    an empty progress object - not NULL, and not a fabricated set of stages it never reported."""
    from alembic import command

    command.upgrade(_alembic_config(engine), "0009")
    with engine.begin() as connection:
        connection.execute(
            text("INSERT INTO tenants (id, name, created_at) VALUES ('t1', 'default', '2026-10-02')")
        )
        connection.execute(
            text(
                "INSERT INTO scans (id, tenant_id, target_domain, profile, status, warnings, "
                "started_at) VALUES ('s1', 't1', 'example.com', 'safe', 'completed', '[]', "
                "'2026-10-02')"
            )
        )

    migrate(engine)

    with engine.connect() as connection:
        progress, status = connection.execute(
            text("SELECT progress, status FROM scans WHERE id = 's1'")
        ).one()
    assert status == "completed"  # the old row is otherwise untouched
    # SQLite hands back the raw server_default text; PostgreSQL decodes the JSON for us.
    assert (json.loads(progress) if isinstance(progress, str) else progress) == {}
    assert schema_differences(engine) == []


def test_the_scan_progress_migration_can_be_undone_and_redone(engine):
    from alembic import command

    migrate(engine)
    command.downgrade(_alembic_config(engine), "0009")
    assert "progress" not in {c["name"] for c in inspect(engine).get_columns("scans")}

    migrate(engine)
    assert "progress" in {c["name"] for c in inspect(engine).get_columns("scans")}
    assert schema_differences(engine) == []
