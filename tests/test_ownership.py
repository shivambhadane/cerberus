"""The ownership layer: the rule, and the schema that backs it."""

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core.db import migrate
from core.models import Asset, Domain, Scan, Tenant, User
from core.ownership import OwnershipError, check_scan_allowed, normalize_domain, normalize_email


@pytest.fixture
def session(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'cerberus.db'}")
    migrate(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def make_user(session, email="a@example.com", **kw) -> User:
    user = User(email=email, password_hash="x", **kw)
    session.add(user)
    session.flush()
    return user


def make_domain(session, user, name="example.com", status="verified") -> Domain:
    domain = Domain(user_id=user.id, domain=name, verification_status=status)
    session.add(domain)
    session.flush()
    return domain


# --- normalisation ---------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("Example.COM", "example.com"),
    ("  example.com.  ", "example.com"),
    ("api.example.co.uk", "api.example.co.uk"),
    ("xn--bcher-kva.example", "xn--bcher-kva.example"),
])
def test_domains_are_normalised(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "   ", "localhost", "https://example.com", "example.com/path", "example.com:8080",
    "*.example.com", "127.0.0.1", "10.0.0.5", "::1", "exa mple.com", "-bad.example.com",
    "bad-.example.com", "a..b.com", "user@example.com", "x" * 64 + ".com",
])
def test_things_that_are_not_bare_domains_are_refused(raw):
    with pytest.raises(OwnershipError) as error:
        normalize_domain(raw)
    assert error.value.code == "invalid_domain"


def test_emails_are_case_and_whitespace_insensitive():
    assert normalize_email("  Shivam@Example.COM ") == "shivam@example.com"
    for bad in ("", "no-at.com", "a@b", "a@@b.com", "a b@c.com", "@c.com"):
        with pytest.raises(OwnershipError):
            normalize_email(bad)


# --- the rule --------------------------------------------------------------------------

def test_the_owner_of_a_verified_domain_may_scan_it_and_its_subdomains(session):
    user = make_user(session)
    domain = make_domain(session, user)
    check_scan_allowed(user, domain)
    check_scan_allowed(user, domain, "example.com")
    check_scan_allowed(user, domain, "API.example.com")


def test_an_unverified_domain_may_not_be_scanned(session):
    user = make_user(session)
    for status in ("pending", "failed"):
        domain = make_domain(session, user, f"{status}.example.com", status)
        with pytest.raises(OwnershipError) as error:
            check_scan_allowed(user, domain)
        assert error.value.code == "not_verified"


def test_someone_elses_domain_is_reported_as_not_theirs_even_when_verified(session):
    owner, other = make_user(session), make_user(session, "b@example.com")
    domain = make_domain(session, owner)
    with pytest.raises(OwnershipError) as error:
        check_scan_allowed(other, domain)
    assert error.value.code == "not_owner"


def test_ownership_is_checked_before_verification_state_is_revealed(session):
    """A stranger asking about a pending domain learns nothing about its state."""
    owner, other = make_user(session), make_user(session, "b@example.com")
    domain = make_domain(session, owner, status="pending")
    with pytest.raises(OwnershipError) as error:
        check_scan_allowed(other, domain)
    assert error.value.code == "not_owner"


def test_a_disabled_account_may_not_scan(session):
    user = make_user(session, is_active=False)
    domain = make_domain(session, user)
    with pytest.raises(OwnershipError) as error:
        check_scan_allowed(user, domain)
    assert error.value.code == "user_inactive"


@pytest.mark.parametrize("target", ["evilexample.com", "example.com.evil.io", "other.com", "example.org"])
def test_a_target_outside_the_verified_domain_is_refused(session, target):
    """Suffix confusion: `evilexample.com` ends with `example.com` but is not a subdomain."""
    user = make_user(session)
    domain = make_domain(session, user)
    with pytest.raises(OwnershipError) as error:
        check_scan_allowed(user, domain, target)
    assert error.value.code == "out_of_scope"


# --- the schema ------------------------------------------------------------------------

def test_new_users_and_domains_get_safe_defaults(session):
    user = make_user(session)
    domain = Domain(user_id=user.id, domain="example.com")
    session.add(domain)
    session.flush()
    assert user.email_verified is False and user.is_active is True
    assert user.created_at and user.updated_at and user.last_login_at is None
    assert domain.verification_status == "pending" and domain.verification_method == "dns_txt"
    assert len(domain.verification_token) >= 24 and domain.verified_at is None


def test_verification_tokens_are_unique_and_unguessable(session):
    user = make_user(session)
    domains = [make_domain(session, user, f"d{i}.example.com", "pending") for i in range(20)]
    assert len({d.verification_token for d in domains}) == 20


def test_an_email_can_register_only_once(session):
    make_user(session, "dup@example.com")
    session.add(User(email="dup@example.com", password_hash="y"))
    with pytest.raises(IntegrityError):
        session.flush()


def test_a_user_cannot_claim_the_same_domain_twice(session):
    user = make_user(session)
    make_domain(session, user, status="pending")
    session.add(Domain(user_id=user.id, domain="example.com"))
    with pytest.raises(IntegrityError):
        session.flush()


def test_two_people_may_claim_a_domain_but_only_one_can_prove_it(session):
    """Anyone can type any domain; only the first to verify it owns it."""
    first, second = make_user(session), make_user(session, "b@example.com")
    make_domain(session, first, status="verified")
    claim = make_domain(session, second, status="pending")  # a claim is allowed
    claim.verification_status = "verified"
    with pytest.raises(IntegrityError):
        session.flush()


def test_a_domain_can_be_reverified_by_another_user_after_the_first_loses_it(session):
    first, second = make_user(session), make_user(session, "b@example.com")
    lost = make_domain(session, first, status="verified")
    claim = make_domain(session, second, status="pending")
    lost.verification_status = "failed"
    session.flush()
    claim.verification_status = "verified"
    session.flush()  # no error


def test_scans_and_assets_carry_nullable_ownership_and_keep_the_tenant(session):
    tenant = Tenant(name="default")
    session.add(tenant)
    session.flush()
    legacy = Scan(tenant_id=tenant.id, target_domain="old.example.com")
    session.add(legacy)
    session.flush()
    assert legacy.user_id is None and legacy.domain_id is None  # legacy rows need no owner

    user = make_user(session)
    domain = make_domain(session, user)
    scan = Scan(tenant_id=tenant.id, user_id=user.id, domain_id=domain.id, target_domain="example.com")
    session.add(scan)
    session.flush()
    asset = Asset(tenant_id=tenant.id, user_id=user.id, domain_id=domain.id,
                  discovered_by_scan_id=scan.id, hostname="example.com", port=443)
    session.add(asset)
    session.flush()
    assert asset.user_id == user.id and asset.domain_id == domain.id and asset.tenant_id == tenant.id


def test_ownership_columns_are_indexed(session):
    inspector = inspect(session.get_bind())
    for table, columns in {"scans": {"user_id", "domain_id"}, "assets": {"user_id", "domain_id"},
                           "domains": {"user_id"}}.items():
        indexed = {c for index in inspector.get_indexes(table) for c in index["column_names"]}
        assert columns <= indexed, (table, columns - indexed)


def test_the_global_intelligence_tables_gained_no_ownership(session):
    """CVE/KEV/EPSS data is not customer-specific and must stay that way."""
    inspector = inspect(session.get_bind())
    for table in ("cve_enrichment", "source_refresh"):
        names = {c["name"] for c in inspector.get_columns(table)}
        assert not names & {"user_id", "domain_id", "tenant_id"}


def test_the_boolean_defaults_are_portable_not_literal_integers(session):
    """A `DEFAULT 0` on a boolean column is rejected by PostgreSQL; the migration must use the
    dialect-aware false()/true(). Checked at the source, since CI has no Postgres."""
    import pathlib
    source = pathlib.Path("migrations/versions/0004_users_and_domains.py").read_text()
    assert "sa.text('0')" not in source and "sa.text('1')" not in source
    assert "sa.false()" in source and "sa.true()" in source
    assert session.execute(text("select count(*) from users")).scalar() == 0


# --- claiming data that predates accounts -------------------------------------------------------

def test_claiming_assigns_only_unowned_rows(session):
    import importlib.util
    import pathlib

    spec = importlib.util.spec_from_file_location("claim_legacy", pathlib.Path("scripts/claim_legacy.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    tenant = Tenant(name="t")
    session.add(tenant)
    session.flush()
    me, other = make_user(session, "me@example.com"), make_user(session, "other@example.com")
    session.add_all([
        Scan(tenant_id=tenant.id, target_domain="legacy.example"),
        Scan(tenant_id=tenant.id, target_domain="theirs.example", user_id=other.id),
        Asset(tenant_id=tenant.id, hostname="legacy.example", port=80),
        Asset(tenant_id=tenant.id, hostname="theirs.example", port=80, user_id=other.id),
    ])
    session.flush()

    assert module.claim(session, "ME@example.com") == (1, 1)
    assert {s.target_domain: s.user_id for s in session.query(Scan)} == {
        "legacy.example": me.id, "theirs.example": other.id}
    assert {a.hostname: a.user_id for a in session.query(Asset)} == {
        "legacy.example": me.id, "theirs.example": other.id}
    assert module.claim(session, "me@example.com") == (0, 0)  # safe to repeat

    with pytest.raises(LookupError, match="Register"):
        module.claim(session, "nobody@example.com")
