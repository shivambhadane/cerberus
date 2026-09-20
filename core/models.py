from __future__ import annotations

import secrets
import uuid
from datetime import UTC, date, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    false,
    text,
    true,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

SCAN_STATUSES = ("pending", "discovering", "enriching", "scoring", "completed", "failed")
DETECTION_METHODS = ("version_inference", "active_detection")
FINDING_STATUSES = ("open", "acknowledged", "resolved", "false_positive")
CRITICALITY_LEVELS = ("low", "medium", "high", "critical")
# How a person proves they control a domain, and where that proof stands. Only the values are
# defined here; the checks that set them are a separate concern (see docs/DATABASE_SCHEMA.md).
# `dns_txt` is the original method. The others prove control of a deployment on a managed platform
# by way of the owner's connected provider account (see providers/ and docs/API.md).
VERIFICATION_METHODS = ("dns_txt", "http_file", "vercel", "netlify", "cloudflare")
PROVIDER_NAMES = ("vercel", "netlify", "cloudflare")
VERIFICATION_STATUSES = ("pending", "verified", "failed")


def new_id() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_verification_token() -> str:
    """An unguessable value the owner publishes (DNS TXT record or file) to prove control."""
    return secrets.token_urlsafe(24)


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class User(Base):
    """A person who signs in. Authentication itself lives at the API boundary; the scanning
    pipeline never sees a password, only the ownership this row establishes."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    # Stored lower-case (core.ownership.normalize_email), so uniqueness is case-insensitive in
    # practice on every database, not just the ones whose collation happens to say so.
    email: Mapped[str] = mapped_column(String(320), unique=True)
    # A hash from a slow password KDF, never the password. Empty until a credential is set.
    password_hash: Mapped[str] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(255), default="", server_default="")
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # From the identity provider's verified token (Google, GitHub), never from the client: the
    # profile picture URL and how the person signed in ("google.com", "github.com", "password").
    picture_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    auth_provider: Mapped[str | None] = mapped_column(String(32), nullable=True)

    domains: Mapped[list[Domain]] = relationship(back_populates="user", cascade="all, delete-orphan")


class Domain(Base):
    """A domain a user says they own. It can be scanned only once verified."""

    __tablename__ = "domains"
    __table_args__ = (
        UniqueConstraint("user_id", "domain", name="uq_domain_per_user"),
        Index("ix_domains_user", "user_id"),
        # Anyone can *claim* any domain, so claims are not unique; *proof* is. At most one user
        # can hold a verified claim on a domain, whichever proves control first.
        Index(
            "uq_domain_one_verified_owner",
            "domain",
            unique=True,
            sqlite_where=text("verification_status = 'verified' AND verification_method NOT IN ('testbed', 'lab')"),
            postgresql_where=text("verification_status = 'verified' AND verification_method NOT IN ('testbed', 'lab')"),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"))
    # Stored normalised (core.ownership.normalize_domain): lower-case, no scheme, no trailing dot.
    domain: Mapped[str] = mapped_column(String(255))
    verification_token: Mapped[str] = mapped_column(String(64), default=new_verification_token)
    verification_method: Mapped[str] = mapped_column(String(16), default="dns_txt", server_default="dns_txt")
    verification_status: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending")
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Set only when verification_method is a platform (vercel/netlify/cloudflare): which connection
    # proved it, the project it belongs to, and the account/team that project sits under.
    provider: Mapped[str | None] = mapped_column(String(16), nullable=True)
    provider_connection_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("connected_providers.id"), nullable=True
    )
    provider_project_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    provider_resource_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    user: Mapped[User] = relationship(back_populates="domains")


class AuthSession(Base):
    """One refresh token, server side. A sign-in starts a *family*; each refresh replaces the token
    with a new one in the same family and revokes the old. If a revoked token is ever presented
    again, someone kept a copy, so the whole family is revoked (see api/auth.py)."""

    __tablename__ = "auth_sessions"
    __table_args__ = (
        Index("ix_auth_sessions_user", "user_id"),
        Index("ix_auth_sessions_family", "family_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"))
    family_id: Mapped[str] = mapped_column(String(36))
    # SHA-256 of the token, never the token: a copy of this table cannot mint a session.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Two different facts, kept apart on purpose. `rotated_at`: this token was used and replaced by
    # a newer one (normal; a short leeway forgives a second tab using it at the same instant).
    # `revoked_at`: the login was ended (sign-out, or theft detected); final, no leeway.
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ConnectedProvider(Base):
    """A user's connection to a deployment platform account (Vercel, Netlify, Cloudflare).

    Cerberus uses it for one thing: asking the platform, with the user's own authorisation, which
    projects that account controls. The tokens are credentials for the user's cloud account, so they
    are stored encrypted (core/crypto.py) and are never returned by the API or sent to the browser.
    """

    __tablename__ = "connected_providers"
    __table_args__ = (
        UniqueConstraint("user_id", "provider", "provider_account_id", name="uq_connection_identity"),
        Index("ix_connected_providers_user", "user_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"))
    provider: Mapped[str] = mapped_column(String(16))
    # The account's id AT THE PROVIDER, read from the provider's API with the fresh token. It is never
    # taken from the browser.
    provider_account_id: Mapped[str] = mapped_column(String(128))
    account_label: Mapped[str] = mapped_column(String(255), default="", server_default="")
    access_token_encrypted: Mapped[str] = mapped_column(Text)
    refresh_token_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scopes: Mapped[str] = mapped_column(Text, default="", server_default="")
    # Non-secret provider details needed to call its API later (a Vercel team id, for example).
    extra: Mapped[dict] = mapped_column(JSON, default=dict, server_default=text("'{}'"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class OAuthState(Base):
    """One in-flight OAuth authorisation: single-use, short-lived, bound to a user and a browser.

    Only hashes are stored, so reading this table reveals nothing that can complete a flow.
    """

    __tablename__ = "oauth_states"
    __table_args__ = (Index("ix_oauth_states_user", "user_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"))
    provider: Mapped[str] = mapped_column(String(16))
    state_hash: Mapped[str] = mapped_column(String(64), unique=True)
    # Hash of a random value also set as a cookie in the browser that started the flow. A callback
    # from any other browser (a link forwarded to a victim, say) does not carry it and is refused.
    browser_hash: Mapped[str] = mapped_column(String(64))
    code_verifier_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_user", "user_id"),
        Index("ix_scans_domain", "domain_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"))
    # Ownership. Nullable while the tenant model is retired: rows written before users existed
    # have neither, and nothing may be invented for them.
    user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    domain_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("domains.id"), nullable=True)
    target_domain: Mapped[str] = mapped_column(String(255))
    # Which scan profile governed this run - the record of what was permitted.
    profile: Mapped[str] = mapped_column(String(32), default="safe")
    status: Mapped[str] = mapped_column(String(32), default="pending")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Non-fatal problems: a scanner that failed to run, a stale enrichment cache. A scan can
    # complete and still have been degraded; without this the only trace was CLI output.
    warnings: Mapped[list] = mapped_column(JSON, default=list, server_default=text("'[]'"))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        # An asset is one host:port *per owner*. Two users may each hold `api.example.com:443`
        # (for instance a verified subdomain inside someone else's verified domain) and must not
        # see or overwrite each other's row. Rows written before users existed have no owner, so
        # they keep the old per-tenant identity.
        Index(
            "uq_asset_identity_owned", "user_id", "hostname", "port", "protocol", unique=True,
            sqlite_where=text("user_id IS NOT NULL"), postgresql_where=text("user_id IS NOT NULL"),
        ),
        Index(
            "uq_asset_identity_legacy", "tenant_id", "hostname", "port", "protocol", unique=True,
            sqlite_where=text("user_id IS NULL"), postgresql_where=text("user_id IS NULL"),
        ),
        Index("ix_assets_tenant", "tenant_id"),
        Index("ix_assets_user", "user_id"),
        Index("ix_assets_domain", "domain_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"))
    user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    domain_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("domains.id"), nullable=True)
    discovered_by_scan_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scans.id"), nullable=True
    )
    hostname: Mapped[str] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    # Tool-supplied text is unbounded. SQLite ignores VARCHAR lengths, so a limit here passes
    # every local test and then fails on PostgreSQL the first time a long value arrives.
    technology: Mapped[str | None] = mapped_column(Text, nullable=True)
    discovered_by_tool: Mapped[str | None] = mapped_column(String(64), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    criticality: Mapped[AssetCriticality | None] = relationship(
        back_populates="asset", uselist=False, cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(back_populates="asset", cascade="all, delete-orphan")


class AssetCriticality(Base):
    __tablename__ = "asset_criticality"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), unique=True)
    level: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # "heuristic" (inferred from the hostname/port) or "manual" (set by a person). The
    # distinction matters to whoever is reading a score: one is a guess, the other a decision.
    source: Mapped[str] = mapped_column(String(16), default="heuristic", server_default="heuristic")
    tagged_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    asset: Mapped[Asset] = relationship(back_populates="criticality")


class CveEnrichment(Base):
    """Global, tenant-independent vulnerability intelligence cache."""

    __tablename__ = "cve_enrichment"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev_listed: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_date_added: Mapped[date | None] = mapped_column(Date, nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    has_public_exploit: Mapped[bool] = mapped_column(Boolean, default=False)
    # CISA KEV `product` can list dozens of variants (one real entry is 179 characters).
    vendor: Mapped[str | None] = mapped_column(Text, nullable=True)
    product: Mapped[str | None] = mapped_column(Text, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_refreshed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("asset_id", "cve_id", name="uq_finding_identity"),
        Index("ix_findings_risk", "risk_score"),
        Index("ix_findings_asset", "asset_id"),
        Index("ix_findings_cve", "cve_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"))
    cve_id: Mapped[str] = mapped_column(String(32), ForeignKey("cve_enrichment.cve_id"))
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="open")
    # How strongly this finding is evidenced, and by what. version_inference means the
    # service advertised an affected version; active_detection means a probe confirmed it.
    detection_method: Mapped[str] = mapped_column(String(32), default="version_inference")
    detected_by_tool: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    asset: Mapped[Asset] = relationship(back_populates="findings")
    cve: Mapped[CveEnrichment] = relationship()


class ObservationRecord(Base):
    """Raw, tool-attributed facts from a scan.

    Kept separate from assets and findings so the audit trail survives normalization:
    an asset row says what Cerberus concluded, these rows say what a tool actually saw.
    """

    __tablename__ = "observations"
    __table_args__ = (
        Index("ix_observations_scan", "scan_id"),
        Index("ix_observations_kind", "kind"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"))
    kind: Mapped[str] = mapped_column(String(32))
    target: Mapped[str] = mapped_column(String(320))
    source_tool: Mapped[str] = mapped_column(String(64))
    source_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SourceRefresh(Base):
    """Tracks when each global enrichment source was last pulled."""

    __tablename__ = "source_refresh"

    name: Mapped[str] = mapped_column(String(32), primary_key=True)
    last_refreshed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    record_count: Mapped[int] = mapped_column(Integer, default=0)
