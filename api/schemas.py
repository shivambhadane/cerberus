from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, Field


def _as_utc(value: datetime) -> datetime:
    """Every timestamp is UTC. SQLite stores datetimes without their zone, so they come back naive;
    sent as-is (`2026-09-20T06:24:23`) a browser reads them as *its own* local time, which put every
    "started N hours ago" out by the viewer's UTC offset. Marking them UTC makes the JSON carry the
    zone (`...Z`), so any client converts correctly."""
    return value if value.tzinfo else value.replace(tzinfo=UTC)


UtcDatetime = Annotated[datetime, AfterValidator(_as_utc)]

# --- accounts --------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=1024)  # policy is enforced in core.security
    name: str = Field(default="", max_length=255)


class LoginRequest(BaseModel):
    email: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=1024)


class UserOut(BaseModel):
    id: str
    email: str
    name: str
    email_verified: bool
    created_at: UtcDatetime
    last_login_at: UtcDatetime | None = None
    picture_url: str | None = None
    auth_provider: str | None = None
    # Read-only cross-tenant visibility (api/admin.py); never settable through this or any API.
    is_admin: bool = False


class AuthResponse(BaseModel):
    user: UserOut
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


# --- domains ---------------------------------------------------------------------------

class DomainCreate(BaseModel):
    domain: str = Field(min_length=1, max_length=300)


class VerificationInstructions(BaseModel):
    """What the owner must publish to prove control. `record_value` contains a secret token, so
    this is only ever returned to the domain's owner."""

    method: str
    record_type: str = "TXT"
    record_name: str
    record_value: str


class DomainOut(BaseModel):
    id: str
    domain: str
    verification_status: str
    verification_method: str
    verified_at: UtcDatetime | None = None
    created_at: UtcDatetime
    # DNS instructions: only for DNS-verified targets (None when a platform account proved it).
    verification: VerificationInstructions | None = None
    # Set when a connected platform account (vercel/netlify/cloudflare) proved it.
    provider: str | None = None
    provider_project_id: str | None = None


class DomainList(BaseModel):
    total: int
    domains: list[DomainOut]


class VerifyResult(BaseModel):
    verified: bool
    reason: str  # verified | record_not_found | token_mismatch | lookup_failed
    detail: str
    domain: DomainOut


class TestbedTargetOut(BaseModel):
    id: str
    name: str
    category: str
    domain: str
    url: str | None = None
    ports: list[int] = Field(default_factory=list)
    docker_command: str | None = None
    docker_teardown: str | None = None
    description: str
    vulnerabilities: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    provider_disclaimer: str | None = None
    already_added: bool = False
    domain_id: str | None = None


class TestbedList(BaseModel):
    total: int
    testbeds: list[TestbedTargetOut]


# --- scans -----------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """Scan a domain the caller has verified. There is no `authorized` flag: asserting
    authorisation is not evidence of it, so the API takes the proof (a verified domain owned by
    the caller) instead of the claim."""

    domain_id: str = Field(min_length=1, max_length=36)
    profile: str | None = None
    accept_profile: bool = False


class ScanCreated(BaseModel):
    scan_id: str
    status: str
    profile: str


class ScanProgress(BaseModel):
    stages: list[str]
    completed: list[str]
    current: str | None = None
    counts: dict[str, int] = {}


class ScanStatus(BaseModel):
    scan_id: str
    target_domain: str
    profile: str
    status: str
    started_at: UtcDatetime
    completed_at: UtcDatetime | None = None
    error: str | None = None
    warnings: list[str] = []
    # Real per-stage progress (core.pipeline.SCAN_STAGES); null for a scan that predates this
    # column, never a fabricated 0% to fill the gap.
    progress: ScanProgress | None = None


class ScanSummary(ScanStatus):
    observation_count: int = 0


class ScanList(BaseModel):
    total: int
    scans: list[ScanSummary]


# --- admin: read-only cross-tenant visibility (api/admin.py) ------------------------------------

class AdminOverview(BaseModel):
    user_count: int
    domain_counts: dict[str, int]      # verification_status -> count, across every account
    scan_counts: dict[str, int]        # status -> count
    finding_counts: dict[str, int]     # risk band -> count (open findings only)


class AdminUserOut(BaseModel):
    id: str
    email: str
    name: str
    is_admin: bool
    created_at: UtcDatetime
    last_login_at: UtcDatetime | None = None
    domain_count: int
    scan_count: int


class AdminUserList(BaseModel):
    total: int
    users: list[AdminUserOut]


class AdminDomainOut(BaseModel):
    id: str
    domain: str
    owner_email: str
    verification_status: str
    verification_method: str
    created_at: UtcDatetime


class AdminDomainList(BaseModel):
    total: int
    domains: list[AdminDomainOut]


class AdminScanOut(BaseModel):
    scan_id: str
    owner_email: str | None = None  # null for scans run before accounts existed
    target_domain: str
    profile: str
    status: str
    started_at: UtcDatetime
    completed_at: UtcDatetime | None = None
    finding_count: int


class AdminScanList(BaseModel):
    total: int
    scans: list[AdminScanOut]


CRITICALITY_LEVELS = ("low", "medium", "high", "critical")


class CriticalityUpdate(BaseModel):
    level: str
    reason: str | None = Field(default=None, max_length=500)


class AssetOut(BaseModel):
    id: str
    hostname: str
    ip_address: str | None
    port: int
    protocol: str
    technology: str | None
    discovered_by_tool: str | None = None
    criticality: str | None = None
    criticality_reason: str | None = None
    criticality_source: str | None = None
    finding_count: int = 0
    first_seen_at: UtcDatetime
    last_seen_at: UtcDatetime


class AssetList(BaseModel):
    total: int
    assets: list[AssetOut]


class FindingOut(BaseModel):
    id: str
    asset_id: str
    asset: str
    cve_id: str
    cvss_score: float | None
    kev_listed: bool
    epss_score: float | None
    asset_criticality: str | None
    risk_score: float | None
    status: str
    reasoning: str | None
    detection_method: str
    detected_by_tool: str | None
    detected_at: UtcDatetime


class FindingList(BaseModel):
    total: int
    findings: list[FindingOut]


class AssetRef(BaseModel):
    id: str
    hostname: str
    port: int


class FindingDetectionOut(BaseModel):
    host: str
    port: int
    technology: str | None
    detection_method: str
    detected_by_tool: str | None


class FindingSeverityOut(BaseModel):
    risk_score: float | None
    cvss_score: float | None
    epss_score: float | None
    kev_listed: bool
    asset_criticality: str | None


class FindingExplanationOut(BaseModel):
    """A developer-friendly reading of the same finding, in the order a developer asks the
    questions. Deterministic, built from stored data only - never a model's guess. See
    scoring/explain.py."""

    what_we_found: str
    what_is_the_problem: str
    why_it_matters: str
    how_it_was_detected: FindingDetectionOut
    how_serious: FindingSeverityOut
    why_this_priority: str | None
    what_to_do: str
    how_to_verify: str


class FindingDetail(BaseModel):
    id: str
    asset: AssetRef
    cve_id: str
    cvss_score: float | None
    kev_listed: bool
    kev_date_added: date | None
    epss_score: float | None
    has_public_exploit: bool
    asset_criticality: str | None
    asset_criticality_source: str | None = None
    asset_criticality_reason: str | None = None
    risk_score: float | None
    status: str
    reasoning: str | None
    description: str | None
    detection_method: str
    detected_by_tool: str | None
    evidence: str | None
    detected_at: UtcDatetime
    explanation: FindingExplanationOut


class FindingUpdate(BaseModel):
    status: str


class ObservationOut(BaseModel):
    id: str
    scan_id: str
    kind: str
    target: str
    source_tool: str
    source_version: str | None
    data: dict
    observed_at: UtcDatetime


class ObservationList(BaseModel):
    total: int
    observations: list[ObservationOut]


class SourceStatus(BaseModel):
    name: str
    last_refreshed_at: UtcDatetime
    record_count: int


class EnrichmentStatus(BaseModel):
    sources: list[SourceStatus]


class FindingsOverview(BaseModel):
    active: int
    actively_exploited: int
    confirmed: int
    by_risk_band: dict[str, int]
    by_detection: dict[str, int]


class AssetsOverview(BaseModel):
    total: int
    by_criticality: dict[str, int]


class Overview(BaseModel):
    findings: FindingsOverview
    assets: AssetsOverview
    scans_total: int
    last_scan: ScanSummary | None = None


# --- deployment providers --------------------------------------------------------------------------

class ConnectionOut(BaseModel):
    """A connection to a platform account. Deliberately carries no token, secret or scope detail a
    client could misuse: it says what is connected and when."""

    id: str
    provider: str
    label: str
    connected_at: UtcDatetime
    scopes: list[str] = []
    method: str = "oauth"  # "oauth", or "token" when the person pasted an access token


class ProviderInfo(BaseModel):
    provider: str
    label: str
    configured: bool  # false until the operator has registered an OAuth app and set its credentials
    token_paste: bool = False  # true when an access token can be used instead (needs only the encryption key)
    connections: list[ConnectionOut] = []


class ProviderList(BaseModel):
    providers: list[ProviderInfo]


class TokenConnect(BaseModel):
    """No length limits here on purpose: a validation error would echo the value back. They are checked
    in `core.provider_service.clean_token`, whose messages never repeat it."""

    token: str
    team_id: str | None = None


class ConnectStarted(BaseModel):
    authorization_url: str


class ProjectOut(BaseModel):
    id: str
    name: str
    hostnames: list[str]  # platform hostnames that can be verified (`*.vercel.app` and the like)
    verified_hostnames: list[str] = []  # the ones already added and verified for this user


class ProjectList(BaseModel):
    connection: ConnectionOut
    projects: list[ProjectOut]


class ProviderTargetRequest(BaseModel):
    connection_id: str = Field(min_length=1, max_length=36)
    project_id: str = Field(min_length=1, max_length=256)
    hostname: str = Field(min_length=1, max_length=300)


class ProviderVerifyRequest(BaseModel):
    connection_id: str = Field(min_length=1, max_length=36)
    project_id: str = Field(min_length=1, max_length=256)


class Disconnected(BaseModel):
    disconnected: bool = True
    targets_reset: int
