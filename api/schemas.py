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
    verification: VerificationInstructions


class DomainList(BaseModel):
    total: int
    domains: list[DomainOut]


class VerifyResult(BaseModel):
    verified: bool
    reason: str  # verified | record_not_found | token_mismatch | lookup_failed
    detail: str
    domain: DomainOut


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


class ScanStatus(BaseModel):
    scan_id: str
    target_domain: str
    profile: str
    status: str
    started_at: UtcDatetime
    completed_at: UtcDatetime | None = None
    error: str | None = None
    warnings: list[str] = []


class ScanSummary(ScanStatus):
    observation_count: int = 0


class ScanList(BaseModel):
    total: int
    scans: list[ScanSummary]


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
