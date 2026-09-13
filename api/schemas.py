from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target_domain: str = Field(min_length=1, max_length=255)
    authorized: bool = False
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
    started_at: datetime
    completed_at: datetime | None = None
    error: str | None = None


class AssetOut(BaseModel):
    id: str
    hostname: str
    ip_address: str | None
    port: int
    protocol: str
    technology: str | None
    first_seen_at: datetime
    last_seen_at: datetime


class AssetList(BaseModel):
    total: int
    assets: list[AssetOut]


class FindingOut(BaseModel):
    id: str
    asset: str
    cve_id: str
    cvss_score: float | None
    kev_listed: bool
    epss_score: float | None
    asset_criticality: str | None
    risk_score: float | None
    status: str
    reasoning: str | None
    detected_at: datetime


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
    risk_score: float | None
    status: str
    reasoning: str | None
    description: str | None
    detected_at: datetime


class FindingUpdate(BaseModel):
    status: str


class SourceStatus(BaseModel):
    name: str
    last_refreshed_at: datetime
    record_count: int


class EnrichmentStatus(BaseModel):
    sources: list[SourceStatus]
