from __future__ import annotations

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
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

SCAN_STATUSES = ("pending", "discovering", "enriching", "scoring", "completed", "failed")
DETECTION_METHODS = ("version_inference", "active_detection")
FINDING_STATUSES = ("open", "acknowledged", "resolved", "false_positive")
CRITICALITY_LEVELS = ("low", "medium", "high", "critical")


def new_id() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"))
    target_domain: Mapped[str] = mapped_column(String(255))
    # Which scan profile governed this run - the record of what was permitted.
    profile: Mapped[str] = mapped_column(String(32), default="safe")
    status: Mapped[str] = mapped_column(String(32), default="pending")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("tenant_id", "hostname", "port", "protocol", name="uq_asset_identity"),
        Index("ix_assets_tenant", "tenant_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"))
    discovered_by_scan_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scans.id"), nullable=True
    )
    hostname: Mapped[str] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    technology: Mapped[str | None] = mapped_column(String(255), nullable=True)
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
    vendor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    product: Mapped[str | None] = mapped_column(String(128), nullable=True)
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
    source_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SourceRefresh(Base):
    """Tracks when each global enrichment source was last pulled."""

    __tablename__ = "source_refresh"

    name: Mapped[str] = mapped_column(String(32), primary_key=True)
    last_refreshed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    record_count: Mapped[int] = mapped_column(Integer, default=0)
