from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, Depends, FastAPI, Header, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.schemas import (
    AssetList,
    AssetOut,
    AssetRef,
    EnrichmentStatus,
    FindingDetail,
    FindingList,
    FindingOut,
    FindingUpdate,
    ScanCreated,
    ScanRequest,
    ScanStatus,
    SourceStatus,
)
from core.config import load_config
from core.db import get_default_tenant, init_db, session_scope
from core.models import (
    FINDING_STATUSES,
    Asset,
    AssetCriticality,
    CveEnrichment,
    Finding,
    Scan,
    SourceRefresh,
)
from core.pipeline import create_scan_record, run_pipeline

log = logging.getLogger(__name__)

ACTIVE_STATUSES = ("pending", "discovering", "enriching", "scoring")

@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Cerberus API",
    description="Continuous attack surface and exploitability intelligence.",
    version="1.0.0",
    lifespan=lifespan,
)


class ApiError(Exception):
    def __init__(self, status_code: int, code: str, message: str):
        self.status_code = status_code
        self.code = code
        self.message = message


# The dashboard is served from a different origin in development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=load_config().cors_origins,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.exception_handler(ApiError)
async def _api_error_handler(_: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message}},
    )


def require_auth(authorization: str = Header(default="")) -> None:
    expected = load_config().api_secret_key
    if authorization != f"Bearer {expected}":
        raise ApiError(401, "unauthorized", "Missing or invalid bearer token")


def get_session():
    with session_scope() as session:
        yield session


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.post("/api/v1/scans", response_model=ScanCreated, status_code=202, dependencies=[Depends(require_auth)])
def create_scan(
    payload: ScanRequest,
    background: BackgroundTasks,
    session: Session = Depends(get_session),
) -> ScanCreated:
    if not payload.authorized:
        raise ApiError(400, "invalid_request", "authorized must be true to start a scan")

    tenant = get_default_tenant(session)
    active = session.scalar(
        select(Scan).where(Scan.tenant_id == tenant.id, Scan.status.in_(ACTIVE_STATUSES))
    )
    if active is not None:
        raise ApiError(409, "scan_in_progress", f"scan {active.id} is already running for this tenant")

    scan_id = create_scan_record(
        session, payload.target_domain, payload.authorized, tenant.id
    )
    # The background task opens its own session, so the row must be durable before
    # it starts - dependency teardown commits too late for it to be visible.
    session.commit()
    background.add_task(run_pipeline, scan_id, load_config())
    return ScanCreated(scan_id=scan_id, status="pending")


@app.get("/api/v1/scans/{scan_id}", response_model=ScanStatus, dependencies=[Depends(require_auth)])
def get_scan(scan_id: str, session: Session = Depends(get_session)) -> ScanStatus:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise ApiError(404, "not_found", f"no scan with id {scan_id}")
    return ScanStatus(
        scan_id=scan.id,
        target_domain=scan.target_domain,
        status=scan.status,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error=scan.error,
    )


@app.get("/api/v1/assets", response_model=AssetList, dependencies=[Depends(require_auth)])
def list_assets(
    session: Session = Depends(get_session),
    tenant_id: str | None = None,
    scan_id: str | None = None,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> AssetList:
    stmt = select(Asset)
    if tenant_id:
        stmt = stmt.where(Asset.tenant_id == tenant_id)
    if scan_id:
        stmt = stmt.where(Asset.discovered_by_scan_id == scan_id)

    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = session.scalars(stmt.order_by(Asset.hostname, Asset.port).limit(limit).offset(offset)).all()
    return AssetList(total=total, assets=[AssetOut.model_validate(a, from_attributes=True) for a in rows])


def _findings_query(tenant_id: str | None, min_risk_score: float | None, kev_only: bool):
    stmt = (
        select(Finding, CveEnrichment, Asset, AssetCriticality)
        .join(CveEnrichment, Finding.cve_id == CveEnrichment.cve_id)
        .join(Asset, Finding.asset_id == Asset.id)
        .outerjoin(AssetCriticality, AssetCriticality.asset_id == Asset.id)
    )
    if tenant_id:
        stmt = stmt.where(Asset.tenant_id == tenant_id)
    if min_risk_score is not None:
        stmt = stmt.where(Finding.risk_score >= min_risk_score)
    if kev_only:
        stmt = stmt.where(CveEnrichment.kev_listed.is_(True))
    return stmt


@app.get("/api/v1/findings", response_model=FindingList, dependencies=[Depends(require_auth)])
def list_findings(
    session: Session = Depends(get_session),
    tenant_id: str | None = None,
    sort: str = Query("risk_score", pattern="^(risk_score|detected_at)$"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    min_risk_score: float | None = None,
    kev_only: bool = False,
) -> FindingList:
    stmt = _findings_query(tenant_id, min_risk_score, kev_only)
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0

    column = Finding.risk_score if sort == "risk_score" else Finding.detected_at
    ordering = column.desc() if order == "desc" else column.asc()
    rows = session.execute(
        stmt.order_by(ordering, CveEnrichment.cvss_score.desc()).limit(limit).offset(offset)
    ).all()

    findings = [
        FindingOut(
            id=f.id,
            asset=f"{a.hostname}:{a.port}",
            cve_id=c.cve_id,
            cvss_score=c.cvss_score,
            kev_listed=c.kev_listed,
            epss_score=c.epss_score,
            asset_criticality=crit.level if crit else None,
            risk_score=f.risk_score,
            status=f.status,
            reasoning=f.reasoning,
            detected_at=f.detected_at,
        )
        for f, c, a, crit in rows
    ]
    return FindingList(total=total, findings=findings)


def _load_finding(session: Session, finding_id: str):
    row = session.execute(
        select(Finding, CveEnrichment, Asset, AssetCriticality)
        .join(CveEnrichment, Finding.cve_id == CveEnrichment.cve_id)
        .join(Asset, Finding.asset_id == Asset.id)
        .outerjoin(AssetCriticality, AssetCriticality.asset_id == Asset.id)
        .where(Finding.id == finding_id)
    ).first()
    if row is None:
        raise ApiError(404, "not_found", f"no finding with id {finding_id}")
    return row


def _detail(row) -> FindingDetail:
    f, c, a, crit = row
    return FindingDetail(
        id=f.id,
        asset=AssetRef(id=a.id, hostname=a.hostname, port=a.port),
        cve_id=c.cve_id,
        cvss_score=c.cvss_score,
        kev_listed=c.kev_listed,
        kev_date_added=c.kev_date_added,
        epss_score=c.epss_score,
        has_public_exploit=c.has_public_exploit,
        asset_criticality=crit.level if crit else None,
        risk_score=f.risk_score,
        status=f.status,
        reasoning=f.reasoning,
        description=c.description,
        detected_at=f.detected_at,
    )


@app.get("/api/v1/findings/{finding_id}", response_model=FindingDetail, dependencies=[Depends(require_auth)])
def get_finding(finding_id: str, session: Session = Depends(get_session)) -> FindingDetail:
    return _detail(_load_finding(session, finding_id))


@app.patch(
    "/api/v1/findings/{finding_id}",
    response_model=FindingDetail,
    dependencies=[Depends(require_auth)],
)
def update_finding(
    finding_id: str,
    payload: FindingUpdate,
    session: Session = Depends(get_session),
) -> FindingDetail:
    if payload.status not in FINDING_STATUSES:
        raise ApiError(400, "invalid_request", f"status must be one of {', '.join(FINDING_STATUSES)}")
    row = _load_finding(session, finding_id)
    row[0].status = payload.status
    session.flush()
    return _detail(row)


@app.get("/api/v1/enrichment/status", response_model=EnrichmentStatus, dependencies=[Depends(require_auth)])
def enrichment_status(session: Session = Depends(get_session)) -> EnrichmentStatus:
    rows = session.scalars(select(SourceRefresh).order_by(SourceRefresh.name)).all()
    return EnrichmentStatus(
        sources=[SourceStatus.model_validate(r, from_attributes=True) for r in rows]
    )
