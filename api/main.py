from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from datetime import timedelta

from fastapi import BackgroundTasks, Depends, FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import case, delete, func, or_, select
from sqlalchemy.orm import Session

from api import auth, domains
from api import providers as provider_routes
from api.deps import ApiError, current_user, get_session
from api.schemas import (
    CRITICALITY_LEVELS,
    AssetList,
    AssetOut,
    AssetRef,
    AssetsOverview,
    CriticalityUpdate,
    EnrichmentStatus,
    FindingDetail,
    FindingList,
    FindingOut,
    FindingsOverview,
    FindingUpdate,
    ObservationList,
    ObservationOut,
    Overview,
    ScanCreated,
    ScanList,
    ScanRequest,
    ScanStatus,
    ScanSummary,
    SourceStatus,
)
from core.config import load_config
from core.crypto import CryptoError, get_cipher
from core.db import get_default_tenant, init_db, session_scope
from core.models import (
    FINDING_STATUSES,
    Asset,
    AssetCriticality,
    AuthSession,
    CveEnrichment,
    Domain,
    Finding,
    ObservationRecord,
    Scan,
    SourceRefresh,
    User,
    utcnow,
)
from core.ownership import OwnershipError, check_scan_allowed
from core.pipeline import (
    ACTIVE_SCAN_STATUSES,
    create_scan_record,
    fail_interrupted_scans,
    run_pipeline,
)
from core.profiles import ProfileViolation, get_profile
from core.provider_service import ProviderServiceError, recheck_platform_target
from scoring.engine import RISK_BANDS, score_pending_findings

log = logging.getLogger(__name__)


# Values that ship in the repo (.env.example, the config default). A credential every reader of
# the repository already knows is not a credential.
INSECURE_SECRETS = frozenset({"", "change-me"})


MIN_SECRET_LENGTH = 32  # HS256 signing keys shorter than the hash output are brute-forceable offline


def check_api_secret() -> None:
    """Refuse to serve with an unset, placeholder or short secret.

    API_SECRET_KEY signs every sign-in token. With a value everyone who reads the repository knows,
    or one short enough to guess offline from a single token, anyone could mint a token for any
    user, so the API will not start with one. Local development against a throwaway key can opt out
    explicitly with CERBERUS_ALLOW_INSECURE_DEV=1.
    """
    secret = load_config().api_secret_key
    unusable = secret in INSECURE_SECRETS or len(secret) < MIN_SECRET_LENGTH
    if unusable and os.environ.get("CERBERUS_ALLOW_INSECURE_DEV") != "1":
        raise RuntimeError(
            "API_SECRET_KEY is unset, still the shipped placeholder, or shorter than "
            f"{MIN_SECRET_LENGTH} characters. Generate one (`openssl rand -hex 24`) and set it in "
            ".env. For throwaway local use only, set CERBERUS_ALLOW_INSECURE_DEV=1."
        )


@asynccontextmanager
async def lifespan(_: FastAPI):
    check_api_secret()
    if os.environ.get("CERBERUS_ALLOW_TEST_TOKENS") == "1" and os.environ.get("PYTEST_CURRENT_TEST") is None:
        log.error(
            "CERBERUS_ALLOW_TEST_TOKENS=1 is set: anyone can sign in as any email address. "
            "It exists only for the test suite. Unset it."
        )
    init_db()
    with session_scope() as session:
        fail_interrupted_scans(session)
        # Housekeeping: refresh tokens expired more than a day ago are of no further use.
        session.execute(delete(AuthSession).where(AuthSession.expires_at < utcnow() - timedelta(days=1)))
    yield


app = FastAPI(
    title="Cerberus API",
    description="Continuous attack surface and exploitability intelligence.",
    version="1.0.0",
    lifespan=lifespan,
)


# The dashboard is served from a different origin in development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=load_config().cors_origins,
    allow_credentials=True,  # the refresh cookie; origins are an explicit list, never "*"
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.exception_handler(ApiError)
async def _api_error_handler(_: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message}},
        headers=exc.headers,
    )


app.include_router(auth.router)
app.include_router(domains.router)
app.include_router(provider_routes.router)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


def _optional_cipher():
    try:
        return get_cipher()
    except CryptoError:
        return None


@app.post("/api/v1/scans", response_model=ScanCreated, status_code=202)
def create_scan(
    payload: ScanRequest,
    background: BackgroundTasks,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> ScanCreated:
    """Scan a domain the caller owns and has verified.

    There is no "I am authorised" flag to send: the proof is the verified domain itself
    (core/ownership.py). A domain that is not yours is reported as not found, and one that is
    yours but unverified is refused with what to do about it.
    """
    try:
        profile = get_profile(
            payload.profile or load_config().scanning.profile,
            opted_in=payload.accept_profile,
        )
    except ProfileViolation as exc:
        raise ApiError(400, "invalid_profile", str(exc)) from None

    domain = session.get(Domain, payload.domain_id)
    if domain is None:
        raise ApiError(404, "not_found", "No such domain.")
    try:
        check_scan_allowed(user, domain)
    except OwnershipError as exc:
        status, code = {
            "not_owner": (404, "not_found"),  # someone else's domain looks like no domain
            "not_verified": (403, "domain_not_verified"),
            "user_inactive": (403, "account_disabled"),
        }.get(exc.code, (403, exc.code))
        raise ApiError(status, code, str(exc)) from None

    # A target proved through Vercel/Netlify/Cloudflare is re-confirmed with the platform right now:
    # platform names are released when a project is deleted, and a verification must not outlive the
    # ownership it recorded. DNS-verified targets pass straight through.
    try:
        recheck_platform_target(session, domain, _optional_cipher())
    except ProviderServiceError as exc:
        raise provider_routes.to_api_error(exc) from None

    active = session.scalar(
        select(Scan).where(Scan.user_id == user.id, Scan.status.in_(ACTIVE_SCAN_STATUSES))
    )
    if active is not None:
        raise ApiError(409, "scan_in_progress", f"scan {active.id} is already running")

    tenant = get_default_tenant(session)
    scan_id = create_scan_record(
        session, domain.domain, True, tenant.id, profile.name, user_id=user.id, domain_id=domain.id
    )
    # The background task opens its own session, so the row must be durable before
    # it starts - dependency teardown commits too late for it to be visible.
    session.commit()
    background.add_task(run_pipeline, scan_id, load_config())
    return ScanCreated(scan_id=scan_id, status="pending", profile=profile.name)


@app.get("/api/v1/scans", response_model=ScanList)
def list_scans(
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> ScanList:
    """Scan history, newest first, with how much each scan recorded."""
    mine = Scan.user_id == user.id
    total = session.scalar(select(func.count()).select_from(Scan).where(mine)) or 0
    scans = session.scalars(
        select(Scan).where(mine).order_by(Scan.started_at.desc()).limit(limit).offset(offset)
    ).all()
    counts = dict(
        session.execute(
            select(ObservationRecord.scan_id, func.count())
            .where(ObservationRecord.scan_id.in_([s.id for s in scans]))
            .group_by(ObservationRecord.scan_id)
        ).all()
    ) if scans else {}
    return ScanList(
        total=total,
        scans=[
            ScanSummary(
                scan_id=s.id,
                target_domain=s.target_domain,
                profile=s.profile,
                status=s.status,
                started_at=s.started_at,
                completed_at=s.completed_at,
                error=s.error,
                warnings=list(s.warnings or []),
                observation_count=counts.get(s.id, 0),
            )
            for s in scans
        ],
    )


@app.get("/api/v1/scans/{scan_id}", response_model=ScanStatus)
def get_scan(
    scan_id: str, user: User = Depends(current_user), session: Session = Depends(get_session)
) -> ScanStatus:
    scan = session.get(Scan, scan_id)
    if scan is None or scan.user_id != user.id:
        raise ApiError(404, "not_found", f"no scan with id {scan_id}")
    return ScanStatus(
        scan_id=scan.id,
        target_domain=scan.target_domain,
        profile=scan.profile,
        status=scan.status,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error=scan.error,
        warnings=list(scan.warnings or []),
    )


@app.get("/api/v1/assets", response_model=AssetList)
def list_assets(
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
    scan_id: str | None = None,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> AssetList:
    stmt = select(Asset).where(Asset.user_id == user.id)
    if scan_id:
        stmt = stmt.where(Asset.discovered_by_scan_id == scan_id)

    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    assets = session.scalars(stmt.order_by(Asset.hostname, Asset.port).limit(limit).offset(offset)).all()
    return AssetList(total=total, assets=_asset_rows(session, assets))


def _asset_rows(session: Session, assets: list[Asset]) -> list[AssetOut]:
    ids = [a.id for a in assets]
    crit = {
        c.asset_id: c
        for c in session.scalars(select(AssetCriticality).where(AssetCriticality.asset_id.in_(ids)))
    } if ids else {}
    counts = dict(
        session.execute(
            select(Finding.asset_id, func.count()).where(Finding.asset_id.in_(ids)).group_by(Finding.asset_id)
        ).all()
    ) if ids else {}
    return [
        AssetOut(
            id=a.id,
            hostname=a.hostname,
            ip_address=a.ip_address,
            port=a.port,
            protocol=a.protocol,
            technology=a.technology,
            discovered_by_tool=a.discovered_by_tool,
            criticality=crit[a.id].level if a.id in crit else None,
            criticality_reason=crit[a.id].reason if a.id in crit else None,
            criticality_source=crit[a.id].source if a.id in crit else None,
            finding_count=counts.get(a.id, 0),
            first_seen_at=a.first_seen_at,
            last_seen_at=a.last_seen_at,
        )
        for a in assets
    ]


@app.patch(
    "/api/v1/assets/{asset_id}/criticality",
    response_model=AssetOut,
)
def set_criticality(
    asset_id: str,
    payload: CriticalityUpdate,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> AssetOut:
    """A person's judgement of how much an asset matters. It feeds the score (25% by default),
    and, unlike the hostname heuristic, is never overwritten by a re-scan."""
    if payload.level not in CRITICALITY_LEVELS:
        raise ApiError(400, "invalid_request", f"level must be one of {', '.join(CRITICALITY_LEVELS)}")
    asset = session.get(Asset, asset_id)
    if asset is None or asset.user_id != user.id:
        raise ApiError(404, "not_found", f"no asset with id {asset_id}")

    tag = session.scalar(select(AssetCriticality).where(AssetCriticality.asset_id == asset_id))
    if tag is None:
        tag = AssetCriticality(asset_id=asset_id, level=payload.level)
        session.add(tag)
    tag.level = payload.level
    tag.reason = payload.reason or "set manually"
    tag.source = "manual"
    session.flush()

    # The new level changes this asset's scores, so refresh them now rather than leave the
    # ranking stale until the next scan.
    score_pending_findings(session, load_config().scoring.weights, asset_id=asset_id)
    return _asset_rows(session, [asset])[0]


ACTIVE_FINDING_STATUSES = ("open", "acknowledged")


def _findings_query(
    user_id: str,
    min_risk_score: float | None,
    kev_only: bool,
    q: str | None = None,
    statuses: list[str] | None = None,
    detection_method: str | None = None,
    asset_id: str | None = None,
):
    stmt = (
        select(Finding, CveEnrichment, Asset, AssetCriticality)
        .join(CveEnrichment, Finding.cve_id == CveEnrichment.cve_id)
        .join(Asset, Finding.asset_id == Asset.id)
        .outerjoin(AssetCriticality, AssetCriticality.asset_id == Asset.id)
    )
    stmt = stmt.where(Asset.user_id == user_id)
    if min_risk_score is not None:
        stmt = stmt.where(Finding.risk_score >= min_risk_score)
    if kev_only:
        stmt = stmt.where(CveEnrichment.kev_listed.is_(True))
    if q:
        needle = f"%{q.strip().lower()}%"
        stmt = stmt.where(
            or_(func.lower(Finding.cve_id).like(needle), func.lower(Asset.hostname).like(needle))
        )
    if statuses:
        stmt = stmt.where(Finding.status.in_(statuses))
    if detection_method:
        stmt = stmt.where(Finding.detection_method == detection_method)
    if asset_id:
        stmt = stmt.where(Finding.asset_id == asset_id)
    return stmt


SORT_COLUMNS = {
    "risk_score": Finding.risk_score,
    "detected_at": Finding.detected_at,
    "cvss_score": CveEnrichment.cvss_score,
    "epss_score": CveEnrichment.epss_score,
}


@app.get("/api/v1/findings", response_model=FindingList)
def list_findings(
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
    sort: str = Query("risk_score", pattern="^(risk_score|detected_at|cvss_score|epss_score)$"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    min_risk_score: float | None = None,
    kev_only: bool = False,
    q: str | None = Query(None, max_length=100, description="matches CVE id or hostname"),
    status: str | None = Query(
        None, description="comma-separated: open, acknowledged, resolved, false_positive, or 'active'"
    ),
    detection_method: str | None = Query(None, pattern="^(version_inference|active_detection)$"),
    asset_id: str | None = None,
) -> FindingList:
    statuses = None
    if status:
        statuses = (
            list(ACTIVE_FINDING_STATUSES)
            if status == "active"
            else [s.strip() for s in status.split(",") if s.strip()]
        )
        unknown = set(statuses) - set(FINDING_STATUSES)
        if unknown:
            raise ApiError(400, "invalid_request", f"unknown status: {', '.join(sorted(unknown))}")

    stmt = _findings_query(user.id, min_risk_score, kev_only, q, statuses, detection_method, asset_id)
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0

    column = SORT_COLUMNS[sort]
    # NULLs (an unscored or CVSS-less finding) sort last in either direction rather than first.
    ordering = column.desc().nulls_last() if order == "desc" else column.asc().nulls_last()
    rows = session.execute(
        stmt.order_by(ordering, Finding.cve_id, Finding.id).limit(limit).offset(offset)
    ).all()

    findings = [
        FindingOut(
            id=f.id,
            asset_id=a.id,
            asset=f"{a.hostname}:{a.port}",
            cve_id=c.cve_id,
            cvss_score=c.cvss_score,
            kev_listed=c.kev_listed,
            epss_score=c.epss_score,
            asset_criticality=crit.level if crit else None,
            risk_score=f.risk_score,
            status=f.status,
            reasoning=f.reasoning,
            detection_method=f.detection_method,
            detected_by_tool=f.detected_by_tool,
            detected_at=f.detected_at,
        )
        for f, c, a, crit in rows
    ]
    return FindingList(total=total, findings=findings)


def _load_finding(session: Session, finding_id: str, user_id: str):
    row = session.execute(
        select(Finding, CveEnrichment, Asset, AssetCriticality)
        .join(CveEnrichment, Finding.cve_id == CveEnrichment.cve_id)
        .join(Asset, Finding.asset_id == Asset.id)
        .outerjoin(AssetCriticality, AssetCriticality.asset_id == Asset.id)
        .where(Finding.id == finding_id, Asset.user_id == user_id)
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
        asset_criticality_source=crit.source if crit else None,
        asset_criticality_reason=crit.reason if crit else None,
        risk_score=f.risk_score,
        status=f.status,
        reasoning=f.reasoning,
        description=c.description,
        detection_method=f.detection_method,
        detected_by_tool=f.detected_by_tool,
        evidence=f.evidence,
        detected_at=f.detected_at,
    )


@app.get("/api/v1/findings/{finding_id}", response_model=FindingDetail)
def get_finding(
    finding_id: str, user: User = Depends(current_user), session: Session = Depends(get_session)
) -> FindingDetail:
    return _detail(_load_finding(session, finding_id, user.id))


@app.patch(
    "/api/v1/findings/{finding_id}",
    response_model=FindingDetail,
)
def update_finding(
    finding_id: str,
    payload: FindingUpdate,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> FindingDetail:
    if payload.status not in FINDING_STATUSES:
        raise ApiError(400, "invalid_request", f"status must be one of {', '.join(FINDING_STATUSES)}")
    row = _load_finding(session, finding_id, user.id)
    row[0].status = payload.status
    session.flush()
    return _detail(row)


@app.get("/api/v1/observations", response_model=ObservationList)
def list_observations(
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
    scan_id: str | None = None,
    kind: str | None = None,
    source_tool: str | None = None,
    target: str | None = Query(None, description="exact host:port, to see the evidence behind one asset"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> ObservationList:
    """Raw tool output, before normalization - the provenance behind every finding."""
    stmt = select(ObservationRecord).where(
        ObservationRecord.scan_id.in_(select(Scan.id).where(Scan.user_id == user.id))
    )
    if scan_id:
        stmt = stmt.where(ObservationRecord.scan_id == scan_id)
    if kind:
        stmt = stmt.where(ObservationRecord.kind == kind)
    if source_tool:
        stmt = stmt.where(ObservationRecord.source_tool == source_tool)
    if target:
        stmt = stmt.where(ObservationRecord.target == target)

    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = session.scalars(
        stmt.order_by(ObservationRecord.observed_at.desc()).limit(limit).offset(offset)
    ).all()
    return ObservationList(
        total=total,
        observations=[ObservationOut.model_validate(r, from_attributes=True) for r in rows],
    )


@app.get("/api/v1/overview", response_model=Overview)
def overview(user: User = Depends(current_user), session: Session = Depends(get_session)) -> Overview:
    """Headline numbers for the dashboard's landing page, computed in the database so the page
    does not have to download every finding just to count them."""
    my_assets = select(Asset.id).where(Asset.user_id == user.id)
    # Findings that are the caller's and still in play. Everything below is confined to these.
    active = Finding.status.in_(ACTIVE_FINDING_STATUSES) & Finding.asset_id.in_(my_assets)

    def counts(column, *conditions) -> dict[str, int]:
        stmt = select(column, func.count()).where(*conditions).group_by(column)
        return {str(key): n for key, n in session.execute(stmt).all()}

    band = case(
        *[(Finding.risk_score >= threshold, name) for name, threshold in RISK_BANDS[:-1]],
        (Finding.risk_score.isnot(None), RISK_BANDS[-1][0]),
        else_="unscored",
    )
    by_band = {name: 0 for name, _ in RISK_BANDS} | {"unscored": 0}
    by_band.update(counts(band, active))

    by_detection = {"active_detection": 0, "version_inference": 0}
    by_detection.update(counts(Finding.detection_method, active))

    kev = session.scalar(
        select(func.count())
        .select_from(Finding)
        .join(CveEnrichment, Finding.cve_id == CveEnrichment.cve_id)
        .where(active, CveEnrichment.kev_listed.is_(True))
    ) or 0

    criticality = {level: 0 for level in CRITICALITY_LEVELS} | {"unset": 0}
    tagged = counts(AssetCriticality.level, AssetCriticality.asset_id.in_(my_assets))
    criticality.update(tagged)
    asset_total = session.scalar(select(func.count()).select_from(Asset).where(Asset.user_id == user.id)) or 0
    criticality["unset"] = max(0, asset_total - sum(tagged.values()))

    scans_total = session.scalar(
        select(func.count()).select_from(Scan).where(Scan.user_id == user.id)
    ) or 0
    last = session.scalars(
        select(Scan).where(Scan.user_id == user.id).order_by(Scan.started_at.desc()).limit(1)
    ).first()
    last_summary = None
    if last is not None:
        observation_count = session.scalar(
            select(func.count()).select_from(ObservationRecord).where(ObservationRecord.scan_id == last.id)
        ) or 0
        last_summary = ScanSummary(
            scan_id=last.id,
            target_domain=last.target_domain,
            profile=last.profile,
            status=last.status,
            started_at=last.started_at,
            completed_at=last.completed_at,
            error=last.error,
            warnings=list(last.warnings or []),
            observation_count=observation_count,
        )

    return Overview(
        findings=FindingsOverview(
            active=sum(by_detection.values()),
            actively_exploited=kev,
            confirmed=by_detection["active_detection"],
            by_risk_band=by_band,
            by_detection=by_detection,
        ),
        assets=AssetsOverview(total=asset_total, by_criticality=criticality),
        scans_total=scans_total,
        last_scan=last_summary,
    )


@app.get("/api/v1/enrichment/status", response_model=EnrichmentStatus)
def enrichment_status(
    _: User = Depends(current_user), session: Session = Depends(get_session)
) -> EnrichmentStatus:
    rows = session.scalars(select(SourceRefresh).order_by(SourceRefresh.name)).all()
    return EnrichmentStatus(
        sources=[SourceStatus.model_validate(r, from_attributes=True) for r in rows]
    )
