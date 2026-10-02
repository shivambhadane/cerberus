"""Read-only, cross-tenant visibility for an account with `is_admin` set.

What this grants and what it does not, stated once, here: an admin can **see** every user's domains,
scans and findings. It grants **no scanning power**. Starting a scan still goes through
`core/ownership.py` exactly as it does for anyone — a verified domain the caller themselves owns — and
nothing here touches that code. There is also no endpoint that sets `is_admin`: only an operator with
direct database access can grant it (`scripts/grant_admin.py`), the same trust boundary as
`claim_legacy.py`. See docs/API.md §5 for the full contract.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from api.deps import get_session, require_admin
from api.schemas import (
    AdminDomainList,
    AdminDomainOut,
    AdminOverview,
    AdminScanList,
    AdminScanOut,
    AdminUserList,
    AdminUserOut,
)
from core.models import Asset, Domain, Finding, Scan, User
from scoring.engine import RISK_BANDS

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


@router.get("/overview", response_model=AdminOverview)
def admin_overview(
    _: User = Depends(require_admin), session: Session = Depends(get_session)
) -> AdminOverview:
    """Headline counts across every account, not just the caller's (contrast with `GET /overview`)."""

    def counts(column, *conditions) -> dict[str, int]:
        stmt = select(column, func.count()).where(*conditions).group_by(column)
        return {str(key): n for key, n in session.execute(stmt).all()}

    user_count = session.scalar(select(func.count()).select_from(User)) or 0
    domain_counts = counts(Domain.verification_status)
    scan_counts = counts(Scan.status)

    band = case(
        *[(Finding.risk_score >= threshold, name) for name, threshold in RISK_BANDS[:-1]],
        (Finding.risk_score.isnot(None), RISK_BANDS[-1][0]),
        else_="unscored",
    )
    finding_counts = {name: 0 for name, _ in RISK_BANDS} | {"unscored": 0}
    finding_counts.update(counts(band, Finding.status == "open"))

    return AdminOverview(
        user_count=user_count,
        domain_counts=domain_counts,
        scan_counts=scan_counts,
        finding_counts=finding_counts,
    )


@router.get("/users", response_model=AdminUserList)
def admin_users(
    _: User = Depends(require_admin),
    session: Session = Depends(get_session),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> AdminUserList:
    total = session.scalar(select(func.count()).select_from(User)) or 0
    users = session.scalars(
        select(User).order_by(User.created_at.desc()).limit(limit).offset(offset)
    ).all()
    domain_n = dict(
        session.execute(
            select(Domain.user_id, func.count()).group_by(Domain.user_id)
        ).all()
    )
    scan_n = dict(
        session.execute(
            select(Scan.user_id, func.count()).where(Scan.user_id.isnot(None)).group_by(Scan.user_id)
        ).all()
    )
    return AdminUserList(
        total=total,
        users=[
            AdminUserOut(
                id=u.id, email=u.email, name=u.name, is_admin=u.is_admin,
                created_at=u.created_at, last_login_at=u.last_login_at,
                domain_count=domain_n.get(u.id, 0), scan_count=scan_n.get(u.id, 0),
            )
            for u in users
        ],
    )


@router.get("/domains", response_model=AdminDomainList)
def admin_domains(
    _: User = Depends(require_admin),
    session: Session = Depends(get_session),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> AdminDomainList:
    total = session.scalar(select(func.count()).select_from(Domain)) or 0
    rows = session.execute(
        select(Domain, User.email)
        .join(User, Domain.user_id == User.id)
        .order_by(Domain.created_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return AdminDomainList(
        total=total,
        domains=[
            AdminDomainOut(
                id=d.id, domain=d.domain, owner_email=email,
                verification_status=d.verification_status, verification_method=d.verification_method,
                created_at=d.created_at,
            )
            for d, email in rows
        ],
    )


@router.get("/scans", response_model=AdminScanList)
def admin_scans(
    _: User = Depends(require_admin),
    session: Session = Depends(get_session),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> AdminScanList:
    total = session.scalar(select(func.count()).select_from(Scan)) or 0
    rows = session.execute(
        select(Scan, User.email)
        .outerjoin(User, Scan.user_id == User.id)  # some scans predate accounts and have no owner
        .order_by(Scan.started_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    scan_ids = [s.id for s, _ in rows]
    finding_n = dict(
        session.execute(
            select(Asset.discovered_by_scan_id, func.count())
            .select_from(Finding)
            .join(Asset, Finding.asset_id == Asset.id)
            .where(Asset.discovered_by_scan_id.in_(scan_ids))
            .group_by(Asset.discovered_by_scan_id)
        ).all()
    ) if scan_ids else {}
    return AdminScanList(
        total=total,
        scans=[
            AdminScanOut(
                scan_id=s.id, owner_email=email, target_domain=s.target_domain, profile=s.profile,
                status=s.status, started_at=s.started_at, completed_at=s.completed_at,
                finding_count=finding_n.get(s.id, 0),
            )
            for s, email in rows
        ],
    )
