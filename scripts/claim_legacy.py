#!/usr/bin/env python3
"""Give data that has no owner to an account.

Scans and assets written before accounts existed (and CLI scans run without `--owner`) belong to
nobody, and the API shows a signed-in user only their own data, so they are invisible until claimed.
This assigns every unowned scan and asset to one existing account.

    python scripts/claim_legacy.py you@example.com

Register the account in the dashboard first. Only unowned rows are touched: anything already owned by
someone (including you) is left exactly as it is. Safe to run more than once.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select, update  # noqa: E402

from core.config import load_config  # noqa: E402
from core.db import init_db, redact_url, session_scope  # noqa: E402
from core.models import Asset, Scan, User  # noqa: E402
from core.ownership import OwnershipError, normalize_email  # noqa: E402


def claim(session, email: str) -> tuple[int, int]:
    """Assign unowned scans and assets to `email`'s account. Returns (scans, assets) claimed."""
    user = session.scalar(select(User).where(User.email == normalize_email(email)))
    if user is None:
        raise LookupError(f"no account for {email!r}. Register it in the dashboard first.")
    scans = session.execute(update(Scan).where(Scan.user_id.is_(None)).values(user_id=user.id)).rowcount
    assets = session.execute(update(Asset).where(Asset.user_id.is_(None)).values(user_id=user.id)).rowcount
    return scans, assets


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("email", help="the account that should own the unowned data")
    args = parser.parse_args()

    init_db()
    try:
        with session_scope() as session:
            scans, assets = claim(session, args.email)
    except (LookupError, OwnershipError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    where = redact_url(load_config().database_url)
    print(f"{args.email}: claimed {scans} scan(s) and {assets} asset(s) on {where}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
