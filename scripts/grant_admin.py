#!/usr/bin/env python3
"""Grant or revoke the admin flag on an account.

An admin can see every user's domains, scans and findings (read-only — see docs/API.md §5). It
grants no scanning power beyond what any verified-domain owner already has: an admin's own scans
are still authorised exactly like anyone else's, by a domain *they* own and verified. There is no
API endpoint that sets this flag, deliberately, the same trust boundary as claim_legacy.py: only
someone with direct access to this database can grant it.

    python scripts/grant_admin.py you@example.com            # grant
    python scripts/grant_admin.py you@example.com --revoke   # revoke

Register the account in the dashboard first.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select  # noqa: E402

from core.config import load_config  # noqa: E402
from core.db import init_db, redact_url, session_scope  # noqa: E402
from core.models import User  # noqa: E402
from core.ownership import OwnershipError, normalize_email  # noqa: E402


def set_admin(session, email: str, admin: bool) -> User:
    user = session.scalar(select(User).where(User.email == normalize_email(email)))
    if user is None:
        raise LookupError(f"no account for {email!r}. Register it in the dashboard first.")
    user.is_admin = admin
    return user


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("email", help="the account to grant or revoke admin on")
    parser.add_argument("--revoke", action="store_true", help="revoke admin instead of granting it")
    args = parser.parse_args()

    init_db()
    try:
        with session_scope() as session:
            user = set_admin(session, args.email, admin=not args.revoke)
    except (LookupError, OwnershipError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    where = redact_url(load_config().database_url)
    verb = "revoked from" if args.revoke else "granted to"
    print(f"admin {verb} {user.email} on {where}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
