#!/usr/bin/env python3
"""Add a sanctioned testbed domain (e.g. testphp.vulnweb.com) as a verified target for a user."""

from __future__ import annotations

import sys
from pathlib import Path
from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.db import session_scope
from core.models import Domain, User, utcnow


def main():
    if len(sys.argv) < 3:
        print("Usage: python scripts/add_test_target.py <user_email> <domain>")
        print("Example: python scripts/add_test_target.py you@example.com testphp.vulnweb.com")
        sys.exit(1)

    email = sys.argv[1].strip()
    domain_name = (
        sys.argv[2]
        .strip()
        .lower()
        .replace("http://", "")
        .replace("https://", "")
        .rstrip("/")
    )

    with session_scope() as session:
        user = session.scalar(select(User).where(User.email == email))
        if not user:
            print(f"Error: User '{email}' not found. Register or sign in first in the dashboard.")
            sys.exit(1)

        domain = session.scalar(
            select(Domain).where(Domain.domain == domain_name, Domain.user_id == user.id)
        )
        if not domain:
            domain = Domain(user_id=user.id, domain=domain_name)
            session.add(domain)

        domain.verification_status = "verified"
        domain.verified_at = utcnow()
        domain.verification_method = "dns_txt"

    print(f"Success: '{domain_name}' is now a verified target for '{email}'.")
    print(f"Go to your dashboard (http://localhost:5173/platform/#/domains) to click 'Scan this domain'!")


if __name__ == "__main__":
    main()
