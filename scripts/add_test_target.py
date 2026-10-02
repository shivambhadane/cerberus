#!/usr/bin/env python3
"""Add a sanctioned testbed domain (e.g. testphp.vulnweb.com) as a verified target for a user.

Only the testbeds in api.domains.SANCTIONED_TESTBEDS can be added, and they are recorded with
verification_method "testbed" - the same provenance the API's own POST /domains/testbeds/{id}
writes. Both of those matter:

  * Marking an arbitrary domain verified would make this script an ownership-verification bypass,
    which is exactly the class of hole docs/RULES_OF_ENGAGEMENT.md 1 exists to prevent. Permission
    to scan these particular hosts comes from their owners publishing them as test targets.
  * Writing "dns_txt" (which this script used to do) would claim a DNS TXT record was checked when
    none was. The evidence trail is meant to say how a target was actually proven, not to look tidy.
"""

from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.domains import SANCTIONED_TESTBEDS
from core.db import session_scope
from core.models import Domain, User, utcnow


def sanctioned_domains() -> dict[str, list[str]]:
    """{domain: [testbed id, ...]} for every sanctioned testbed - several Docker labs share 127.0.0.1."""
    out: dict[str, list[str]] = {}
    for tid, info in SANCTIONED_TESTBEDS.items():
        out.setdefault(info["domain"], []).append(tid)
    return out


def main():
    allowed = sanctioned_domains()
    if len(sys.argv) < 3:
        print("Usage: python scripts/add_test_target.py <user_email> <domain>")
        print("Example: python scripts/add_test_target.py you@example.com testphp.vulnweb.com")
        print("\nSanctioned testbeds:")
        for domain_name, ids in sorted(allowed.items()):
            print(f"  {domain_name:24} ({', '.join(sorted(ids))})")
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

    if domain_name not in allowed:
        print(f"Error: '{domain_name}' is not a sanctioned testbed, so this script will not mark it")
        print("verified. Scanning needs permission from whoever owns the target; prove ownership of")
        print("your own domain in the dashboard (DNS TXT, or a connected deployment) instead.")
        print("\nSanctioned testbeds:")
        for allowed_domain, ids in sorted(allowed.items()):
            print(f"  {allowed_domain:24} ({', '.join(sorted(ids))})")
        sys.exit(1)

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
        domain.verification_method = "testbed"

    print(f"Success: '{domain_name}' is now a verified target for '{email}'.")
    print("Go to your dashboard (http://localhost:5173/platform/#/domains) to click 'Scan this domain'!")


if __name__ == "__main__":
    main()
