"""Who may scan what: the ownership rule, as code.

    logged-in user -> owns the domain? -> domain verified? -> target inside that domain? -> allow

This module holds only the rule and the normalisation the rule depends on. It knows nothing
about passwords, sessions or HTTP: authentication happens at the API boundary and hands this a
`User` and a `Domain`. The scanning pipeline downstream never sees either.

Every refusal is an `OwnershipError` with a stable `code`, so the API can map it to a status
without parsing messages. `not_owner` is deliberately distinct from `not_verified`: an API
should answer `not_owner` as "no such domain" (404), so it cannot be used to discover which
domains other people have claimed.
"""

from __future__ import annotations

import ipaddress
import re

from core.models import Domain, User
from core.scope import Scope

MAX_DOMAIN_LENGTH = 253
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class OwnershipError(ValueError):
    """A scan (or claim) was refused. `code` is stable; the message is for a person."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def normalize_email(email: str) -> str:
    """Lower-case and trim, so `A@x.com` and `a@x.com ` are one account."""
    value = (email or "").strip().lower()
    local, _, host = value.partition("@")
    if not local or "." not in host or " " in value or value.count("@") != 1:
        raise OwnershipError("invalid_email", f"{email!r} is not a valid email address")
    return value


def normalize_domain(value: str) -> str:
    """The canonical form stored in `domains.domain`.

    Accepts what a person might paste (mixed case, a trailing dot) and refuses what is not a
    bare registrable name: URLs, paths, ports, addresses, wildcards. A scan target must be a
    name a verification record can be published under, and an IP address or `localhost` cannot
    prove ownership that way.
    """
    domain = (value or "").strip().lower().rstrip(".")
    if not domain:
        raise OwnershipError("invalid_domain", "Enter a domain such as example.com.")
    if any(ch in domain for ch in "/:@ *?#\\"):
        raise OwnershipError(
            "invalid_domain",
            f"{value!r} is not a bare domain. Enter just the name, for example example.com "
            "(no https://, path, port or wildcard).",
        )
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise OwnershipError("invalid_domain", "An IP address cannot be verified as a domain you own.")
    labels = domain.split(".")
    if len(domain) > MAX_DOMAIN_LENGTH or len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        raise OwnershipError("invalid_domain", f"{value!r} is not a valid domain name.")
    return domain


def check_scan_allowed(user: User, domain: Domain, target: str | None = None) -> None:
    """Raise `OwnershipError` unless `user` may scan `target` (default: the domain itself)."""
    if not user.is_active:
        raise OwnershipError("user_inactive", "This account is disabled.")
    if domain.user_id != user.id:
        raise OwnershipError("not_owner", "No such domain.")
    if domain.verification_status != "verified":
        raise OwnershipError(
            "not_verified",
            f"{domain.domain} is not verified yet. Publish the verification record and verify it "
            "before scanning.",
        )
    if target is not None and not Scope(domain.domain).permits_host(target):
        raise OwnershipError(
            "out_of_scope",
            f"{target} is not {domain.domain} or one of its subdomains.",
        )
