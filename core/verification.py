"""Proving control of a domain with a DNS TXT record.

The owner publishes a value only someone who can edit the domain's DNS can publish:

    _cerberus-challenge.example.com.  TXT  "cerberus-verify=<token>"

and we look it up. The token is per claim and unguessable (`Domain.verification_token`), so
knowing a domain name is not enough to verify it. This is the whole of what replaces the old
"I am authorised" checkbox.

The lookup is injectable so tests never touch the network, and its failures are kept apart:
"the record is not there" (the owner has more to do) is not "we could not ask" (try again).
"""

from __future__ import annotations

import hmac
from collections.abc import Callable
from dataclasses import dataclass

import dns.exception
import dns.resolver

CHALLENGE_LABEL = "_cerberus-challenge"
VALUE_PREFIX = "cerberus-verify="
LOOKUP_TIMEOUT_SECONDS = 8.0


class RecordNotFound(Exception):
    """The name does not exist or has no TXT records."""


class LookupUnavailable(Exception):
    """DNS could not be asked (timeout, no reachable nameserver). Says nothing about the record."""


@dataclass(frozen=True)
class VerificationResult:
    verified: bool
    # "verified" | "record_not_found" | "token_mismatch" | "lookup_failed"
    reason: str
    detail: str


def challenge_record(domain: str, token: str) -> tuple[str, str]:
    """(record name, record value) the owner must publish."""
    return f"{CHALLENGE_LABEL}.{domain}", f"{VALUE_PREFIX}{token}"


def lookup_txt(name: str, timeout: float = LOOKUP_TIMEOUT_SECONDS) -> list[str]:
    """Every TXT string at `name`, each record's chunks joined (DNS splits long values at 255 bytes)."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = min(timeout, 4.0)
    try:
        answer = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as exc:
        raise RecordNotFound(name) from exc
    except (dns.resolver.NoNameservers, dns.exception.Timeout, dns.exception.DNSException, OSError) as exc:
        raise LookupUnavailable(str(exc) or exc.__class__.__name__) from exc
    return [b"".join(record.strings).decode("utf-8", errors="replace") for record in answer]


def check_dns_txt(
    domain: str,
    token: str,
    lookup: Callable[[str], list[str]] | None = None,
) -> VerificationResult:
    lookup = lookup or lookup_txt
    name, expected = challenge_record(domain, token)
    try:
        records = lookup(name)
    except RecordNotFound:
        return VerificationResult(
            False, "record_not_found",
            f"No TXT record found at {name}. DNS changes can take a few minutes to appear; "
            "check the name and value, then try again.",
        )
    except LookupUnavailable:
        return VerificationResult(
            False, "lookup_failed",
            "DNS could not be reached just now, so nothing was concluded. Try again in a moment.",
        )

    wanted = expected.encode()
    for record in records:
        if hmac.compare_digest(record.strip().strip('"').encode(), wanted):
            return VerificationResult(True, "verified", f"Found the verification record at {name}.")
    return VerificationResult(
        False, "token_mismatch",
        f"{name} has a TXT record, but not this one. Check that the value is exactly {expected}.",
    )
