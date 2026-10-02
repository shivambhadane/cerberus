"""Authorization and scope boundaries.

Cerberus performs active reconnaissance, so what it is allowed to touch is a
correctness concern, not a policy document. Every scanner is handed a Scope and
must ask it before probing anything; see docs/RULES_OF_ENGAGEMENT.md.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


class OutOfScopeError(Exception):
    """Raised when something tries to probe a target the scope forbids."""


@dataclass
class Scope:
    domain: str
    include_subdomains: bool = True
    excluded_hosts: set[str] = field(default_factory=set)
    excluded_ports: set[int] = field(default_factory=set)
    allow_private_addresses: bool = False
    # A narrower grant than allow_private_addresses: permits ONLY the exact loopback addresses
    # (127.0.0.1, ::1), never the RFC1918 ranges, link-local, or the cloud metadata address
    # (169.254.169.254). This exists for one caller: a Test Labs Docker lab target, which must
    # never be able to reach this host's own private network, only itself.
    allow_loopback_only: bool = False

    def __post_init__(self) -> None:
        self.domain = self.domain.lower().rstrip(".")
        self.excluded_hosts = {h.lower().rstrip(".") for h in self.excluded_hosts}

    def permits_host(self, hostname: str) -> bool:
        host = hostname.lower().rstrip(".")
        if host in self.excluded_hosts:
            return False
        if host == self.domain:
            return True
        if self.include_subdomains and host.endswith(f".{self.domain}"):
            return True
        return False

    def permits_address(self, ip: str | None) -> bool:
        """Keep scans off loopback/private ranges unless explicitly allowed.

        A hostname in scope can still resolve somewhere we have no authority over,
        such as a shared CDN or an internal address.
        """
        if ip is None:
            return True
        if self.allow_private_addresses:
            return True
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if self.allow_loopback_only:
            return address.is_loopback
        return not (address.is_private or address.is_loopback or address.is_link_local
                    or address.is_multicast or address.is_reserved)

    def permits_port(self, port: int) -> bool:
        return port not in self.excluded_ports

    def filter_hosts(self, hosts: dict[str, str | None]) -> dict[str, str | None]:
        """Drop anything out of scope, logging each rejection for the audit trail."""
        kept: dict[str, str | None] = {}
        for hostname, ip in hosts.items():
            if not self.permits_host(hostname):
                log.info("scope: skipping %s (outside %s)", hostname, self.domain)
                continue
            if not self.permits_address(ip):
                log.info("scope: skipping %s (%s is not a public address)", hostname, ip)
                continue
            kept[hostname] = ip
        return kept

    def require_host(self, hostname: str) -> None:
        if not self.permits_host(hostname):
            raise OutOfScopeError(f"{hostname} is outside the authorized scope ({self.domain})")


def development_scope(domain: str) -> Scope:
    """Scope for Level 1 local testing, which necessarily targets private addresses."""
    return Scope(domain=domain, allow_private_addresses=True)
