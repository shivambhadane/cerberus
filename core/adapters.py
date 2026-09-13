"""Scanner adapter contract.

Every tool that observes something about a target — a CT-log query, a port scan, a
nuclei run — implements one of these protocols and returns Observations. An
Observation records what was seen *and which tool saw it*, so a finding can always
be traced back to the evidence that produced it.

Adding a tool means writing an adapter and registering it. Nothing in the pipeline
core changes.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from core.profiles import ScanProfile
from core.scope import Scope

log = logging.getLogger(__name__)


class ObservationKind:
    SUBDOMAIN = "subdomain"
    OPEN_PORT = "open_port"
    TECHNOLOGY = "technology"
    VULNERABILITY = "vulnerability"


class DetectionMethod:
    """How strongly a finding is evidenced.

    VERSION_INFERENCE: the service reported a version associated with this CVE.
    ACTIVE_DETECTION:  the target responded to a probe specific to this weakness.
    """

    VERSION_INFERENCE = "version_inference"
    ACTIVE_DETECTION = "active_detection"


@dataclass(frozen=True)
class Endpoint:
    hostname: str
    ip_address: str | None = None
    port: int | None = None
    protocol: str = "tcp"

    def __str__(self) -> str:
        return f"{self.hostname}:{self.port}" if self.port else self.hostname


@dataclass(frozen=True)
class Observation:
    """One fact, produced by one tool, at one time."""

    kind: str
    target: str
    source_tool: str
    data: dict = field(default_factory=dict)
    source_version: str | None = None
    raw: str | None = None
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@runtime_checkable
class Scanner(Protocol):
    """Identity and availability, shared by every adapter."""

    name: str
    kind: str

    def is_available(self) -> bool: ...
    def version(self) -> str | None: ...


@runtime_checkable
class SubdomainScanner(Scanner, Protocol):
    def run(self, scope: Scope) -> list[Observation]: ...


@runtime_checkable
class PortScanner(Scanner, Protocol):
    def run(self, endpoints: list[Endpoint], scope: Scope) -> list[Observation]: ...


@runtime_checkable
class ServiceProbe(Scanner, Protocol):
    def run(self, endpoints: list[Endpoint], scope: Scope) -> list[Observation]: ...


@runtime_checkable
class VulnerabilityScanner(Scanner, Protocol):
    """Vulnerability scanners are handed a resolved ScanProfile, never CLI arguments.

    The profile is the security boundary: it decides what may run, at what rate, and
    the adapter has no way to widen it.
    """

    def run(
        self, endpoints: list[Endpoint], scope: Scope, profile: ScanProfile
    ) -> list[Observation]: ...


_REGISTRY: dict[str, list[Scanner]] = defaultdict(list)


def register(scanner: Scanner) -> Scanner:
    _REGISTRY[scanner.kind].append(scanner)
    return scanner


def registered(kind: str) -> list[Scanner]:
    return list(_REGISTRY[kind])


def available(kind: str) -> list[Scanner]:
    """Registered adapters for a stage that can actually run on this machine."""
    usable = []
    for scanner in _REGISTRY[kind]:
        if scanner.is_available():
            usable.append(scanner)
        else:
            log.info("adapter %s unavailable, skipping", scanner.name)
    return usable


def clear_registry() -> None:
    _REGISTRY.clear()
