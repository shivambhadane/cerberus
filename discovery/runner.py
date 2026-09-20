"""Stage 1 orchestration.

Runs the registered adapters for each discovery phase, enforcing scope between
phases and returning raw Observations. Normalization into assets is ingestion's
job; this module deliberately keeps the tool output intact so provenance survives.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from core.adapters import Endpoint, Observation, ObservationKind, available
from core.config import DiscoveryConfig
from core.proc import ScannerError
from core.profiles import ScanProfile
from core.scope import Scope

log = logging.getLogger(__name__)


@dataclass
class DiscoveryResult:
    observations: list[Observation]
    endpoints: list[Endpoint]
    # Tools that failed to run. Kept apart from observations so "found nothing" and
    # "did not run" are never confused in a scan report.
    errors: list[str] = field(default_factory=list)

    def by_kind(self, kind: str) -> list[Observation]:
        return [o for o in self.observations if o.kind == kind]


def _configure(scanner, config: DiscoveryConfig | None) -> None:
    """Apply operator config to an adapter that accepts it.

    Adapters are registered once at import time, so without this step settings such as
    discovery.ports would be silently ignored.
    """
    configure = getattr(scanner, "configure", None)
    if config is not None and callable(configure):
        configure(config)


def _run_adapter(
    scanner, call: Callable[[], list[Observation]], errors: list[str]
) -> list[Observation]:
    """Run one adapter; a failure is recorded, not fatal, and never silent."""
    try:
        return call()
    except ScannerError as exc:
        log.error("adapter %s failed: %s", scanner.name, exc)
        errors.append(f"{scanner.name}: {exc}")
        return []


def _hosts_from(observations: list[Observation], scope: Scope) -> list[Endpoint]:
    hosts: dict[str, str | None] = {}
    for obs in observations:
        hostname = obs.data.get("hostname")
        if hostname:
            hosts.setdefault(hostname, obs.data.get("ip_address"))
    permitted = scope.filter_hosts(hosts)
    return [Endpoint(hostname=h, ip_address=ip) for h, ip in permitted.items()]


def _endpoints_from_ports(observations: list[Observation], scope: Scope) -> list[Endpoint]:
    """Collapse port observations into unique endpoints.

    Several port scanners can report the same open port; without this the endpoint
    list carries one entry per tool, so later stages probe and count each port twice.
    """
    endpoints: dict[tuple[str, int, str], Endpoint] = {}
    for obs in observations:
        hostname, port = obs.data.get("hostname"), obs.data.get("port")
        if not hostname or port is None:
            continue
        if not scope.permits_host(hostname) or not scope.permits_port(port):
            continue
        protocol = obs.data.get("protocol", "tcp")
        key = (hostname, port, protocol)
        existing = endpoints.get(key)
        if existing is None or (existing.ip_address is None and obs.data.get("ip_address")):
            endpoints[key] = Endpoint(
                hostname=hostname,
                ip_address=obs.data.get("ip_address") or (existing.ip_address if existing else None),
                port=port,
                protocol=protocol,
            )
    return list(endpoints.values())


def run_discovery(
    scope: Scope,
    profile: ScanProfile,
    enumerate_subdomains: bool = True,
    config: DiscoveryConfig | None = None,
) -> DiscoveryResult:
    """Domain -> in-scope endpoints, with every observation attributed to its tool.

    `profile` decides whether the target is contacted at all: a profile that permits no
    active probing stops after passive enumeration and DNS. Otherwise it also governs the
    vulnerability-scanning stage, where adapters receive it directly rather than any
    arguments assembled here.
    """
    import discovery.adapters  # noqa: F401  (registers the adapters)

    observations: list[Observation] = []
    errors: list[str] = []

    if enumerate_subdomains:
        for scanner in available(ObservationKind.SUBDOMAIN):
            observations.extend(_run_adapter(scanner, lambda s=scanner: s.run(scope), errors))
    else:
        log.info("subdomain enumeration disabled; using the apex domain only")

    hosts = _hosts_from(observations, scope)
    if not hosts:
        from discovery.adapters.crtsh import resolve

        ip = resolve(scope.domain)
        if ip and scope.permits_address(ip):
            hosts = [Endpoint(hostname=scope.domain, ip_address=ip)]
    if not hosts:
        log.warning("no in-scope hosts resolved for %s", scope.domain)
        return DiscoveryResult(observations, [], errors)

    if not profile.runs_active_probes:
        # A passive profile promises certificate-transparency and DNS only. Everything past
        # this point sends packets to the target, so it must not run - the promise is
        # otherwise just documentation.
        log.info("profile %s is passive: names resolved via DNS, target not contacted", profile.name)
        return DiscoveryResult(observations, [], errors)

    port_observations: list[Observation] = []
    for scanner in available(ObservationKind.OPEN_PORT):
        _configure(scanner, config)
        port_observations.extend(_run_adapter(scanner, lambda s=scanner: s.run(hosts, scope), errors))
    observations.extend(port_observations)

    endpoints = _endpoints_from_ports(port_observations, scope)
    if not endpoints:
        log.info("no open ports found for %s", scope.domain)
        return DiscoveryResult(observations, [], errors)

    # Port scanners that do service detection (nmap -sV) already supply technology;
    # only probe what is still unidentified.
    identified = {
        o.target for o in port_observations if o.data.get("technology")
    }
    unidentified = [e for e in endpoints if str(e) not in identified]
    for scanner in available(ObservationKind.TECHNOLOGY):
        observations.extend(_run_adapter(scanner, lambda s=scanner: s.run(unidentified, scope), errors))

    if profile.runs_active_probes:
        for scanner in available(ObservationKind.VULNERABILITY):
            observations.extend(
                _run_adapter(scanner, lambda s=scanner: s.run(endpoints, scope, profile), errors)
            )
    else:
        log.info("profile %s permits no active probing; skipping detection", profile.name)

    log.info(
        "discovery complete: %d observations, %d endpoints, tools=%s",
        len(observations), len(endpoints),
        sorted({o.source_tool for o in observations}),
    )
    return DiscoveryResult(observations, endpoints, errors)
