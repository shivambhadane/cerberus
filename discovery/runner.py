from __future__ import annotations

import logging
import warnings
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from core.config import DiscoveryConfig
from discovery.fingerprint import fingerprint
from discovery.ports import DEFAULT_PORTS, scan
from discovery.subdomains import enumerate_subdomains

log = logging.getLogger(__name__)

warnings.filterwarnings("ignore", message="Unverified HTTPS request")


@dataclass(frozen=True)
class DiscoveredAsset:
    hostname: str
    ip_address: str | None
    port: int
    protocol: str
    technology: str | None


def run_discovery(domain: str, config: DiscoveryConfig) -> list[DiscoveredAsset]:
    """Stage 1: domain -> list of reachable host:port assets with technologies."""
    hosts = enumerate_subdomains(domain, enabled=config.subdomain_enum)
    if not hosts:
        log.warning("no resolvable hosts found for %s", domain)
        return []

    if not config.port_scan:
        return [DiscoveredAsset(h, ip, 443, "tcp", None) for h, ip in hosts.items()]

    open_ports = scan(
        list(hosts),
        ports=config.ports or DEFAULT_PORTS,
        timeout=config.connect_timeout,
        concurrency=config.max_concurrency,
    )

    targets = [(host, port) for host, ports in open_ports.items() for port in ports]
    log.info("found %d open ports across %d hosts", len(targets), len(hosts))

    with ThreadPoolExecutor(max_workers=16) as pool:
        techs = list(pool.map(lambda t: fingerprint(*t), targets))

    return [
        DiscoveredAsset(host, hosts.get(host), port, "tcp", tech)
        for (host, port), tech in zip(targets, techs, strict=True)
    ]
