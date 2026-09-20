"""Level 2: authorized public targets.

AUTHORIZATION
    scanme.nmap.org is run by the Nmap project for exactly this purpose. Their stated policy
    authorizes scanning it "with Nmap or other port scanners" and asks that it not be hammered.

    That grant covers port and service discovery. It does NOT cover running a vulnerability
    scanner, so these tests never invoke nuclei, scan only ports 22 and 80, and use a low
    concurrency. Do not extend them to other tools or ports without checking the policy.

OPT-IN
    These tests contact a third party over the network, so they are skipped unless
    CERBERUS_PUBLIC_TESTS=1 is set. They are not run by default or in CI.

        CERBERUS_PUBLIC_TESTS=1 pytest tests/integration/test_public_targets.py -v
"""

from __future__ import annotations

import os
import shutil

import pytest

from core.adapters import Endpoint, ObservationKind
from core.scope import Scope
from discovery.adapters.crtsh import resolve
from discovery.adapters.http_probe import HttpProbe
from discovery.adapters.nmap_scan import NmapScanner
from discovery.adapters.tcp_connect import TcpConnectScanner

TARGET = "scanme.nmap.org"
PORTS = [22, 80]

pytestmark = pytest.mark.skipif(
    os.environ.get("CERBERUS_PUBLIC_TESTS") != "1",
    reason="contacts a third-party host; set CERBERUS_PUBLIC_TESTS=1 to run",
)


@pytest.fixture(scope="module")
def scope() -> Scope:
    return Scope(domain=TARGET, include_subdomains=False)


@pytest.fixture(scope="module")
def endpoint(scope: Scope) -> Endpoint:
    ip = resolve(TARGET)
    if ip is None:
        pytest.skip("could not resolve scanme.nmap.org (offline?)")
    assert scope.permits_address(ip), "scanme.nmap.org must resolve to a public address"
    return Endpoint(hostname=TARGET, ip_address=ip)


@pytest.fixture(scope="module")
def open_ports(scope: Scope, endpoint: Endpoint):
    scanner = TcpConnectScanner(ports=PORTS, timeout=8.0, concurrency=2)
    return scanner.run([endpoint], scope)


def test_port_scan_finds_the_published_services(open_ports):
    found = {o.data["port"] for o in open_ports}
    assert found, "scanme.nmap.org publishes SSH and HTTP; nothing was found"
    assert found <= set(PORTS)  # never reports a port we did not ask about


def test_every_observation_is_in_scope_and_attributed(open_ports):
    assert open_ports
    for obs in open_ports:
        assert obs.source_tool == "tcp_connect"
        assert obs.kind == ObservationKind.OPEN_PORT
        assert obs.data["hostname"] == TARGET


@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap not installed")
def test_nmap_identifies_a_service_and_is_not_rejected_by_scope(scope, endpoint):
    """Regression for the reverse-DNS bug: scanme's PTR record is not scanme.nmap.org, so
    trusting nmap's hostname would make scope discard every result."""
    scanner = NmapScanner(ports=PORTS)
    observations = scanner.run([endpoint], scope)

    assert observations, "nmap results were all discarded - hostname identity is broken"
    assert all(o.target.startswith(f"{TARGET}:") for o in observations)
    assert any(o.data.get("technology") for o in observations)


def test_http_probe_fingerprints_the_web_server(scope):
    observations = HttpProbe(timeout=10.0).run([Endpoint(TARGET, port=80)], scope)

    assert observations
    assert observations[0].source_tool == "http_probe"
    assert observations[0].data["technology"]


def test_out_of_scope_hosts_are_never_contacted(scope):
    """Scope is enforced before any packet is sent, so this makes no network call."""
    scanner = TcpConnectScanner(ports=PORTS, timeout=1.0, concurrency=1)
    observations = scanner.run([Endpoint("evil-scanme.nmap.org", "203.0.113.5")], scope)
    assert observations == []
