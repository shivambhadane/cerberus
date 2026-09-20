from __future__ import annotations

import logging
import shutil
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from core.adapters import Endpoint, Observation, ObservationKind, register
from core.proc import ScannerError, run_tool, stderr_tail
from core.scope import Scope
from discovery.adapters.tcp_connect import DEFAULT_PORTS

log = logging.getLogger(__name__)

TIMEOUT = 600


class NmapScanner:
    """Port and service discovery via nmap, when installed.

    Uses a TCP connect scan with light version detection (-sV --version-intensity 2)
    rather than the default aggressive probing, per docs/RULES_OF_ENGAGEMENT.md.
    Its service/version output is more reliable than banner grabbing, so when nmap is
    present it supersedes the pure-Python scanner.
    """

    name = "nmap"
    kind = ObservationKind.OPEN_PORT

    def __init__(self, ports: list[int] | None = None):
        self.ports = ports or DEFAULT_PORTS

    def is_available(self) -> bool:
        return shutil.which("nmap") is not None

    def configure(self, config) -> None:
        self.ports = list(config.ports) or DEFAULT_PORTS

    def version(self) -> str | None:
        if not self.is_available():
            return None
        try:
            proc = run_tool(["nmap", "--version"], timeout=15)
        except ScannerError:
            return None
        first = proc.stdout.strip().splitlines()[0] if proc.stdout.strip() else ""
        return first or None

    def run(self, endpoints: list[Endpoint], scope: Scope) -> list[Observation]:
        hosts = sorted({e.hostname for e in endpoints if scope.permits_host(e.hostname)})
        if not hosts:
            return []
        ports = ",".join(str(p) for p in self.ports if scope.permits_port(p))

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "scan.xml"
            cmd = [
                "nmap", "-Pn", "-sT", "--open",
                "-sV", "--version-intensity", "2",
                "-T3", "-p", ports, "-oX", str(out), *hosts,
            ]
            proc = run_tool(cmd, timeout=TIMEOUT, tool="nmap")
            if proc.returncode != 0:
                raise ScannerError(f"nmap exited {proc.returncode}: {stderr_tail(proc)}")
            xml = out.read_text() if out.exists() else ""

        return self._parse(xml, scope, endpoints)

    def _parse(
        self, xml: str, scope: Scope, endpoints: list[Endpoint] | None = None
    ) -> list[Observation]:
        if not xml.strip():
            return []
        try:
            root = ET.fromstring(xml)
        except ET.ParseError as exc:
            log.warning("could not parse nmap output (%s)", exc)
            return []

        version = self.version()
        observations: list[Observation] = []
        requested = {e.ip_address: e.hostname for e in (endpoints or []) if e.ip_address}
        for host in root.findall("host"):
            address = host.find("address")
            ip = address.get("addr") if address is not None else None
            hostname = _identify_host(host, ip, requested)
            if hostname is None or not scope.permits_host(hostname):
                continue
            if ip is not None and not scope.permits_address(ip):
                continue

            for port in host.findall("ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                number = int(port.get("portid", "0"))
                if not scope.permits_port(number):
                    continue

                service = port.find("service")
                technology = None
                if service is not None:
                    product = service.get("product")
                    ver = service.get("version")
                    technology = f"{product}/{ver}" if product and ver else product

                observations.append(
                    Observation(
                        kind=self.kind,
                        target=f"{hostname}:{number}",
                        source_tool=self.name,
                        source_version=version,
                        data={
                            "hostname": hostname,
                            "ip_address": ip,
                            "port": number,
                            "protocol": port.get("protocol", "tcp"),
                            "technology": technology,
                            "service": service.get("name") if service is not None else None,
                        },
                        raw=ET.tostring(port, encoding="unicode").strip(),
                    )
                )
        log.info("nmap: %d open ports", len(observations))
        return observations


def _identify_host(host: ET.Element, ip: str | None, requested: dict[str, str]) -> str | None:
    """Decide which hostname a result belongs to, without trusting reverse DNS.

    nmap labels a host with whatever its PTR record says (`localhost`, or
    `93-184-216-34.bc.googleusercontent.com` for a cloud IP). That name says nothing about
    the target we asked for, and treating it as identity makes the scope check reject
    every result on a real host. Identity comes from, in order: the name we passed on the
    command line (`type="user"`), the endpoint we already resolved to this address, then any
    non-PTR name. A PTR name is never used.
    """
    by_type: dict[str, str] = {}
    for h in host.findall("hostnames/hostname"):
        if h.get("name"):
            by_type.setdefault(h.get("type") or "", h.get("name"))

    if "user" in by_type:
        return by_type["user"]
    if ip is not None and ip in requested:
        return requested[ip]
    for kind, name in by_type.items():
        if kind != "PTR":
            return name
    return ip


register(NmapScanner())
