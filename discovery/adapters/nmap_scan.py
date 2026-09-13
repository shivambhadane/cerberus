from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from core.adapters import Endpoint, Observation, ObservationKind, register
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

    def version(self) -> str | None:
        if not self.is_available():
            return None
        try:
            proc = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=15)
            first = proc.stdout.strip().splitlines()[0] if proc.stdout.strip() else ""
            return first or None
        except (subprocess.SubprocessError, IndexError):
            return None

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
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT, check=False)
                xml = out.read_text() if out.exists() else ""
            except subprocess.TimeoutExpired:
                log.warning("nmap timed out after %ss", TIMEOUT)
                return []

        return self._parse(xml, scope)

    def _parse(self, xml: str, scope: Scope) -> list[Observation]:
        if not xml.strip():
            return []
        try:
            root = ET.fromstring(xml)
        except ET.ParseError as exc:
            log.warning("could not parse nmap output (%s)", exc)
            return []

        version = self.version()
        observations: list[Observation] = []
        for host in root.findall("host"):
            names = [h.get("name") for h in host.findall("hostnames/hostname") if h.get("name")]
            address = host.find("address")
            ip = address.get("addr") if address is not None else None
            hostname = names[0] if names else ip
            if hostname is None or not scope.permits_host(hostname):
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


register(NmapScanner())
