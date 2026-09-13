from __future__ import annotations

import logging
import shutil
import subprocess

from core.adapters import Observation, ObservationKind, register
from core.scope import Scope
from discovery.adapters.crtsh import resolve

log = logging.getLogger(__name__)

TIMEOUT = 180


class SubfinderScanner:
    """Subdomain enumeration via projectdiscovery/subfinder, when installed."""

    name = "subfinder"
    kind = ObservationKind.SUBDOMAIN

    def is_available(self) -> bool:
        return shutil.which("subfinder") is not None

    def version(self) -> str | None:
        if not self.is_available():
            return None
        try:
            proc = subprocess.run(
                ["subfinder", "-version"], capture_output=True, text=True, timeout=15
            )
            output = (proc.stdout + proc.stderr).strip()
            return output.splitlines()[-1] if output else None
        except (subprocess.SubprocessError, IndexError):
            return None

    def run(self, scope: Scope) -> list[Observation]:
        try:
            proc = subprocess.run(
                ["subfinder", "-d", scope.domain, "-silent"],
                capture_output=True,
                text=True,
                timeout=TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            log.warning("subfinder timed out for %s", scope.domain)
            return []

        version = self.version()
        observations = []
        for line in proc.stdout.splitlines():
            hostname = line.strip().lower()
            if not hostname or not scope.permits_host(hostname):
                continue
            ip = resolve(hostname)
            if ip is None or not scope.permits_address(ip):
                continue
            observations.append(
                Observation(
                    kind=self.kind,
                    target=hostname,
                    source_tool=self.name,
                    source_version=version,
                    data={"hostname": hostname, "ip_address": ip},
                    raw=line.strip(),
                )
            )
        log.info("subfinder: %d in-scope hosts", len(observations))
        return observations


register(SubfinderScanner())
