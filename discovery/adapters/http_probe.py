from __future__ import annotations

import logging
import re
import socket
import warnings

import requests

from core.adapters import Endpoint, Observation, ObservationKind, register
from core.http import build_session
from core.scope import Scope

log = logging.getLogger(__name__)

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

HTTP_PORTS = {80, 8000, 8080, 8888, 3000, 5601, 9200, 18081, 18082}
HTTPS_PORTS = {443, 8443}

BANNER_PATTERNS = [
    (re.compile(rb"SSH-\d+\.\d+-OpenSSH[_-]([\w.]+)", re.I), "openssh"),
    (re.compile(rb"220[- ].*?ProFTPD ([\d.]+)", re.I), "proftpd"),
    (re.compile(rb"220[- ].*?vsFTPd ([\d.]+)", re.I), "vsftpd"),
    (re.compile(rb"220[- ].*?Postfix", re.I), "postfix"),
    (re.compile(rb"redis_version:([\d.]+)", re.I), "redis"),
    (re.compile(rb"([\d.]+)-MariaDB", re.I), "mariadb"),
]


class HttpProbe:
    """Identify the product and version serving a port.

    Tries HTTP response headers first, then a raw banner read. Superseded by nmap's
    -sV output when nmap is available; this keeps fingerprinting working without it.
    """

    name = "http_probe"
    kind = ObservationKind.TECHNOLOGY

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self._session = build_session(total_retries=1)

    def is_available(self) -> bool:
        return True

    def version(self) -> str | None:
        return None

    def _http(self, endpoint: Endpoint) -> tuple[str | None, str | None]:
        scheme = "https" if endpoint.port in HTTPS_PORTS else "http"
        url = f"{scheme}://{endpoint.hostname}:{endpoint.port}/"
        try:
            resp = self._session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
        except requests.RequestException:
            return None, None

        header = resp.headers.get("Server") or resp.headers.get("X-Powered-By")
        if not header:
            return None, None
        technology = header.split("(")[0].strip().split()[0]
        return technology or None, f"Server: {header}"

    def _banner(self, endpoint: Endpoint) -> tuple[str | None, str | None]:
        try:
            with socket.create_connection((endpoint.hostname, endpoint.port), timeout=4.0) as sock:
                sock.settimeout(4.0)
                try:
                    data = sock.recv(256)
                except TimeoutError:
                    sock.sendall(b"\r\n")
                    data = sock.recv(256)
        except OSError:
            return None, None

        if not data:
            return None, None
        for pattern, product in BANNER_PATTERNS:
            match = pattern.search(data)
            if match:
                ver = match.group(1).decode(errors="ignore") if match.groups() else None
                return (f"{product}/{ver}" if ver else product), data[:200].decode(errors="replace")
        return None, data[:200].decode(errors="replace")

    def run(self, endpoints: list[Endpoint], scope: Scope) -> list[Observation]:
        observations = []
        for endpoint in endpoints:
            if endpoint.port is None or not scope.permits_host(endpoint.hostname):
                continue

            technology = raw = None
            if endpoint.port in HTTP_PORTS or endpoint.port in HTTPS_PORTS:
                technology, raw = self._http(endpoint)
            if technology is None:
                technology, raw = self._banner(endpoint)
            if technology is None:
                continue

            observations.append(
                Observation(
                    kind=self.kind,
                    target=str(endpoint),
                    source_tool=self.name,
                    data={
                        "hostname": endpoint.hostname,
                        "port": endpoint.port,
                        "technology": technology,
                    },
                    raw=raw,
                )
            )
        log.info("http_probe: fingerprinted %d of %d endpoints", len(observations), len(endpoints))
        return observations


register(HttpProbe())
