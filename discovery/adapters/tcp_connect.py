from __future__ import annotations

import asyncio
import logging

from core.adapters import Endpoint, Observation, ObservationKind, register
from core.scope import Scope

log = logging.getLogger(__name__)

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    465, 587, 993, 995, 1433, 3000, 3306, 3389, 5432, 5601,
    6379, 8000, 8080, 8443, 8888, 9200, 11211, 27017,
]


class TcpConnectScanner:
    """Pure-Python TCP connect scan. Non-destructive: it opens and closes, nothing more."""

    name = "tcp_connect"
    kind = ObservationKind.OPEN_PORT

    def __init__(self, ports: list[int] | None = None, timeout: float = 2.0, concurrency: int = 50):
        self.ports = ports or DEFAULT_PORTS
        self.timeout = timeout
        self.concurrency = concurrency

    def is_available(self) -> bool:
        return True

    def version(self) -> str | None:
        return None

    async def _probe(self, host: str, port: int, sem: asyncio.Semaphore) -> int | None:
        async with sem:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), self.timeout
                )
            except (OSError, TimeoutError):
                return None
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            return port

    async def _scan(self, endpoints: list[Endpoint], scope: Scope) -> list[Observation]:
        sem = asyncio.Semaphore(self.concurrency)
        ports = [p for p in self.ports if scope.permits_port(p)]
        jobs, meta = [], []
        for endpoint in endpoints:
            if not scope.permits_host(endpoint.hostname):
                continue
            for port in ports:
                jobs.append(self._probe(endpoint.hostname, port, sem))
                meta.append((endpoint, port))

        results = await asyncio.gather(*jobs)
        observations = []
        for (endpoint, port), found in zip(meta, results, strict=True):
            if found is None:
                continue
            observations.append(
                Observation(
                    kind=self.kind,
                    target=f"{endpoint.hostname}:{port}",
                    source_tool=self.name,
                    data={
                        "hostname": endpoint.hostname,
                        "ip_address": endpoint.ip_address,
                        "port": port,
                        "protocol": "tcp",
                    },
                )
            )
        return observations

    def run(self, endpoints: list[Endpoint], scope: Scope) -> list[Observation]:
        observations = asyncio.run(self._scan(endpoints, scope))
        log.info("tcp_connect: %d open ports across %d hosts", len(observations), len(endpoints))
        return observations


register(TcpConnectScanner())
