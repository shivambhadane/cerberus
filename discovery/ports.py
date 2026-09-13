from __future__ import annotations

import asyncio
import logging

log = logging.getLogger(__name__)

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    465, 587, 993, 995, 1433, 3000, 3306, 3389, 5432, 5601,
    6379, 8000, 8080, 8443, 8888, 9200, 11211, 27017,
]


async def _probe(host: str, port: int, timeout: float, sem: asyncio.Semaphore) -> int | None:
    async with sem:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        except (TimeoutError, OSError):
            return None
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return port


async def _scan_host(host: str, ports: list[int], timeout: float, sem: asyncio.Semaphore) -> list[int]:
    results = await asyncio.gather(*(_probe(host, p, timeout, sem) for p in ports))
    return sorted(p for p in results if p is not None)


async def scan_hosts(
    hosts: list[str],
    ports: list[int] | None = None,
    timeout: float = 2.0,
    concurrency: int = 50,
) -> dict[str, list[int]]:
    """TCP connect scan. Non-destructive and rate-limited by `concurrency`."""
    ports = ports or DEFAULT_PORTS
    sem = asyncio.Semaphore(concurrency)
    scans = await asyncio.gather(*(_scan_host(h, ports, timeout, sem) for h in hosts))
    return dict(zip(hosts, scans, strict=True))


def scan(
    hosts: list[str],
    ports: list[int] | None = None,
    timeout: float = 2.0,
    concurrency: int = 50,
) -> dict[str, list[int]]:
    return asyncio.run(scan_hosts(hosts, ports, timeout, concurrency))
