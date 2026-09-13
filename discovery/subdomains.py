from __future__ import annotations

import json
import logging
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

import requests

log = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/"
CRTSH_TIMEOUT = 45


def from_crtsh(domain: str) -> set[str]:
    """Passive subdomain enumeration via certificate transparency logs."""
    try:
        resp = requests.get(
            CRTSH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=CRTSH_TIMEOUT,
            headers={"User-Agent": "cerberus-asm"},
        )
        resp.raise_for_status()
        rows = resp.json()
    except (requests.RequestException, json.JSONDecodeError) as exc:
        log.warning("crt.sh lookup failed (%s); continuing without CT data", exc)
        return set()

    names: set[str] = set()
    for row in rows:
        for name in (row.get("name_value") or "").splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith(domain):
                names.add(name)
    return names


def from_subfinder(domain: str) -> set[str]:
    """Use subfinder when it is installed; silently skipped otherwise."""
    if not shutil.which("subfinder"):
        return set()
    try:
        proc = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            timeout=180,
        )
    except subprocess.TimeoutExpired:
        log.warning("subfinder timed out for %s", domain)
        return set()
    return {line.strip().lower() for line in proc.stdout.splitlines() if line.strip()}


def resolve(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def enumerate_subdomains(domain: str, enabled: bool = True) -> dict[str, str]:
    """Return {hostname: ip} for every resolvable name found."""
    candidates = {domain, f"www.{domain}"}
    if enabled:
        candidates |= from_crtsh(domain)
        candidates |= from_subfinder(domain)

    with ThreadPoolExecutor(max_workers=32) as pool:
        resolved = list(pool.map(resolve, candidates))

    hosts = {name: ip for name, ip in zip(candidates, resolved, strict=True) if ip}
    log.info("resolved %d/%d candidate hostnames for %s", len(hosts), len(candidates), domain)
    return hosts
