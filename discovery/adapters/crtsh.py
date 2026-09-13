from __future__ import annotations

import json
import logging
import socket
from concurrent.futures import ThreadPoolExecutor

import requests

from core.adapters import Observation, ObservationKind, register
from core.http import build_session
from core.scope import Scope

log = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/"
TIMEOUT = 45


def resolve(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


class CrtShScanner:
    """Passive subdomain enumeration from certificate transparency logs."""

    name = "crtsh"
    kind = ObservationKind.SUBDOMAIN

    def __init__(self) -> None:
        self._session = build_session()

    def is_available(self) -> bool:
        return True

    def version(self) -> str | None:
        return None  # public service, unversioned

    def _candidates(self, scope: Scope) -> set[str]:
        try:
            resp = self._session.get(
                CRTSH_URL,
                params={"q": f"%.{scope.domain}", "output": "json"},
                timeout=TIMEOUT,
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
                if name and scope.permits_host(name):
                    names.add(name)
        return names

    def run(self, scope: Scope) -> list[Observation]:
        candidates = {scope.domain, f"www.{scope.domain}"} | self._candidates(scope)
        candidates = {c for c in candidates if scope.permits_host(c)}

        with ThreadPoolExecutor(max_workers=32) as pool:
            resolved = list(pool.map(resolve, candidates))

        observations = []
        for hostname, ip in zip(candidates, resolved, strict=True):
            if ip is None or not scope.permits_address(ip):
                continue
            observations.append(
                Observation(
                    kind=self.kind,
                    target=hostname,
                    source_tool=self.name,
                    data={"hostname": hostname, "ip_address": ip},
                )
            )
        log.info("crtsh: %d in-scope hosts resolved from %d candidates",
                 len(observations), len(candidates))
        return observations


register(CrtShScanner())
