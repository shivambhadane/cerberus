"""Shared HTTP client with retry and backoff.

Every external source Cerberus depends on (crt.sh, NVD, CISA, FIRST) rate-limits or
occasionally fails. Without retries a single blip silently degrades a scan stage,
which matters more here than usual: a missed KEV lookup does not error, it just
quietly produces a wrong ranking.
"""

from __future__ import annotations

import logging

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger(__name__)

USER_AGENT = "cerberus-asm"
RETRY_STATUSES = (429, 500, 502, 503, 504)


def build_session(
    total_retries: int = 3,
    backoff_factor: float = 1.0,
    user_agent: str = USER_AGENT,
) -> requests.Session:
    retry = Retry(
        total=total_retries,
        connect=total_retries,
        read=total_retries,
        status=total_retries,
        status_forcelist=RETRY_STATUSES,
        allowed_methods=frozenset(["GET", "HEAD"]),
        backoff_factor=backoff_factor,
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=32)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"User-Agent": user_agent})
    return session
