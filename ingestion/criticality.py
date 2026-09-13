from __future__ import annotations

import re

# Ordered most-specific first; the first match wins.
HOSTNAME_RULES: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"(^|[.\-])(dev|test|staging|stage|uat|sandbox|demo)([.\-]|$)"), "low",
     "hostname matches a non-production naming convention"),
    (re.compile(r"(^|[.\-])(admin|vpn|auth|sso|id|login|payments?|billing)([.\-]|$)"), "critical",
     "hostname indicates an authentication or payments system"),
    (re.compile(r"(^|[.\-])(api|prod|production|db|database|internal)([.\-]|$)"), "high",
     "hostname indicates a production or data-tier system"),
]

# Ports that expose management or data-tier services directly to the internet.
SENSITIVE_PORTS: dict[int, str] = {
    22: "SSH exposed", 23: "Telnet exposed", 445: "SMB exposed",
    1433: "MSSQL exposed", 3306: "MySQL exposed", 3389: "RDP exposed",
    5432: "PostgreSQL exposed", 6379: "Redis exposed",
    9200: "Elasticsearch exposed", 11211: "Memcached exposed",
    27017: "MongoDB exposed",
}


def infer_criticality(hostname: str, port: int) -> tuple[str, str]:
    """Heuristic asset criticality from naming convention and exposed service.

    Manual `asset_criticality` rows always override this (see ingestion.normalize).
    """
    host = hostname.lower()
    for pattern, level, reason in HOSTNAME_RULES:
        if pattern.search(host):
            if level == "low" and port in SENSITIVE_PORTS:
                return "medium", f"{reason}, but {SENSITIVE_PORTS[port].lower()}"
            return level, reason

    if port in SENSITIVE_PORTS:
        return "high", SENSITIVE_PORTS[port]
    return "medium", "no naming convention matched; default business criticality"
