from __future__ import annotations

import logging
import re
import socket

import requests

log = logging.getLogger(__name__)

HTTP_PORTS = {80, 8000, 8080, 8888, 3000, 5601, 9200}
HTTPS_PORTS = {443, 8443}

# Banner patterns for common non-HTTP services, mapped to a product token.
BANNER_PATTERNS = [
    (re.compile(rb"SSH-\d+\.\d+-OpenSSH[_-]([\w.]+)", re.I), "openssh"),
    (re.compile(rb"220[- ].*?ProFTPD ([\d.]+)", re.I), "proftpd"),
    (re.compile(rb"220[- ].*?vsFTPd ([\d.]+)", re.I), "vsftpd"),
    (re.compile(rb"220[- ].*?Postfix", re.I), "postfix"),
    (re.compile(rb"-ERR|^\+PONG|redis_version:([\d.]+)", re.I), "redis"),
    (re.compile(rb"([\d.]+)-MariaDB", re.I), "mariadb"),
    (re.compile(rb"\x0a([\d.]+)\x00", re.I), "mysql"),
]

SERVER_HEADER_RE = re.compile(r"^([A-Za-z][\w\-. ]*?)[/ ]?v?([\d][\d.]*)?$")


def _normalize_server(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    # "nginx/1.24.0 (Ubuntu)" -> "nginx/1.24.0"
    value = value.split("(")[0].strip()
    primary = value.split()[0] if value.split() else value
    return primary or None


def fingerprint_http(host: str, port: int, timeout: float = 5.0) -> str | None:
    scheme = "https" if port in HTTPS_PORTS else "http"
    url = f"{scheme}://{host}:{port}/"
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": "cerberus-asm"},
        )
    except requests.RequestException:
        return None

    server = resp.headers.get("Server")
    if server:
        return _normalize_server(server)
    powered = resp.headers.get("X-Powered-By")
    if powered:
        return _normalize_server(powered)
    return None


def grab_banner(host: str, port: int, timeout: float = 4.0) -> str | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                data = sock.recv(256)
            except TimeoutError:
                sock.sendall(b"\r\n")
                data = sock.recv(256)
    except OSError:
        return None

    if not data:
        return None
    for pattern, product in BANNER_PATTERNS:
        match = pattern.search(data)
        if match:
            version = match.group(1).decode(errors="ignore") if match.groups() and match.group(1) else None
            return f"{product}/{version}" if version else product
    return None


def fingerprint(host: str, port: int) -> str | None:
    """Identify the product/version serving a port, HTTP first then raw banner."""
    if port in HTTP_PORTS or port in HTTPS_PORTS:
        tech = fingerprint_http(host, port)
        if tech:
            return tech
    return grab_banner(host, port)
