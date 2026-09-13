"""Scanner adapters. Importing this package registers every available adapter."""

from discovery.adapters import crtsh, http_probe, nmap_scan, nuclei, subfinder, tcp_connect

__all__ = ["crtsh", "http_probe", "nmap_scan", "nuclei", "subfinder", "tcp_connect"]
