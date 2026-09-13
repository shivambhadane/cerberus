# discovery

Asset discovery scanners — stage 1 of the pipeline.

Finds what a domain exposes to the internet:

- [subdomains.py](subdomains.py) — certificate transparency logs via crt.sh, plus `subfinder` when it is on PATH, then DNS resolution
- [ports.py](ports.py) — asyncio TCP connect scan, rate-limited by `discovery.max_concurrency`
- [fingerprint.py](fingerprint.py) — product/version from HTTP `Server` headers, falling back to raw service banners
- [runner.py](runner.py) — orchestrates the three into `DiscoveredAsset` records

Runs in pure Python, so no Go toolchain or nmap install is required. Scanning is
non-destructive: connect-only probes and a single HTTP GET, never exploitation.

**Input:** a domain name
**Output:** `DiscoveredAsset(hostname, ip_address, port, protocol, technology)` handed to `ingestion/`.
