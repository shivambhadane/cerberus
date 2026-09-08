# discovery

Asset discovery scanners and connectors — stage 1 of the pipeline.

Responsible for finding what an organization exposes to the internet: subdomain enumeration (subfinder, crt.sh), port/service scanning (nmap/masscan), technology fingerprinting (httpx), and vulnerability signature scanning (nuclei).

**Input:** a domain name
**Output:** a list of discovered assets (hosts, ports, services, technologies) handed to `ingestion/`.
