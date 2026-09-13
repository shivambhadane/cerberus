# Cerberus — Rules of Engagement

This document defines what Cerberus is allowed to do, against what targets, and under what conditions. It exists because Cerberus performs **active reconnaissance** (port scanning, vulnerability probing via nuclei) as well as passive OSINT — and active scanning against a system you don't own or have authorization to test can violate computer misuse law (e.g. the CFAA in the US) regardless of intent. This is not boilerplate; treat it as binding for any use of this tool.

See also: [Legal & Ethical Use](../README.md#legal--ethical-use) in the root README.

## 1. Authorization is required before any scan

- Cerberus MUST NOT be run against a domain unless the operator has one of:
  1. Direct ownership of the target domain/infrastructure, or
  2. Written authorization from the target's owner (e.g. a signed pentest engagement letter, a bug bounty program's published scope, or a CTF/lab environment explicitly built for testing), or
  3. The target is a dedicated, intentionally vulnerable lab environment (e.g. a personal test VM, a CTF box) with no real-world stakeholder.
- The `--authorized` flag (CLI) and `authorized: true` field ([API](API.md#post-apiv1scans)) are an operator attestation, **not** a verification mechanism. Passing the flag does not make a scan lawful — it only records that the operator claims authorization existed. Cerberus does not, and cannot, verify legal authorization on its own.
- When in doubt about whether a target is in scope, do not scan it. Confirm scope in writing first.

## 2. Scope boundaries

- Scans are limited to the `target_domain` explicitly provided and its discovered subdomains. Cerberus does not pivot to out-of-scope domains, unrelated third-party infrastructure (e.g. shared CDNs, cloud provider control planes), or internal/private IP ranges discovered incidentally.
- If a bug bounty or engagement scope document exists, its exclusions (specific hosts, IP ranges, or testing windows) take precedence over what Cerberus technically has permission to reach.
- Cerberus is built for **external attack surface** only. It is not intended to scan internal/on-prem networks (see [PRD §3, Non-Goals](PRD.md#3-non-goals-v1)).

## 3. What Cerberus will and will not do

**Will do:**
- Passive OSINT: subdomain enumeration via certificate transparency logs (crt.sh), public DNS records.
- Active but non-destructive reconnaissance: port/service scanning (nmap/masscan), technology fingerprinting (httpx), and vulnerability *detection* signatures (nuclei) that identify a weakness without exploiting it.

**Will not do:**
- Exploit a discovered vulnerability to gain access, execute code, exfiltrate data, or modify a target system. Cerberus reports what *could* be exploited, based on public exploit/KEV/EPSS data — it does not exploit anything itself.
- Perform denial-of-service or load-generating actions (no aggressive scan rates against fragile targets, no intentional resource exhaustion).
- Scan ranges or targets not explicitly provided by the operator.

## 4. Rate and impact limits

- Port scans and nuclei runs use conservative default rate limits to avoid degrading the target's service. Operators should not override these defaults against production systems without the target owner's explicit sign-off on scan intensity.
- Only one scan runs per tenant/target at a time (see [API §4, Rate Limiting](API.md#4-rate-limiting)) to avoid compounding load from overlapping runs.

## 5. Data handling for scan results

- Discovered assets and findings are stored only for the tenant that requested the scan (see [Database Schema](DATABASE_SCHEMA.md#3-table-reference)). Enrichment data (CVE/KEV/EPSS) is the only globally shared data, and it describes public vulnerabilities, not target-specific information.
- Scan results (hostnames, open ports, detected CVEs) should be treated as sensitive: they are effectively a map of a target's weaknesses. Do not share raw findings output outside the parties authorized to receive it.

## 6. If Cerberus finds something serious

- If a scan (run under proper authorization) surfaces a vulnerability with active real-world exploitation (KEV-listed, high EPSS), treat it as urgent regardless of where it falls in a backlog — that's the entire point of the ranking.
- If a scan against your own infrastructure or an authorized engagement surfaces evidence that a system may *already* be compromised (not just vulnerable), stop and escalate to the system owner/incident response immediately rather than continuing routine scanning.
- If you are testing under a bug bounty or third-party engagement and find something in scope, follow that program's disclosure process — Cerberus does not have its own disclosure channel; it's a detection and prioritization tool, not a reporting platform.

## 7. Operator responsibility

Running Cerberus against a target is the operator's decision and the operator's legal responsibility. This document describes the intended, authorized use of the tool; it does not grant permission to scan anything, and the maintainers are not responsible for use outside these boundaries (see [Disclaimer](../README.md#disclaimer)).
