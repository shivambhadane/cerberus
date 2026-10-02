# Cerberus — Rules of Engagement

This document defines what Cerberus is allowed to do, against what targets, and under what conditions. It exists because Cerberus performs **active reconnaissance** (port scanning, vulnerability probing via nuclei) as well as passive OSINT — and active scanning against a system you don't own or have authorization to test can violate computer misuse law (e.g. the CFAA in the US) regardless of intent. This is not boilerplate; treat it as binding for any use of this tool.

See also: [Legal & Ethical Use](../README.md#legal--ethical-use) in the root README.

## 1. Authorization is required before any scan

- Cerberus MUST NOT be run against a domain unless the operator has one of:
  1. Direct ownership of the target domain/infrastructure, or
  2. Written authorization from the target's owner (e.g. a signed pentest engagement letter, a bug bounty program's published scope, or a CTF/lab environment explicitly built for testing), or
  3. The target is a dedicated, intentionally vulnerable lab environment (e.g. a personal test VM, a CTF box) with no real-world stakeholder.
- **Through the API and dashboard**, authorization is *proven*, not asserted: a scan names a `domain_id` the caller has verified by publishing a DNS TXT record only someone who controls the domain's DNS could publish ([API](API.md#post-apiv1domainsidverify)). There is no `authorized: true` field to send. This raises the bar from "the operator says so" to "the operator demonstrated control of the DNS", which is what domain-validated certificates rest on.
- **On the CLI**, `--authorized` remains an operator attestation, **not** a verification mechanism. Passing the flag does not make a scan lawful — it only records that the operator claims authorization existed. The CLI is an operator tool, run by whoever controls the machine and the database.
- Neither mechanism verifies *legal* authorization. Control of DNS is not the same as permission from the organisation that owns the system, and a bug-bounty scope can exclude hosts you do control. Cerberus cannot judge that; you must.
- When in doubt about whether a target is in scope, do not scan it. Confirm scope in writing first.

## 2. Scope boundaries

- Scans are limited to the `target_domain` explicitly provided and its discovered subdomains. Cerberus does not pivot to out-of-scope domains, unrelated third-party infrastructure (e.g. shared CDNs, cloud provider control planes), or internal/private IP ranges discovered incidentally.
- **Known exception:** the dashboard's Test Labs screen deliberately lets a signed-in user add the
  built-in `127.0.0.1` Docker lab as a verified target. That scan is granted only the exact loopback
  address, never the RFC1918 ranges or the cloud metadata address — `core/scope.py`'s
  `allow_loopback_only`, narrower than a blanket private-address allowance (see
  [DEPLOYMENT.md §5](DEPLOYMENT.md#5-scanning-from-the-deployed-api)). On a shared deployment this
  still means any account can scan this server's loopback interface; it is accepted here because v1
  targets single-operator use ([PRD §3](PRD.md#3-non-goals-v1)).
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

## 4. Scan profiles

What a scanner may do is governed by a **scan profile** ([core/profiles.py](../core/profiles.py)),
not by whatever templates happen to be installed. Template selection is an allowlist: a
profile names the categories permitted, and anything unnamed does not run.

| Profile | Active probing | Severity | Opt-in |
|---|---|---|---|
| `passive` | None — certificate transparency and DNS only. The target is not contacted at all: no port scan, no service probe, no HTTP request | n/a | no |
| `safe` (default) | Known CVEs, exposed panels/files, misconfiguration, TLS | medium and above | no |
| `thorough` | Adds low/info severity, default-credential and unauth checks | all | **yes** |

Two categories are refused unconditionally and **no profile can enable them** — a profile
that tries is rejected when it is constructed, not when it runs:

- **Destructive tags:** `dos`, `ddos`, `fuzz`, `fuzzing`, `intrusive`, `brute-force`.
  These intentionally degrade the target or send large volumes of mutated input.
- **Local-execution protocols:** `code` and `file`. These run commands or read the local
  filesystem rather than probing the target, so they are not remote assessment at all.

These exclusions are passed to the scanner explicitly as well as being enforced by the
allowlist, because a single template can carry several tags and an allowed one must not
drag in a forbidden one. Template auto-update is disabled so the template set cannot
change underneath a scan.

`thorough` must be requested explicitly (`--accept-profile`, or `accept_profile: true` on
the API); asking for it without that is refused. The profile used is recorded on the scan
row, so every finding can be traced to the rules that permitted the request that found it.

For maximum control a profile can pin exact template IDs, in which case only those run.

## 5. Rate and impact limits

- Rate limit, concurrency, timeout and retry counts are part of the scan profile, so intensity is a declared property of the run rather than an implementation detail. The default (`safe`) is 20 requests/second at concurrency 10.
- Only one scan runs per tenant/target at a time (see [API §4, Rate Limiting](API.md#4-rate-limiting)) to avoid compounding load from overlapping runs.
- Scope is enforced in code ([core/scope.py](../core/scope.py)): hosts outside the authorized domain are refused, as are private, loopback and link-local addresses (including cloud metadata endpoints) unless a development scope explicitly permits them.
- Permitting private addresses (needed for the [Docker lab](../lab/README.md)) is a CLI flag (`--allow-private`) or operator configuration (`discovery.allow_private_addresses`) and is deliberately **not** an API parameter: a caller able to set it could point the server at its own internal network.
- A scanner's own account of *which host* a result belongs to is not trusted. nmap labels hosts by reverse-DNS (PTR) name, which is controlled by whoever owns the IP, so results are mapped back to the endpoints Cerberus asked about rather than to the name the tool reported.

### Public test targets

Level 2 testing uses `scanme.nmap.org`, whose operators authorize scanning "with Nmap or other
port scanners" and ask that it not be hammered. That grant covers **port and service discovery
only**. The public-target tests therefore never run nuclei, touch only ports 22 and 80, use low
concurrency, and are opt-in (`CERBERUS_PUBLIC_TESTS=1`). Do not point a vulnerability scanner at
a third-party host on the strength of a port-scanning grant.

## 6. Data handling for scan results

- Discovered assets and findings are stored only for the tenant that requested the scan (see [Database Schema](DATABASE_SCHEMA.md#3-table-reference)). Enrichment data (CVE/KEV/EPSS) is the only globally shared data, and it describes public vulnerabilities, not target-specific information.
- Scan results (hostnames, open ports, detected CVEs) should be treated as sensitive: they are effectively a map of a target's weaknesses. Do not share raw findings output outside the parties authorized to receive it.

## 7. If Cerberus finds something serious

- If a scan (run under proper authorization) surfaces a vulnerability with active real-world exploitation (KEV-listed, high EPSS), treat it as urgent regardless of where it falls in a backlog — that's the entire point of the ranking.
- If a scan against your own infrastructure or an authorized engagement surfaces evidence that a system may *already* be compromised (not just vulnerable), stop and escalate to the system owner/incident response immediately rather than continuing routine scanning.
- If you are testing under a bug bounty or third-party engagement and find something in scope, follow that program's disclosure process — Cerberus does not have its own disclosure channel; it's a detection and prioritization tool, not a reporting platform.

## 8. Operator responsibility

Running Cerberus against a target is the operator's decision and the operator's legal responsibility. This document describes the intended, authorized use of the tool; it does not grant permission to scan anything, and the maintainers are not responsible for use outside these boundaries (see [Disclaimer](../README.md#disclaimer)).
