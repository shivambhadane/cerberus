# Cerberus — Product Requirements Document

**Status:** Draft v1
**Owner:** Shivam Bhadane

## 1. Summary

Cerberus is a continuous attack surface and exploitability intelligence tool. Given a domain, it discovers internet-facing assets, finds vulnerabilities on them, enriches those vulnerabilities with real-world exploitation data (CISA KEV, EPSS), and produces a ranked, explainable list of what to fix first — prioritized by actual attacker behavior, not raw CVSS severity.

Full problem framing and architecture live in the [root README](../README.md); this document defines *what gets built, in what order, and what is explicitly out of scope*.

## 2. Goals

- G1: Given a single domain, produce a ranked list of exploitable exposures with a plain-English reason for each ranking.
- G2: Make severity ranking reflect real-world exploitation likelihood (KEV + EPSS), not just CVSS.
- G3: Keep every pipeline stage independently testable and replaceable (per the [design principles](../README.md#design-principles)).
- G4: Run end-to-end on free, open data sources with no required paid API keys.

## 3. Non-Goals (v1)

- Not building exploit/weaponization tooling — detection and prioritization only ([Legal & Ethical Use](../README.md#legal--ethical-use)).
- Not supporting internal/on-prem network scanning — external attack surface only.
- Not building a learned/ML scoring model — v1 uses a hand-tuned weighted formula (see [scoring.weights](../config.yaml)).
- Not multi-tenant SaaS with billing — single-operator or lab use for v1.
- Not real-time continuous monitoring — scheduled/on-demand scans only (`scan_interval_hours`).

## 4. Target Users

| Persona | Need |
|---|---|
| Security analyst / small security team | "What should I patch this week, out of everything my scanners flagged?" |
| Student / portfolio reviewer | A working, well-documented example of a full attack-surface-management pipeline |
| Bug bounty / pentest researcher (authorized engagements only) | Fast recon-to-priority workflow against an in-scope target |

## 5. Features (v1 scope, mapped to pipeline stages)

### 5.1 Asset Discovery
- Subdomain enumeration via subfinder + crt.sh
- Port/service scan via nmap or masscan
- Tech fingerprinting via httpx
- **Acceptance:** given a domain, produces a deduplicated list of `host:port` assets with detected technologies.

### 5.2 Ingestion & Normalization
- Normalize discovery output into the shared asset/finding data model (see [Database Schema Document](DATABASE_SCHEMA.md))
- Deduplicate against previously seen assets on re-scan
- **Acceptance:** re-running a scan on an unchanged target does not create duplicate asset rows.

### 5.3 Enrichment
- Pull and cache NVD, CISA KEV, EPSS, OSV data globally (not per-scan)
- Join enrichment data onto findings by CVE ID
- **Acceptance:** a finding referencing a KEV-listed CVE is flagged `kev_listed: true` without a live lookup at scoring time.

### 5.4 Exploitability Scoring
- Weighted formula combining KEV status, EPSS score, asset criticality, exposure context
- Every score ships with a `reasoning` string
- **Acceptance:** two findings with identical CVSS but different KEV/EPSS status receive different `risk_score` values, and the reasoning explains why.

### 5.5 Delivery
- REST API (see [API Documentation](API.md))
- Dashboard: ranked findings list, per-asset detail
- Manual scan trigger via CLI
- **Acceptance:** `cerberus report --top 10` and `GET /api/v1/findings?sort=risk_score` return the same ranking.

## 6. Out of Scope for v1 (tracked in [Roadmap](../README.md#roadmap))

- Cloud connector support (AWS/Azure/GCP asset inventory)
- Slack/Jira integration
- Multi-tenant row-level security
- Graph-based blast-radius analysis
- Learned scoring model

## 7. Constraints & Assumptions

- All scans require the `--authorized` flag; Cerberus assumes the operator has verified authorization out-of-band (see [Rules of Engagement](RULES_OF_ENGAGEMENT.md)). Cerberus does not verify ownership itself in v1.
- Enrichment sources are rate-limited (notably NVD without an API key); refresh cadence is daily by default.
- No paid data source is required to exercise any v1 feature.

## 8. Success Metrics (for a portfolio/demo context)

- End-to-end run against a lab/CTF-style target completes and produces a ranked top-10 list with reasoning.
- A reviewer can read [README.md](../README.md) → [PRD.md](PRD.md) → [API.md](API.md) → [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md) and understand the full system without reading code.

## 9. Open Questions

- Which asset criticality tagging model ships first — manual tagging UI, or a naming-convention heuristic (e.g. `prod-*` vs `test-*`)?
- Does v1 need scan history/diffing, or is each scan a fresh snapshot?
