# Cerberus — Roadmap

Tracks what's actually built vs. planned, grouped by phase. See [PRD](PRD.md) for what each v1 feature needs to satisfy, and the root [README Roadmap](../README.md#roadmap) for the condensed view.

## Phase 0 — Foundation

- [x] Problem statement, architecture, and design principles ([README](../README.md))
- [x] Product Requirements Document ([PRD.md](PRD.md))
- [x] API contract ([API.md](API.md))
- [x] Database schema ([DATABASE_SCHEMA.md](DATABASE_SCHEMA.md))
- [x] Rules of Engagement ([RULES_OF_ENGAGEMENT.md](RULES_OF_ENGAGEMENT.md))
- [x] Repo scaffold: module directories, `config.yaml`, `.env.example`, `docker-compose.yml`, `LICENSE`

## Phase 1 — MVP pipeline (build order)

Each item is a working slice, not just a stub — see [PRD §5](PRD.md#5-features-v1-scope-mapped-to-pipeline-stages) for acceptance criteria.

- [x] `discovery/`: subdomain enumeration (crt.sh, plus subfinder when installed) + async TCP port scan + technology fingerprinting from HTTP headers and service banners
- [x] `ingestion/`: normalize discovery output into the `assets` table, with dedupe on re-scan and heuristic criticality tagging
- [x] `enrichment/`: `scripts/refresh_enrichment.py` pulling CISA KEV + EPSS into `cve_enrichment`, and NVD CPE matching to turn a fingerprint into CVEs
- [x] `scoring/`: weighted risk score + reasoning string, per [config.yaml](../config.yaml) weights
- [x] `api/`: all documented endpoints wired to a real database, with bearer auth
- [x] CLI: `cerberus.py scan --target <domain> --authorized` running the full pipeline end-to-end
- [x] Test suite covering scoring, dedupe, criticality, matching, and the API

**Exit criterion — met.** A single command against a lab target produces a ranked top-10 list
with reasoning. In a verification run against a local lab host presenting `Apache/2.4.49`,
the top findings were `CVE-2021-41773` and `CVE-2021-42013` (KEV-listed path-traversal RCEs),
and `CVE-2023-44487` at CVSS **7.5** outranked `CVE-2021-44790` at CVSS **9.8** because only the
former is under active exploitation — the behaviour the whole product exists to produce.

## Phase 2 — Delivery & polish

- [ ] Dashboard (`frontend/`): ranked findings list + per-asset detail view
- [x] `GET /api/v1/assets`, `GET /api/v1/enrichment/status`, `PATCH /api/v1/findings/{id}` (status updates)
- [ ] Deployment guide (beyond local `docker compose up`)
- [ ] Demo script / one-pager for presenting the finished pipeline

## Phase 3 — Scale features (originally listed in README, deferred past v1 per [PRD §6](PRD.md#6-out-of-scope-for-v1))

- [ ] Cloud connector support (AWS/Azure/GCP asset inventory)
- [ ] Asset criticality tagging UI (replacing manual `asset_criticality` rows)
- [ ] Slack/Jira integration (`integrations/`)
- [ ] Multi-tenant support with row-level security
- [ ] Graph-based blast-radius analysis
- [ ] Learned scoring model (trained on confirmed-exploit outcomes)
- [ ] Public API for MSSP/partner use
