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

- [ ] `discovery/`: subdomain enumeration (subfinder + crt.sh) + port scan (nmap) + tech fingerprinting (httpx) against a single target domain
- [ ] `ingestion/`: normalize discovery output into the `assets` table, with dedupe on re-scan
- [ ] `enrichment/`: `scripts/refresh_enrichment.py` pulling NVD + CISA KEV + EPSS into `cve_enrichment`
- [ ] `scoring/`: weighted risk score + reasoning string, per [config.yaml](../config.yaml) weights
- [ ] `api/`: `POST /api/v1/scans`, `GET /api/v1/findings`, `GET /api/v1/findings/{id}` wired to a real database
- [ ] CLI: `cerberus scan --target <domain> --authorized` running the full pipeline end-to-end

**Exit criterion:** a single command against a lab/CTF target produces a ranked top-10 list with reasoning, matching the [PRD success metric](PRD.md#8-success-metrics-for-a-portfoliodemo-context).

## Phase 2 — Delivery & polish

- [ ] Dashboard (`frontend/`): ranked findings list + per-asset detail view
- [ ] `GET /api/v1/assets`, `GET /api/v1/enrichment/status`, `PATCH /api/v1/findings/{id}` (status updates)
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
