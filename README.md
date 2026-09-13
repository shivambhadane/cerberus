# Cerberus

**Continuous Attack Surface & Exploitability Intelligence**

Cerberus discovers everything an organization exposes to the internet, correlates it against real-world vulnerability, exploit, and threat-intelligence data, and tells you which weaknesses attackers are actually most likely to exploit — not just which ones have the scariest score.

Three heads, one job: see everything, know what's dangerous, tell you what to fix first.

## Table of Contents
- [Documentation](#documentation)
- [Problem Statement](#problem-statement)
- [What Cerberus Does](#what-cerberus-does)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Data Sources](#data-sources)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Roadmap](#roadmap)
- [Legal & Ethical Use](#legal--ethical-use)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

## Documentation

| Document | Purpose |
|---|---|
| [PRD](docs/PRD.md) | What's in/out of scope for v1, feature acceptance criteria |
| [API Documentation](docs/API.md) | Every endpoint, request/response shape, auth |
| [Database Schema](docs/DATABASE_SCHEMA.md) | Tables, relationships, and why they're designed that way |
| [Rules of Engagement](docs/RULES_OF_ENGAGEMENT.md) | What Cerberus is allowed to scan, and how |
| [Roadmap](docs/ROADMAP.md) | What's built vs. planned, by phase, with exit criteria |

## Problem Statement

Every organization with an internet presence faces three compounding problems:

1. **Unknown exposure.** Cloud servers get spun up and forgotten. Test environments stay online. Shadow IT exists outside any inventory. Security teams routinely don't know the full extent of what they expose to the internet — and you cannot defend what you don't know exists.
2. **Alert overload.** Traditional vulnerability scanners report volume, not priority. A scan can return thousands of findings, but a security team can typically only act on a handful per week. Nobody can fix everything, and generic severity scores (CVSS) don't tell you where to start.
3. **Severity ≠ real-world danger.** A vulnerability rated 9.8/10 in theoretical severity might never be touched by an actual attacker. A vulnerability rated 6.5/10 might be under active, mass exploitation by ransomware groups right now. Static severity scores don't capture what's actually happening in the wild, so teams often patch the wrong things first.

Net result: organizations spend limited security engineering time patching low-risk issues while genuinely dangerous, actively-exploited weaknesses sit open.

## What Cerberus Does

Cerberus closes that gap by combining four types of data that are normally siloed in separate tools:

| Data type | What it tells you |
|---|---|
| Asset data | What you actually expose to the internet |
| Vulnerability data | What's technically wrong with each asset |
| Exploit & threat intelligence | Whether attackers are actively using that weakness right now |
| Asset criticality | Whether the affected system is a crown jewel or a forgotten test box |

Cerberus fuses these into a single, continuously-updated, ranked list:

> "Here are the top 10 things attackers are most likely to exploit against you today, ranked, with the reasoning behind each ranking."

## How It Works

**Input → Output, in one line**

Input: a domain name (e.g. `example.com`)
Output: a ranked, explainable list of exploitable exposures

**Pipeline stages**

```
1. Asset Discovery        → what do you expose?
2. Vulnerability Scanning → what's wrong with it?
3. Enrichment              → is it actively exploited in the wild?
4. Exploitability Scoring  → how dangerous is this, for YOU specifically?
5. Delivery                → dashboard, API, Slack/Jira alerts
```

Each stage takes a clearly-typed input and produces a clearly-typed output, so the system can be reasoned about, tested, and extended one stage at a time.

## Architecture

```
                    ┌────────────────────────┐
                    │   1. Asset Discovery    │
                    │  (external recon, cloud │
                    │   connectors, DNS/CT)   │
                    └───────────┬─────────────┘
                                │
                    ┌───────────▼─────────────┐
                    │ 2. Ingestion &           │
                    │    Normalization         │
                    │  (common asset/finding   │
                    │   data model, dedupe)    │
                    └───────────┬─────────────┘
                                │
                    ┌───────────▼─────────────┐
                    │ 3. Enrichment            │
                    │  (CVE, KEV, EPSS,        │
                    │   exploit intel)         │
                    └───────────┬─────────────┘
                                │
                    ┌───────────▼─────────────┐
                    │ 4. Exploitability        │
                    │    Scoring Engine        │
                    │  (risk graph + ranking)  │
                    └───────────┬─────────────┘
                                │
                    ┌───────────▼─────────────┐
                    │ 5. API, Dashboard &      │
                    │    Integrations          │
                    │  (Slack, Jira, REST API) │
                    └──────────────────────────┘

               ┌───────────────────────────────┐
               │         Storage Layer          │
               │  Postgres · Redis · (Graph DB  │
               │  optional, for blast-radius    │
               │  queries at scale)             │
               └───────────────────────────────┘
```

### Design principles

- **Each stage is independently replaceable.** The scoring engine can evolve from a hand-tuned formula to a learned model without touching discovery or ingestion code.
- **Enrichment data is global, not tenant-scoped.** CVE/KEV/EPSS data is the same for everyone; it's cached once and reused, not re-fetched per scan.
- **Everything is explainable.** Every risk score ships with the reasoning behind it — not just a number, so a human can trust and act on it.

## Tech Stack

**In v1 today:**

| Layer | Technology |
|---|---|
| Discovery | Pure-Python CT log + DNS enumeration, async TCP connect scan, HTTP/banner fingerprinting (`subfinder` used when installed) |
| Backend / API | Python 3.11+, FastAPI |
| Database | PostgreSQL, or SQLite for zero-setup local runs (SQLAlchemy 2.x) |
| Scoring | Python module, importable and independently deployable |
| Deployment | Docker Compose (Postgres + API) |

**Planned (see [Roadmap](docs/ROADMAP.md)):** Redis Streams then Kafka for the async
worker queue, React/Next.js dashboard, Neo4j for blast-radius analysis, Kubernetes for
production deployment.

## Data Sources

Cerberus is built to run entirely on free, open data. No paid API keys are required to get a fully working instance.

| Source | Provides | Used in v1 | Cost |
|---|---|---|---|
| NVD | CVE records, CVSS scores, CPE matching | Yes | Free (API key recommended for higher rate limits) |
| CISA KEV | Confirmed actively-exploited CVEs | Yes | Free |
| EPSS (FIRST.org) | Probability of exploitation in the next 30 days | Yes | Free |
| crt.sh | Certificate transparency logs (subdomain discovery) | Yes | Free |
| NVD reference tags | Public proof-of-concept exploit signal | Yes | Free |
| OSV.dev | Open-source package vulnerabilities | Not yet - needs dependency scanning | Free |
| Nuclei templates | Community-maintained detection signatures | Not yet | Free |

Optional paid upgrades (not required to run Cerberus): Shodan/Censys (internet-wide asset lookups), GreyNoise (live exploitation telemetry), VulnCheck/Recorded Future (premium threat intelligence).

## Getting Started

### Prerequisites

- Python 3.11+
- Docker & Docker Compose (optional - only for running Postgres and the API in containers)
- `subfinder` (optional - Cerberus uses certificate transparency logs when it is absent)

Discovery runs in pure Python, so no Go toolchain is required to scan.

### Installation

```bash
# Clone the repository
git clone https://github.com/shivambhadane/cerberus.git
cd cerberus

# Install Python dependencies
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Optional: configure a Postgres URL and an NVD API key.
# Without a .env, Cerberus uses a local SQLite database and the anonymous
# NVD rate limit (5 requests/30s, which makes scans slower but still works).
cp .env.example .env

# Create the database schema
python scripts/init_db.py

# Pull the latest enrichment data (CISA KEV + EPSS, ~1700 CVEs)
python scripts/refresh_enrichment.py
```

> **Run the enrichment refresh before your first scan.** Without it, every finding is
> scored as if it were *not* actively exploited, which inverts the ranking Cerberus
> exists to produce. Scans warn loudly when the cache is empty or stale.

To run against Postgres and serve the API in containers instead:

```bash
docker compose up -d          # postgres + api on :8000
```

### Quick test run

```bash
# Scan a target you own or are authorized to test
python cerberus.py scan --target example.com --authorized

# Inspect the ranked results at any time
python cerberus.py report --top 10
python cerberus.py status
```

`--authorized` is a required flag confirming you have permission to scan the target;
without it the scan is refused. See [Rules of Engagement](docs/RULES_OF_ENGAGEMENT.md).

### Running the API

```bash
uvicorn api.main:app --reload          # http://localhost:8000/docs
```

All endpoints except `/healthz` require `Authorization: Bearer $API_SECRET_KEY`.

### Running the tests

```bash
pytest -q
```

## Configuration

Cerberus is configured via `.env` and `config.yaml`:

```yaml
# config.yaml
discovery:
  subdomain_enum: true
  port_scan: true
  scan_interval_hours: 24

enrichment:
  refresh_interval_hours: 24
  sources:
    - nvd
    - kev
    - epss
    - osv

scoring:
  weights:
    kev_status: 0.35
    epss_score: 0.25
    asset_criticality: 0.25
    exposure_context: 0.15

integrations:
  slack_webhook_url: ""
  jira:
    enabled: false
```

## Usage

### CLI

```bash
# Run full discovery + scan + score pipeline
cerberus scan --target example.com --authorized

# Re-run enrichment only (refresh KEV/EPSS/CVE data)
cerberus enrich --refresh

# View top-ranked findings
cerberus report --top 10
```

### API

```bash
# Get ranked findings for a tenant
GET /api/v1/findings?tenant_id=abc123&sort=risk_score&limit=10

# Get full detail + reasoning for one finding
GET /api/v1/findings/{finding_id}
```

### Example finding output

```json
{
  "asset": "api.example.com:443",
  "cve_id": "CVE-2021-41773",
  "cvss_score": 9.8,
  "kev_listed": true,
  "epss_score": 0.99992,
  "asset_criticality": "high",
  "risk_score": 89.6,
  "status": "open",
  "reasoning": "Actively exploited (CISA KEV, added 2021-11-03); 100% predicted exploitation probability (EPSS); high-criticality asset (hostname indicates a production or data-tier system); internet-facing web service on port 443, critical severity (CVSS 9.8)."
}

Ranking is driven by exploitation, not severity. In a real run against a lab target,
`CVE-2023-44487` (CVSS **7.5**, KEV-listed) scored **83.4**, while `CVE-2021-44790`
(CVSS **9.8**, no known exploitation) scored **63.3** - the lower-severity flaw ranks
higher because attackers are actually using it.
```

## Project Structure

```
cerberus/
├── core/                 # Config, database session, ORM models, pipeline orchestration
├── discovery/            # Subdomain enum, port scanning, technology fingerprinting
├── ingestion/            # Normalization, dedupe, asset criticality tagging
├── enrichment/           # CVE/KEV/EPSS pullers, cache, and technology->CVE matching
├── scoring/              # Exploitability scoring engine
├── api/                  # REST API (FastAPI)
├── tests/                # Test suite
├── scripts/              # Schema creation and enrichment refresh
├── frontend/             # Dashboard (Phase 2 - not yet implemented)
├── integrations/         # Slack, Jira, webhooks (Phase 3 - not yet implemented)
├── cerberus.py           # CLI entry point
├── config.yaml
├── docker-compose.yml
└── README.md
```

## Roadmap

Full phased breakdown with build order and exit criteria: [docs/ROADMAP.md](docs/ROADMAP.md).

- [x] Foundation docs: README, PRD, API contract, database schema, rules of engagement, repo scaffold
- [ ] MVP pipeline: discovery → ingestion → enrichment → scoring → CLI, end to end against a single target
- [ ] Delivery & polish: dashboard, remaining API endpoints, deployment guide
- [ ] Scale features: cloud connectors, criticality UI, Slack/Jira integration, multi-tenant support, graph-based blast-radius analysis, learned scoring model, public API

## Legal & Ethical Use

Cerberus performs active reconnaissance (port scanning, vulnerability probing) in addition to passive OSINT. **Only run Cerberus against assets you own or have explicit written authorization to test.** Unauthorized scanning of third-party systems may violate computer misuse laws in your jurisdiction (e.g. the CFAA in the US).

This project does not include or facilitate weaponized exploit code, and is intended for defensive security use: helping organizations understand and reduce their own attack surface.

## Contributing

Contributions are welcome. Please:

- Open an issue describing the change before submitting a large PR
- Follow the existing code style and add tests for new functionality
- Do not submit code that adds active-exploitation/weaponization capability — detection and prioritization only

## License

This project is licensed under the MIT License — see LICENSE for details.

## Disclaimer

Cerberus is provided as-is, for legitimate security research and defensive use. The maintainers are not responsible for misuse of this tool. Always operate within the bounds of the law and with proper authorization.
