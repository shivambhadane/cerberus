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

| Layer | Technology |
|---|---|
| Discovery | subfinder, amass, nmap/masscan, nuclei, httpx |
| Backend / API | Python (FastAPI) or Node.js (TypeScript) |
| Queue | Redis Streams (early stage) → Kafka (at scale) |
| Primary database | PostgreSQL |
| Cache / enrichment store | Redis |
| Graph queries (optional, later) | Neo4j |
| Frontend | React / Next.js |
| Scoring service | Python microservice, independently deployable |
| Deployment | Docker containers, orchestrated with Docker Compose (dev) / Kubernetes (production) |

## Data Sources

Cerberus is built to run entirely on free, open data. No paid API keys are required to get a fully working instance.

| Source | Provides | Cost |
|---|---|---|
| NVD | CVE records, CVSS scores | Free (API key recommended for higher rate limits) |
| CISA KEV | Confirmed actively-exploited CVEs | Free |
| EPSS (FIRST.org) | Probability of exploitation in the next 30 days | Free |
| OSV.dev | Open-source package vulnerabilities | Free |
| Exploit-DB | Public proof-of-concept exploits | Free |
| crt.sh | Certificate transparency logs (subdomain discovery) | Free |
| Nuclei templates | Community-maintained vulnerability detection signatures | Free |

Optional paid upgrades (not required to run Cerberus): Shodan/Censys (internet-wide asset lookups), GreyNoise (live exploitation telemetry), VulnCheck/Recorded Future (premium threat intelligence).

## Getting Started

### Prerequisites

- Docker & Docker Compose
- Go (for building discovery tools, if not using prebuilt binaries)
- Python 3.11+
- Node.js 18+ (for the frontend)

### Installation

```bash
# Clone the repository
git clone https://github.com/<your-username>/cerberus.git
cd cerberus

# Install discovery tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Set up environment variables
cp .env.example .env
# Edit .env with your NVD API key (optional but recommended) and database URLs

# Start core services
docker compose up -d postgres redis

# Run database migrations
python manage.py migrate

# Pull the latest enrichment data (CVE, KEV, EPSS)
python scripts/refresh_enrichment.py

# Start the API and worker services
docker compose up -d api worker scoring-engine

# Start the frontend
cd frontend && npm install && npm run dev
```

### Quick test run

```bash
python cerberus.py scan --target example.com --authorized
```

`--authorized` is a required flag confirming you have permission to scan the target. See [Legal & Ethical Use](#legal--ethical-use).

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
  "asset": "api.example.com",
  "cve_id": "CVE-2023-XXXXX",
  "cvss_score": 6.5,
  "kev_listed": true,
  "epss_score": 0.94,
  "asset_criticality": "high",
  "risk_score": 98,
  "reasoning": "Actively exploited (CISA KEV), 94% predicted exploitation probability, affects a production-tagged, internet-facing asset."
}
```

## Project Structure

```
cerberus/
├── discovery/           # Asset discovery scanners and connectors
├── ingestion/            # Normalization and deduplication workers
├── enrichment/           # CVE/KEV/EPSS/OSV data pullers and cache
├── scoring/              # Exploitability scoring engine (standalone service)
├── api/                  # REST API
├── frontend/             # Dashboard (React/Next.js)
├── integrations/         # Slack, Jira, webhook handlers
├── scripts/              # Setup, migration, and data-refresh scripts
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
