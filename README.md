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
| [API Documentation](docs/API.md) | Every endpoint, request/response shape, auth, and how deployment-provider verification works and is secured |
| [Database Schema](docs/DATABASE_SCHEMA.md) | Tables, relationships, and why they're designed that way |
| [Rules of Engagement](docs/RULES_OF_ENGAGEMENT.md) | What Cerberus is allowed to scan, and how |
| [Code map](docs/code.md) | Every directory and file: what it does and where to change things |
| [Roadmap](docs/ROADMAP.md) | What's built vs. planned, by phase, with exit criteria |
| [Deployment](docs/DEPLOYMENT.md) | Running the API + Postgres in Docker Compose, setting up Vercel / Netlify / Cloudflare verification, and what was and wasn't verified |
| [Demo script](docs/DEMO.md) | A 10-minute walkthrough, including where the tool is honest about its limits |
| [Validation](docs/VALIDATION.md) | What a real end-to-end run against the lab produced, including the bugs it found |
| [Test lab](lab/README.md) | The pinned, intentionally vulnerable Docker targets used for Level 1 validation |

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
| Discovery | Interchangeable scanner adapters: crt.sh, subfinder, async TCP connect, nmap, HTTP/banner probing |
| Vulnerability detection | nuclei, governed by scan profiles (allowlisted templates, non-overridable safety floor) |
| Backend / API | Python 3.11+, FastAPI |
| Database | PostgreSQL, or SQLite for zero-setup local runs (SQLAlchemy 2.x); schema managed by Alembic |
| Scoring | Python module, importable and independently deployable |
| Frontend | React 18 + TypeScript, built with Vite |
| Deployment | Docker Compose (Postgres + API) |

**Planned (see [Roadmap](docs/ROADMAP.md)):** Redis Streams then Kafka for the async
worker queue, Neo4j for blast-radius analysis, Kubernetes for production deployment.

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
- Docker & Docker Compose (optional - Postgres, the API, and the [test lab](lab/README.md))
- `nmap` (recommended - service/version detection; a pure-Python scan is used when absent)
- `nuclei` (recommended - **active detection**; see below)
- `subfinder` (optional - Cerberus uses certificate transparency logs when it is absent)

Every external tool is optional and is an interchangeable adapter: Cerberus runs whichever are
installed and records which tool produced each observation.

**Without nuclei, every finding is `version_inference`** - "this service reports a version NVD lists
as affected" - which is a claim about the version, not a test of the host. With nuclei, findings a
probe actually matched are marked `active_detection`. Install it and its templates
(`nuclei -update-templates`) to get the stronger evidence.

### Quick start

One script does everything: dependencies, the database, the exploitation data, and both servers.

```bash
git clone https://github.com/shivambhadane/cerberus.git
cd cerberus
./run.sh
```

Then open **http://localhost:5173**, create an account, add a domain you own, publish the DNS record
it shows you, and scan it.

| | |
|---|---|
| `./run.sh` | set up if needed, then start the API and dashboard |
| `./run.sh stop` / `status` / `logs` | stop, inspect, follow |
| `./run.sh test` | tests, lint and the dashboard build |
| `./run.sh scan <domain>` | scan from the command line |
| `./run.sh lab up` / `lab scan` / `lab down` | the local vulnerable target |
| `./run.sh help` | everything else |

It only stops processes it started, and if a port is busy it tells you what holds it rather than
killing it. The rest of this section is the same thing done by hand.

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
uvicorn api.main:app --reload          # http://localhost:8000/docs   (or: ./run.sh api)
```

All endpoints except `/healthz` and `/api/v1/auth/*` require a signed-in user
(`Authorization: Bearer <access token>` from `POST /api/v1/auth/login`). Everything you can reach is
your own: another account's data answers 404. Scans name a domain you have verified with a DNS TXT
record, so there is no "I am authorised" flag to send. See [docs/API.md](docs/API.md#1-authentication).

### Running the dashboard

```bash
cd frontend && npm install && npm run dev     # http://localhost:5173   (or: ./run.sh web)
```

The dashboard is served at `/platform/` (the landing page is at `/`) and asks you to sign in on first load:
with Google, GitHub or email. Your name and photo come from your sign-in provider and appear on the
**Profile** page. Add a target, prove you own it, and then you can scan it. The API must allow the dashboard's
origin: `CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173` (already set in `.env.example`). See
[frontend/README.md](frontend/README.md).

### Proving you own a target

A scan needs a **verified** target. There are two ways to verify one, and the first is always available:

| You have | Verify it with | Notes |
|---|---|---|
| A custom domain (`example.com`) | **A DNS TXT record** the dashboard gives you | Works for any domain. Unchanged. |
| An app on the platform's free address (`*.vercel.app`, `*.netlify.app`, `*.pages.dev`) | **Connecting your Vercel, Netlify or Cloudflare account** (Targets → *Add a deployment*) | You sign in on the platform, pick a project, and Cerberus asks the platform whether the account controls it. |

You cannot add DNS records to `something.vercel.app`, which is what the second route is for. It is
**optional and off until the operator sets it up**: it needs an OAuth app on each platform and an
encryption key for the stored tokens (`./run.sh` generates that key; the platform steps are in
[docs/DEPLOYMENT.md §7](docs/DEPLOYMENT.md#7-deployment-providers)). Until then each provider shows as "Not
set up on this server" and nothing else changes.

- **Tokens stay on the server**, encrypted at rest, and are never sent to your browser. OAuth uses the
  authorization-code flow with a random, single-use `state` bound to your account and browser.
- **Only the platform's own addresses can be verified this way.** A custom domain attached to a project proves
  nothing about DNS control, so it still needs the TXT record.
- **Scan authorization is unchanged.** A platform-verified target is additionally re-checked with the platform
  just before each scan, and refused if that cannot be confirmed.
- **Disconnect** (Targets, or the Profile page's list) deletes the stored tokens and returns the targets that
  connection verified to "not verified".
- **Honest limits:** it has been tested against fakes of each platform's documented responses, **not against a
  live account**; Netlify's token endpoint is undocumented and its tokens have no scopes; Cloudflare's Pages
  scope name is unpublished; a Vercel integration must be public before other people can use it. Details:
  [docs/API.md §4](docs/API.md#4-deployment-providers).

### Viewing the landing page

A single static file with no build step — see [landing/README.md](landing/README.md).

### Running the tests

```bash
pytest -q                                   # unit + integration; hermetic, no network
```

Testing is in three levels, and each is a different claim:

| Level | What | How |
|---|---|---|
| 1 | Local: unit tests, malformed input, records captured from the real tools, and the [Docker lab](lab/README.md) | `pytest -q`; `docker compose -f lab/docker-compose.yml up -d` for the lab |
| 2 | Authorized public target (`scanme.nmap.org`), port/service discovery only | `CERBERUS_PUBLIC_TESTS=1 pytest tests/integration -v` (opt-in: it contacts a third party) |
| 3 | Your own infrastructure: VPS, several subdomains, deliberately vulnerable services | not yet built |

### Database migrations

```bash
python scripts/init_db.py      # creates or upgrades the schema (also runs at API startup)
```

A database created before migrations existed is adopted only if its schema matches; otherwise
Cerberus refuses with a clear error rather than mark it current while columns are missing.

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

Secrets and per-deployment settings live in `.env` (copy `.env.example`; `./run.sh` creates it and generates the
keys). The ones added for deployment-provider verification are optional:

| Variable | Purpose |
|---|---|
| `PROVIDER_TOKEN_ENCRYPTION_KEY` | Fernet key that encrypts stored provider tokens. Required for any provider. Back it up. |
| `PUBLIC_API_URL`, `FRONTEND_URL` | Where the API and the dashboard are reached. The OAuth redirect URIs are built from `PUBLIC_API_URL`. |
| `VERCEL_CLIENT_ID`, `VERCEL_CLIENT_SECRET`, `VERCEL_INTEGRATION_SLUG` | Your Vercel integration. |
| `NETLIFY_CLIENT_ID`, `NETLIFY_CLIENT_SECRET` | Your Netlify OAuth application. |
| `CLOUDFLARE_CLIENT_ID`, `CLOUDFLARE_CLIENT_SECRET`, `CLOUDFLARE_OAUTH_SCOPES` | Your Cloudflare OAuth client and its scopes. |

`CERBERUS_ALLOW_TEST_TOKENS` exists for the test suite only. It lets anyone sign in as any email address; never set it.

## Usage

### CLI

```bash
# Run full discovery + scan + score pipeline (default profile: safe)
cerberus scan --target example.com --authorized

# Choose what scanners may do: passive | safe | thorough
cerberus scan --target example.com --authorized --profile passive
cerberus scan --target example.com --authorized --profile thorough --accept-profile

# Scan a local lab (private addresses are refused unless you opt in)
cerberus scan --target 127.0.0.1 --authorized --allow-private --no-subdomains --ports 18081,18082

# Re-run enrichment only (refresh KEV/EPSS/CVE data)
cerberus enrich --refresh

# View top-ranked findings
cerberus report --top 10
```

Scan profiles are the security boundary for what runs against a target - see
[Rules of Engagement §4](docs/RULES_OF_ENGAGEMENT.md#4-scan-profiles). `passive` never contacts the
target; `safe` (default) runs non-destructive detection only; `thorough` must be requested
explicitly. Destructive template categories and local-execution protocols are refused by every
profile.

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
├── core/                 # Config, DB + migrations, models, pipeline, scope, scan profiles,
│                         #   scanner-adapter contracts, retrying HTTP client, tool runner
├── discovery/            # Orchestration + scanner adapters (crtsh, subfinder, tcp_connect,
│   └── adapters/         #   nmap, http_probe, nuclei)
├── ingestion/            # Normalization, dedupe, asset criticality tagging
├── enrichment/           # CVE/KEV/EPSS pullers, cache, and technology->CVE matching
├── scoring/              # Exploitability scoring engine
├── api/                  # REST API (FastAPI): auth, domains, scans, findings, deployment providers
├── providers/            # Vercel / Netlify / Cloudflare Pages: "which projects does this account control?"
├── migrations/           # Alembic schema migrations
├── lab/                  # Level 1 test lab: pinned intentionally-vulnerable Docker services
├── tests/                # Unit tests, plus integration/ for authorized public targets
├── scripts/              # Schema migration and enrichment refresh
├── frontend/             # Dashboard (React + TypeScript, Vite)
├── landing/              # Static marketing landing page
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
- [ ] Delivery & polish: dashboard, remaining API endpoints, deployment guide, accounts and domain ownership (DNS TXT, or a connected Vercel / Netlify / Cloudflare account for platform addresses)
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
