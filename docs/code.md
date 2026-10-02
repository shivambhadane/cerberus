# Code map

Where everything is and what it does. For *why* it is built this way see [README.md](../README.md) and
[docs/](./); this file is only the map.

`landing/` (the marketing site) is maintained separately and is not covered here.

## 1. How a scan flows

```
cerberus.py scan  ─┐                                   (or)   POST /api/v1/scans  (api/main.py)
                   ▼
core/pipeline.py  run_pipeline(scan_id)
   │
   ├─ 1. DISCOVER   discovery/runner.py  run_discovery(scope, profile)
   │        │   crtsh / subfinder          → subdomain observations
   │        │   tcp_connect / nmap         → open-port observations
   │        │   http_probe                 → technology observations
   │        └─  nuclei                     → vulnerability observations   (only if profile allows)
   │
   ├─ 2. INGEST     ingestion/normalize.py  ingest_assets()
   │        raw observations → `observations` table, endpoints → `assets`, criticality tagged
   │
   ├─ 3. ENRICH     enrichment/matcher.py
   │        match_findings()            technology string → CPE → NVD CVEs   (version_inference)
   │        record_active_detections()  nuclei observations → findings        (active_detection)
   │        enrichment/cache.py + sources.py supply KEV, EPSS, NVD data
   │
   ├─ 4. SCORE      scoring/engine.py  score_pending_findings()
   │        risk_score (0-100) + plain-English reasoning on every finding
   │
   └─ 5. DELIVER    api/main.py (REST)  ·  cerberus.py report (CLI)  ·  frontend/ (dashboard)
```

Scan status moves `pending → discovering → enriching → scoring → completed` (or `failed`).

Two rules cut across every stage:

- **Scope** ([core/scope.py](../core/scope.py)) is checked before anything touches a target.
- **Profile** ([core/profiles.py](../core/profiles.py)) decides what scanners are allowed to do.

## 2. Directory tree

```
cerberus/
├── cerberus.py                 CLI entry point
├── config.yaml                 non-secret settings (ports, scan profile, score weights)
├── .env / .env.example         secrets (git-ignored / template)
├── requirements.txt  pyproject.toml  alembic.ini
├── Dockerfile  docker-compose.yml  .dockerignore
│
├── core/                       shared foundations: config, DB, models, pipeline, safety
│   ├── config.py
│   ├── db.py
│   ├── models.py
│   ├── pipeline.py
│   ├── ownership.py
│   ├── security.py
│   ├── firebase_auth.py
│   ├── profile.py
│   ├── crypto.py
│   ├── provider_service.py
│   ├── throttle.py
│   ├── verification.py
│   ├── scope.py
│   ├── profiles.py
│   ├── adapters.py
│   ├── proc.py
│   └── http.py
│
├── discovery/                  stage 1: find and probe assets
│   ├── runner.py
│   └── adapters/
│       ├── crtsh.py  subfinder.py  tcp_connect.py  nmap_scan.py  http_probe.py  nuclei.py
│
├── ingestion/                  stage 2: normalize, dedupe, tag criticality
│   ├── normalize.py
│   └── criticality.py
│
├── enrichment/                 stage 3: CVE / KEV / EPSS intelligence
│   ├── sources.py
│   ├── cache.py
│   └── matcher.py
│
├── scoring/                    stage 4: exploitability score
│   └── engine.py
│
├── providers/                  deployment platforms: "which projects does this account control?"
│   ├── base.py  vercel.py  netlify.py  cloudflare.py
│
├── api/                        stage 5: REST API
│   ├── main.py  deps.py  auth.py  domains.py  providers.py
│   └── schemas.py
│
├── frontend/                   stage 5: dashboard (React + TypeScript + Vite)
│   └── src/  App.tsx  api.ts  types.ts  styles.css  lib/  components/
│
├── migrations/                 Alembic schema migrations
│   ├── env.py
│   └── versions/  0001 … 0005  0006_user_profile_picture.py  0007_connected_providers_and_provider_targets.py
│
├── scripts/                    operational scripts
│   ├── init_db.py
│   └── refresh_enrichment.py
│
├── lab/                        Level-1 test lab: intentionally vulnerable Docker targets
├── tests/                      unit + integration tests, and fixtures captured from real tools
├── docs/                       PRD, API, schema, RoE, roadmap, deployment, demo, validation
├── integrations/               Slack/Jira: placeholder only, not implemented
└── landing/                    marketing site (separate)
```

## 3. Entry points

| Command | Runs |
|---|---|
| `./run.sh` | everything: setup if needed, then the API and dashboard (`stop`, `status`, `logs`, `test`, `scan`, `claim`, `enrich`, `lab`) |
| `python cerberus.py scan --target X --authorized [...]` | full pipeline; flags: `--profile`, `--accept-profile`, `--owner EMAIL`, `--allow-private`, `--no-subdomains`, `--ports` |
| `python cerberus.py report --top N` | ranked findings table |
| `python cerberus.py status` | asset / finding / cached-CVE counts and enrichment freshness |
| `python cerberus.py enrich` | refresh KEV + EPSS |
| `uvicorn api.main:app` | REST API |
| `python scripts/init_db.py` | create or upgrade the database schema |
| `python scripts/claim_legacy.py EMAIL` | give scans/assets that have no owner to an account |
| `python scripts/refresh_enrichment.py` | refresh KEV + EPSS (run daily; `./run.sh` also runs this automatically whenever the cache is missing or older than 24h) |
| `python scripts/add_test_target.py EMAIL DOMAIN` | mark any domain `dns_txt`-verified for an account directly in the DB, bypassing proof (operator tool, not an API route) |
| `python scripts/grant_admin.py EMAIL [--revoke]` | grant or revoke read-only cross-tenant visibility (operator tool; no API sets this) |
| `python scripts/setup_cloudflare_oauth.py [--diagnose]` | create the Cloudflare OAuth client over Cloudflare's API, because its dashboard form and published scope list are both unreliable; writes `CLOUDFLARE_CLIENT_ID`/`_SECRET`/`_OAUTH_SCOPES` to `.env` |
| `cd frontend && npm run dev` | dashboard on :5173 |
| `docker compose up -d` | API + Postgres |
| `docker compose -f lab/docker-compose.yml up -d` | vulnerable test lab |

## 4. `core/` — shared foundations

| File | What it does |
|---|---|
| [config.py](../core/config.py) | Loads `config.yaml` and `.env` into `Config` (`DiscoveryConfig`, `EnrichmentConfig`, `ScanningConfig`, `ScoringConfig`). Properties: `database_url` (defaults to SQLite), `nvd_api_key`, `api_secret_key`, `cors_origins`, `cookie_secure`, and the provider settings (`provider_token_keys`, `public_api_url`, `frontend_url`, `provider_credentials()`, `vercel_integration_slug`, `cloudflare_oauth_scopes`). |
| [db.py](../core/db.py) | Engine and `session_scope()` (commit/rollback). `migrate()` builds or upgrades the schema with Alembic. A pre-migration database is adopted at the newest revision whose schema it matches (`_matching_revision`), else refused with a readable `SchemaMismatchError` (`describe_differences`). `init_db()`, `get_default_tenant()`, `redact_url()` (masks passwords). |
| [models.py](../core/models.py) | SQLAlchemy tables: `User` (incl. `picture_url`, `auth_provider`), `Domain` (incl. the `provider_*` columns), `AuthSession` (accounts), `ConnectedProvider`, `OAuthState` (deployment providers), `Tenant` (legacy), `Scan` (incl. persisted `warnings`), `Asset`, `AssetCriticality` (incl. `source`: heuristic or manual), `CveEnrichment`, `Finding`, `ObservationRecord`, `SourceRefresh`. Text columns fed by external tools are unbounded on purpose (see VALIDATION.md bug 8). |
| [pipeline.py](../core/pipeline.py) | `run_pipeline()` orchestrates all stages and status. `start_scan()` / `create_scan_record()` refuse without the authorization attestation. `fail_interrupted_scans()` marks scans orphaned by a restart as failed so they don't block new ones. |
| [security.py](../core/security.py) | Passwords and tokens, and nothing else: Argon2id hashing, the length-based password policy, JWT access tokens (algorithm pinned; `alg: none` and key-confusion forgeries refused), opaque refresh tokens stored only as SHA-256. Pure functions, so an identity provider could replace it without the rest of the system noticing. |
| [firebase_auth.py](../core/firebase_auth.py) | Verifies Firebase ID tokens (Google, GitHub, email) against Google's published keys. The synthetic `test-firebase-token:` tokens the tests use are refused unless `CERBERUS_ALLOW_TEST_TOKENS=1`. |
| [profile.py](../core/profile.py) | What is kept from an identity provider's *verified* token and how far it is trusted: `clean_picture_url` (https only), `clean_display_name`, `sign_in_provider`. |
| [crypto.py](../core/crypto.py) | `TokenCipher`: Fernet encryption of provider tokens at rest, bound to the row they belong to, with key rotation. The key exists only in the environment. |
| [provider_service.py](../core/provider_service.py) | The deployment-provider rules, with no HTTP in them: start and complete an OAuth flow (single-use, user- and browser-bound `state`), store a connection, list projects, verify a platform target, disconnect, and `recheck_platform_target` before a scan. Raises `ProviderServiceError` with a stable `code`. |
| [throttle.py](../core/throttle.py) | `FailureLimiter`: failures per key over a sliding window, for sign-in and verification. In-process, matching the single-API-process assumption. |
| [verification.py](../core/verification.py) | DNS TXT domain verification. Keeps "the record is not there" apart from "DNS could not be asked"; the lookup is injectable, so tests never touch the network. |
| [ownership.py](../core/ownership.py) | The ownership rule as code: `check_scan_allowed(user, domain, target)` (active user, owns the domain, domain verified, target inside it) raising `OwnershipError` with a stable `code`; `normalize_domain`, `normalize_email`. Knows nothing about passwords or HTTP. |
| [scope.py](../core/scope.py) | `Scope`: the authorization boundary. `permits_host()` (exact or true subdomain; rejects `evilexample.com`), `permits_address()` (refuses private/loopback/link-local/cloud-metadata unless allowed), `permits_port()`, `filter_hosts()`. `development_scope()` for local labs. `allow_loopback_only` is a narrower grant than `allow_private_addresses` - exact loopback only, used for Test Labs. |
| [profiles.py](../core/profiles.py) | `ScanProfile` and the `passive` / `safe` / `thorough` profiles. Template selection is an allowlist. A non-overridable safety floor refuses `dos`/`ddos`/`fuzz`/`fuzzing`/`intrusive`/`brute-force` tags and `code`/`file` protocols. `nuclei_args()` builds the nuclei flags; `enforce_safety_floor()`, `audit_nuclei_args()` and `result_is_permitted()` re-check at adapter entry, on the real argv, and on results. `get_profile()` enforces the `thorough` opt-in. |
| [adapters.py](../core/adapters.py) | The scanner contract. `Observation` (one fact + which tool saw it), `Endpoint`, `ObservationKind`, `DetectionMethod` (`version_inference` vs `active_detection`), the `Scanner` protocols, and the adapter registry (`register`, `available`). |
| [proc.py](../core/proc.py) | `run_tool()`: the only place external tools run. Always closes stdin and turns timeouts/crashes into `ScannerError`, so "tool failed" never looks like "found nothing". |
| [http.py](../core/http.py) | `build_session()`: `requests` session with retry and backoff on 429/5xx, honouring `Retry-After`. Used for KEV, EPSS, NVD, crt.sh. |

## 5. `discovery/` — stage 1

| File | What it does |
|---|---|
| [runner.py](../discovery/runner.py) | `run_discovery()` runs adapters in order: subdomains → ports → technology → vulnerabilities. Enforces scope between phases, pushes config into adapters (`_configure`), isolates adapter failures (`_run_adapter` records a `ScannerError` instead of aborting), and dedupes ports reported by several scanners. A profile with no active probing stops after passive enumeration. Returns `DiscoveryResult(observations, endpoints, errors)`. |
| [adapters/crtsh.py](../discovery/adapters/crtsh.py) | Passive subdomains from certificate-transparency logs, then DNS resolution. Also exports `resolve()`. |
| [adapters/subfinder.py](../discovery/adapters/subfinder.py) | Subdomains via `subfinder`, when installed. |
| [adapters/tcp_connect.py](../discovery/adapters/tcp_connect.py) | Pure-Python async TCP connect scan; `DEFAULT_PORTS`. |
| [adapters/nmap_scan.py](../discovery/adapters/nmap_scan.py) | Ports plus service/version via `nmap -sT -sV`. Maps results back to the endpoints requested and never trusts nmap's reverse-DNS hostname (`_identify_host`). |
| [adapters/http_probe.py](../discovery/adapters/http_probe.py) | Fingerprints what is still unidentified from the HTTP `Server` header or a raw banner. |
| [adapters/nuclei.py](../discovery/adapters/nuclei.py) | Active detection via `nuclei`, controlled entirely by a resolved `ScanProfile`. `build_command()` audits the argv before running; `parse()` turns JSONL into observations, dropping malformed, out-of-scope, or forbidden-category results. Handles real nuclei's shape (bare host + separate port, lower-case CVE ids). |

Adding a scanner means writing one file here and calling `register(...)`. Nothing in `core/` changes.

## 6. `ingestion/` — stage 2

| File | What it does |
|---|---|
| [normalize.py](../ingestion/normalize.py) | `persist_observations()` stores raw tool output first. `ingest_assets()` upserts assets on `(tenant, host, port, protocol)` so re-scans refresh instead of duplicating, and records which tool identified each technology. |
| [criticality.py](../ingestion/criticality.py) | `infer_criticality()`: hostname patterns (`login`/`payments` → critical, `api`/`prod` → high, `dev`/`test` → low) and exposed sensitive ports. Manual tags are never overwritten. |

## 7. `enrichment/` — stage 3

| File | What it does |
|---|---|
| [sources.py](../enrichment/sources.py) | External data clients. `fetch_kev()` (CISA), `fetch_epss()` (FIRST, batched), and `NvdClient`: rate-limited (faster with `NVD_API_KEY`), `resolve_cpe()` (fingerprint → vendor:product candidates), `cves_for_cpe()` (paginated, warns loudly if a cap is hit). |
| [cache.py](../enrichment/cache.py) | Writes global (tenant-independent) intelligence to `cve_enrichment`. `refresh_global_sources()`, `apply_kev/nvd/epss()`, and `cache_warning()` which flags an empty or stale KEV cache. |
| [matcher.py](../enrichment/matcher.py) | `parse_technology()` (`"Apache httpd/2.4.49"` → product + version); `match_findings()` creates `version_inference` findings; `record_active_detections()` turns nuclei observations into `active_detection` findings, superseding an inferred one for the same asset and CVE; `MatchEvidence` writes the human-readable evidence string. |

## 8. `scoring/` — stage 4

[explain.py](../scoring/explain.py) — `explain()`: the developer-friendly reading of a finding (what was found, what the problem is, why it matters, how it was detected, how serious it is, why this priority, what to do, how to verify). Deterministic, computed at read time from already-stored fields; `why_this_priority` reuses the existing tested `reasoning` sentence rather than building a second one. Never invents a patched-version number NVD/Cerberus does not actually have.

[engine.py](../scoring/engine.py) — `score_finding()` blends four signals using the weights in `config.yaml`:
KEV status **0.35**, EPSS **0.25**, asset criticality **0.25**, exposure context **0.15** (which is
where CVSS enters, so severity alone never dominates). It returns a 0–100 score and a reasoning
string. Detection method appears in the reasoning ("confirmed by active probe") but deliberately
does **not** change the score. `score_pending_findings()` re-scores every finding from current enrichment data.

## 9. `api/` — stage 5 (REST)

| File | What it does |
|---|---|
| [main.py](../api/main.py) | FastAPI app. Startup: refuses to run with an empty or placeholder `API_SECRET_KEY`, runs migrations, fails orphaned scans. `require_auth` is a constant-time bearer check that rejects empty keys. Errors use one shape: `{"error": {"code", "message"}}`. |
| [deps.py](../api/deps.py) | What every route depends on: `ApiError`, the database session, and `current_user` — the single place an access token becomes a `User`. Routes never see a token or a header. |
| [auth.py](../api/auth.py) | `/api/v1/auth/*`: register, login, refresh (rotating, with replay detection), logout, me. Owns the cookie policy and the sign-in throttles. |
| [domains.py](../api/domains.py) | `/api/v1/domains/*`: claim, list, verify (DNS), add/verify through a connected platform account, and the fixed Test Labs allowlist (`/testbeds`). Every route scoped to the caller; someone else's domain is a 404. DNS instructions are omitted for platform-verified targets. |
| [providers.py](../api/providers.py) | `/api/v1/providers`, `/api/v1/connections/*`: list providers, start a connection, the public OAuth callback, list projects, disconnect. Maps `ProviderServiceError` to HTTP; a provider's 401 is never our 401. |
| [admin.py](../api/admin.py) | `/api/v1/admin/*`: read-only cross-tenant overview, users, domains, scans, gated by `require_admin` (`api/deps.py`). Grants no scanning power; `POST /scans` does not know this router exists. |
| [schemas.py](../api/schemas.py) | Pydantic request/response models. |

| Route | Purpose |
|---|---|
| `GET /healthz` | liveness (no auth) |
| `POST /api/v1/scans` | start a scan (`domain_id`, `profile`, `accept_profile`); `409` if one is running. No parameter opens private addresses — except a `testbed`/`lab`-verified `127.0.0.1` target, which gets `allow_loopback_only` (exact loopback only, never RFC1918 or metadata; see [DEPLOYMENT.md §5](DEPLOYMENT.md#5-scanning-from-the-deployed-api)). |
| `GET /api/v1/scans/{id}`, `GET /api/v1/scans` | scan status, now including real `progress` (`core/pipeline.py`'s `SCAN_STAGES`) — null until the pipeline has written a stage, never fabricated |
| `GET /api/v1/domains/testbeds`, `POST /api/v1/domains/testbeds/{id}` | list the sanctioned public benchmarks and Docker labs; add one as an already-verified target (no DNS, no platform account) |
| `GET /api/v1/scans/{id}` | scan status |
| `GET /api/v1/scans` | scan history, newest first, with observation counts and warnings |
| `GET /api/v1/assets` | discovered assets with criticality, its source, and finding counts |
| `PATCH /api/v1/assets/{id}/criticality` | set criticality (a manual decision); re-scores that asset's findings |
| `GET /api/v1/findings` | ranked findings; filters `q`, `status`, `detection_method`, `asset_id`, `kev_only`, `min_risk_score`; sort by risk/CVSS/EPSS/date; paging |
| `GET/PATCH /api/v1/findings/{id}` | detail with evidence; update status |
| `GET /api/v1/observations` | raw tool output, filter by scan/kind/tool/target |
| `GET /api/v1/enrichment/status` | KEV/EPSS freshness |
| `POST /api/v1/domains/provider`, `POST /api/v1/domains/{id}/verify/provider` | add / verify a deployment through a connected platform account |
| `GET /api/v1/providers`, `POST /api/v1/providers/{p}/connect`, `GET /api/v1/providers/{p}/callback` | list providers; start an OAuth flow; the platform's redirect back (no bearer token) |
| `POST /api/v1/providers/{p}/token` | connect with a pasted access token (Vercel) |
| `GET /api/v1/connections`, `GET /api/v1/connections/{id}/projects`, `POST /api/v1/connections/{id}/disconnect` | your connected accounts; their projects; forget one |
| `GET /api/v1/admin/overview`, `GET /api/v1/admin/users`, `GET /api/v1/admin/domains`, `GET /api/v1/admin/scans` | cross-tenant, read-only, `is_admin` only; `404` for everyone else |

Full contract: [docs/API.md](API.md).

### `providers/` — deployment-platform verification

| File | What it does |
|---|---|
| [base.py](../providers/base.py) | The contract (`DeploymentProvider`) and the two rules shared by every provider: only platform hostnames (`*.vercel.app`, `*.netlify.app`, `*.pages.dev`) prove anything, and browser-supplied ids are validated before they go in a URL. `verify_target()` is here and is not overridden. `ProviderHttp`: HTTPS only, no redirects, bounded time and size. |
| [vercel.py](../providers/vercel.py) | Vercel, through an *Integration* (no PKCE, no refresh token, scopes set in the Vercel console). |
| [netlify.py](../providers/netlify.py) | Netlify OAuth (no scopes; token endpoint not in the public reference: the module says so). |
| [cloudflare.py](../providers/cloudflare.py) | Cloudflare self-managed OAuth: PKCE, refresh tokens, scopes supplied by the operator. |
| [\_\_init\_\_.py](../providers/__init__.py) | `get_provider(name)`, `PROVIDER_NAMES`, and `use_http()` so tests substitute the HTTP layer and never touch a real platform. |

## 10. `frontend/` — dashboard

React 18 + TypeScript + Vite, ~4,400 lines of TypeScript/TSX across 16 components, no runtime dependency
beyond React and Firebase (auth only). Full detail, the design system, and the accessibility guarantees:
[frontend/README.md](../frontend/README.md).

| File | What it does |
|---|---|
| [src/App.tsx](../frontend/src/App.tsx) | Shell: skip link, left sidebar (a non-link brand; grouped navigation), top bar (breadcrumb, **Landing page** button, account link to Profile, sign out), sign-in gate, landmarks, enrichment banner. |
| [src/api.ts](../frontend/src/api.ts) | Typed client for every endpoint; token handling; `PAGE_SIZE`. |
| [src/types.ts](../frontend/src/types.ts) | TypeScript shapes matching the API. |
| [src/styles.css](../frontend/src/styles.css) | The design system: tokens (colour, 12–24px type scale, 4px spacing, controls, focus) then components. The only place anything is styled. |
| [src/lib/router.ts](../frontend/src/lib/router.ts) | Hash router. The screen (`overview` is the default), filters, sort, page and selected finding live in the URL, so views are linkable and the back button works. |
| [src/lib/useApi.ts](../frontend/src/lib/useApi.ts) | Fetch hook that cancels stale requests. |
| [src/lib/format.ts](../frontend/src/lib/format.ts) | Dates, durations, percentages. |
| [components/ui.tsx](../frontend/src/components/ui.tsx) | Shared primitives: `Badge`, `RiskScore`, `ExploitBadge`, `DetectionBadge`, `Banner`, `ErrorBanner`, `EmptyState`, `SortHeader`, `TableWrap`, `Pagination`, `PageHeader`, `NewScanLink`. |
| [components/icons.tsx](../frontend/src/components/icons.tsx) | The inline icon set (decorative, `aria-hidden`). |
| [components/OverviewView.tsx](../frontend/src/components/OverviewView.tsx) | Landing page: four KPI cards, Top risks cards, the Risk breakdown bar charts (drawn as lists, so the text carries the data), Recent scans. Polls while a scan runs. |
| [components/FindingsView.tsx](../frontend/src/components/FindingsView.tsx) | Ranked table: search, status/evidence/risk/KEV filters, sortable columns, pagination. |
| [components/FindingDetail.tsx](../frontend/src/components/FindingDetail.tsx) | Detail panel, headlined by the plain-language `explanation.what_we_found` (not the bare CVE id): what/why/how-detected/how-serious/why-this-priority/what-to-do/how-to-verify, then evidence, status control and criticality. Focus moves in, Escape closes and restores focus. |
| [components/CriticalityEditor.tsx](../frontend/src/components/CriticalityEditor.tsx) | Shows whether criticality is *inferred* or *set by you*, and edits it (re-ranks the asset's findings). |
| [components/AssetsView.tsx](../frontend/src/components/AssetsView.tsx) | Asset inventory with inline criticality editing and links to an asset's findings and evidence. |
| [components/ObservationsView.tsx](../frontend/src/components/ObservationsView.tsx) | "Evidence" screen: raw observations, filterable by kind, asset, or scan. |
| [components/ProfileView.tsx](../frontend/src/components/ProfileView.tsx) | Profile page: photo, name, email, sign-in method, last sign-in (from the provider's verified token), and the list of connected deployment accounts. |
| [components/Avatar.tsx](../frontend/src/components/Avatar.tsx) | The person's photo, or initials when there is none or it fails to load (`referrerPolicy="no-referrer"`). |
| [components/DomainsView.tsx](../frontend/src/components/DomainsView.tsx) | "Targets": the choice between **Custom domain** (DNS TXT) and **Deployment**, and each target with how it was verified. |
| [components/DeploymentProviders.tsx](../frontend/src/components/DeploymentProviders.tsx) | The Deployment path: a card per provider (connect, project list, Add & verify, disconnect). Refuses to navigate to anything that is not `https:`. |
| [components/TestLabsView.tsx](../frontend/src/components/TestLabsView.tsx) | "Test Labs": the sanctioned public benchmarks and Docker labs, each with its vulnerabilities, the docker command to start it, and an **Add as target** button. Has not had its accessibility pass yet (3 known axe violations; see [frontend/README.md](../frontend/README.md#known-gaps)). |
| [components/AdminView.tsx](../frontend/src/components/AdminView.tsx) | "Admin", shown only when `user.is_admin`: counts, accounts, targets and scans across every user. Read-only; there is nothing here that starts or affects a scan. |
| [components/ScansView.tsx](../frontend/src/components/ScansView.tsx) | Start-scan form (profile picker, opt-in gates) plus scan history with the warnings a scan finished with. Each row expands to a real stage checklist (`StageProgress`: ✓ done, ● current, — did not run for this profile) and live counts, driven entirely by `scan.progress`. |
| [components/AttackSurfaceView.tsx](../frontend/src/components/AttackSurfaceView.tsx) | "Attack Surface": every verified domain traced to its assets to their findings, built entirely from the existing `/domains`, `/assets` and `/findings` endpoints (no new backend route) and linking back to real evidence. No graph database; PostgreSQL's existing relationships are enough, per the brief that asked for this. |
| [components/EnrichmentBanner.tsx](../frontend/src/components/EnrichmentBanner.tsx) | Warns when the KEV cache is empty or stale. |
| [e2e/dashboard.e2e.cjs](../frontend/e2e/dashboard.e2e.cjs) | Real-Chrome end-to-end + axe accessibility test (`npm run test:e2e`). |

## 11. Data model

```
tenants ─┬─< scans ──< observations        raw tool output: tool, version, data JSON, raw text
         └─< assets ──< findings >── cve_enrichment      (global KEV/EPSS/NVD cache)
              └─ asset_criticality (1:1)
source_refresh      when each global source was last pulled
```

A finding is one `(asset, CVE)` pair (unique) carrying `risk_score`, `reasoning`, `detection_method`,
`detected_by_tool`, and `evidence`. Details: [docs/DATABASE_SCHEMA.md](DATABASE_SCHEMA.md).

## 12. Migrations and scripts

- [migrations/versions/0001_baseline_schema.py](../migrations/versions/0001_baseline_schema.py) — full initial schema.
- [migrations/versions/0002_unbound_tool_supplied_text_columns.py](../migrations/versions/0002_unbound_tool_supplied_text_columns.py) — widened columns fed by external tools.
- [migrations/versions/0003_scan_warnings_and_criticality_source.py](../migrations/versions/0003_scan_warnings_and_criticality_source.py) — `scans.warnings`, `asset_criticality.source`.
- [migrations/versions/0004…0005](../migrations/versions/) — users, domains, auth sessions, per-user asset identity.
- [migrations/versions/0006_user_profile_picture.py](../migrations/versions/0006_user_profile_picture.py) — `users.picture_url`, `users.auth_provider`.
- [migrations/versions/0007_connected_providers_and_provider_targets.py](../migrations/versions/0007_connected_providers_and_provider_targets.py) — `connected_providers`, `oauth_states`, and the `provider_*` columns on `domains`.
- [migrations/versions/0008_testbed_domains.py](../migrations/versions/0008_testbed_domains.py) — excludes `testbed`/`lab` from the one-verified-owner index, so Test Labs benchmarks can be verified by more than one account.
- [migrations/versions/0009_admin_flag.py](../migrations/versions/0009_admin_flag.py) — `users.is_admin`, default `false`.
- [migrations/versions/0010_scan_progress.py](../migrations/versions/0010_scan_progress.py) — `scans.progress`, default `{}`.
- [migrations/env.py](../migrations/env.py) — reads the URL from `core.config`; deliberately does not reconfigure application logging.
- Change the schema: edit `core/models.py`, then `alembic revision --autogenerate -m "..."`, review, commit.

## 13. Configuration

| Where | What |
|---|---|
| [config.yaml](../config.yaml) | `discovery` (ports, timeouts, exclusions, `allow_private_addresses`), `scanning.profile`, `enrichment`, `scoring.weights`, `integrations` (unused) |
| `.env` | `DATABASE_URL`, `NVD_API_KEY`, `API_SECRET_KEY` (**required**), `CORS_ORIGINS`, `POSTGRES_PASSWORD` (compose), `COOKIE_SECURE`, `FIREBASE_PROJECT_ID` |
| `.env` (deployment providers, optional) | `PROVIDER_TOKEN_ENCRYPTION_KEY`, `PUBLIC_API_URL`, `FRONTEND_URL`, `VERCEL_CLIENT_ID` / `_SECRET` / `VERCEL_INTEGRATION_SLUG`, `NETLIFY_CLIENT_ID` / `_SECRET`, `CLOUDFLARE_CLIENT_ID` / `_SECRET` / `CLOUDFLARE_OAUTH_SCOPES`. See [DEPLOYMENT.md §7](DEPLOYMENT.md#7-deployment-providers) |
| env flags | `CERBERUS_ALLOW_TEST_TOKENS=1` (test suite only: accepts synthetic sign-in tokens, i.e. lets anyone sign in as anyone; never set it); |
| env flags (dev) | `CERBERUS_ALLOW_INSECURE_DEV=1` (allow placeholder API key, throwaway use only); `CERBERUS_PUBLIC_TESTS=1` (enable the `scanme.nmap.org` tests) |

## 14. Tests

Counts are test functions; parametrised tests expand to more cases (these counts predate the deployment-provider work for the older files; run `pytest --collect-only -q` for the current total).

| File | Covers |
|---|---|
| [test_nuclei.py](../tests/test_nuclei.py) (30) | profile-driven command building, forbidden tags/types, malformed JSONL, dedupe, real-record parsing, detections → findings |
| [test_adapters.py](../tests/test_adapters.py) (22) | adapter contract, nmap parsing incl. the PTR bug, endpoint dedupe, config reaching adapters, passive-means-passive; the `on_stage` progress callback fires once per real boundary, in order, with true counts, and never for a stage that did not run |
| [test_api.py](../tests/test_api.py) (37) | auth (incl. empty-key bypass), filters, profile gating, scan conflicts; a new scan has no `progress` until the pipeline writes some, and the list endpoint carries it too once it does |
| [test_api_views.py](../tests/test_api_views.py) (41) | dashboard API: search/status/detection filters, NULL-last sorting, paging, scan history and warnings, evidence by target, criticality editing (manual survives re-scan, only that asset re-scored); the finding-detail `explanation` field, consistent after a status update |
| [test_migrations.py](../tests/test_migrations.py) (24) | fresh / legacy / drifted databases, adoption at the matching revision, readable refusals, data survival, logging left intact; the provider, admin-flag and scan-progress migrations are additive, constrained, and undo/redo cleanly |
| [test_crypto.py](../tests/test_crypto.py) (10) | tokens encrypted at rest, bound to their row, key rotation, tampering and wrong keys refused |
| [test_profile.py](../tests/test_profile.py) (14, 26 cases) | picture URLs (https only), names, sign-in method; what a Google sign-in records and refreshes; the profile never exposes credentials; an unverified email cannot take over an existing account |
| [test_provider_clients.py](../tests/test_provider_clients.py) (44, 68 cases) | each provider's requests and response parsing against fakes of the documented responses; platform-hostname rule; id validation |
| [test_providers_api.py](../tests/test_providers_api.py) (42) | connect / callback / list / disconnect: state single-use, expiry, wrong browser, wrong user, replay, redirect URI, no token in any response |
| [test_provider_ownership.py](../tests/test_provider_ownership.py) (36, 45 cases) | Add & verify: what the platform must say, forged ids, custom domains refused, first-to-verify, scan-time re-check and `ownership_lost`, DNS verification and scan authorization unchanged |
| [test_provider_token.py](../tests/test_provider_token.py) (43 cases) | pasted access tokens: proved by using them, stored encrypted, never returned or logged, refused without being echoed, rate limited, isolated, usable with no OAuth app configured; a malformed team ID is its own error and does not spend a wrong-token attempt |
| [test_provider_isolation.py](../tests/test_provider_isolation.py) (13) | another user's connection, project, domain and state answer 404 |
| [test_domains_api.py](../tests/test_domains_api.py) (29 cases) | Test Labs: listing, adding an immediately-verified testbed, cross-account scanning of a shared benchmark address |
| [test_admin.py](../tests/test_admin.py) (15 cases) | every `/admin/*` route is 404 for a non-admin; an admin sees every account's data; `is_admin` cannot be set by any API; **admin visibility grants no scanning power** — the one test that matters most here |
| [test_firebase_auth.py](../tests/test_firebase_auth.py) (7) | Firebase token verification, provisioning, linking, expiry; the synthetic test token is refused unless the suite enables it |
| [test_profiles.py](../tests/test_profiles.py) (14) | the safety floor cannot be lifted |
| [test_pipeline.py](../tests/test_pipeline.py) (13) | authorization refusal, cache warnings, orphaned scans; `_record_stage` marks a stage done, accumulates counts, is idempotent, points `current` at the next stage even if stages are recorded out of order |
| [test_proc.py](../tests/test_proc.py) (8) | stdin always closed, failures explicit |
| [test_nvd_pagination.py](../tests/test_nvd_pagination.py) (7) | every NVD page fetched, loud on truncation |
| [test_ingestion.py](../tests/test_ingestion.py) (7) | dedupe, provenance, criticality |
| [test_scoring.py](../tests/test_scoring.py) (8) | KEV beats CVSS, reasoning content, and the four documented weights are the ones actually used |
| [test_scope.py](../tests/test_scope.py) (10) | suffix confusion, private ranges, exclusions; `allow_loopback_only` grants the exact loopback address and nothing broader - not RFC1918, not the cloud metadata address |
| [test_explain.py](../tests/test_explain.py) (12) | the developer-friendly explanation: grounded in stored data only, honest when NVD gave no description, and never inventing a patched-version number |
| [test_matcher.py](../tests/test_matcher.py) (3) · [test_secrets.py](../tests/test_secrets.py) (3) | technology parsing · password masking |
| [integration/test_public_targets.py](../tests/integration/test_public_targets.py) (5) | Level 2 against `scanme.nmap.org`; opt-in, port/service discovery only |
| [fixtures/](../tests/fixtures/) | records captured from the real nmap and nuclei binaries |

Run: `pytest -q`. Lab: `docker compose -f lab/docker-compose.yml up -d`.

## 15. Where to change things

| To… | Edit |
|---|---|
| add a scanner | new file in `discovery/adapters/`, import it in `discovery/adapters/__init__.py` |
| change what nuclei may run | `core/profiles.py` (the safety floor is not configurable by design) |
| change score weights | `config.yaml` → `scoring.weights` |
| change how risk is computed | `scoring/engine.py` |
| add a criticality rule | `ingestion/criticality.py` |
| map a new banner name to a CPE | `PRODUCT_ALIASES` in `enrichment/sources.py` |
| add a table or column | `core/models.py`, then an Alembic migration |
| add an API endpoint | `api/main.py` + `api/schemas.py`, document in `docs/API.md`, call from `frontend/src/api.ts` |
| run over https://localhost (some OAuth providers need it) | `./run.sh https`; `scripts/local_https.sh` makes and trusts the certificate |
| add a deployment provider | `providers/<name>.py`, a branch in `providers/__init__.py`, the frontend constants: [API.md §4.8](API.md#48-how-to-add-a-provider) |
| add a dashboard view | new file in `frontend/src/components/`, add its name to `TABS` in `lib/router.ts` and to `NAV` in `App.tsx` |

## 16. Generated or ignored

`.env`, `*.db` (`cerberus.db`, `lab.db`), `*.log`, `.venv/`, `node_modules/`, `frontend/dist/`, `__pycache__/`.
None are committed, and `.dockerignore` keeps secrets and databases out of the image.

## 17. Not implemented

`integrations/` (Slack/Jira), cloud
connectors, revoking a provider token at the platform on disconnect, multi-tenant isolation, queue/worker separation, frontend unit/component tests (an end-to-end test exists). See
[docs/ROADMAP.md](ROADMAP.md).
