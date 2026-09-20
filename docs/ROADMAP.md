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

> **Superseded.** The discovery implementation described above (`discovery/subdomains.py`,
> `discovery/ports.py`, `discovery/fingerprint.py`) was deleted and rebuilt as the adapter
> architecture in Phase 1.5 below. The exit criterion still holds against the new code.

## Phase 1.5 — Real-target validation (adapters, scope, profiles, provenance)

Not in the original plan; added when moving from "runs against a lab" to "safe against
infrastructure we don't own the whole stack of." See [RULES_OF_ENGAGEMENT.md §4](RULES_OF_ENGAGEMENT.md#4-scan-profiles).

- [x] `core/scope.py`: authorization boundary as code, not prose. Fixed a real hole — the
      prior `name.endswith(domain)` check accepted `evilexample.com` as in-scope for
      `example.com`. Also refuses private/loopback/link-local addresses (including the
      `169.254.169.254` cloud metadata endpoint) unless a development scope opts in.
- [x] `core/adapters.py`: `Scanner` protocols + registry, so a tool is a plug-in, not a
      rewrite. `Observation` carries tool attribution on every fact discovered.
- [x] `core/profiles.py`: scan profiles (`passive` / `safe` / `thorough`) with a
      **non-overridable safety floor** — `dos`/`ddos`/`fuzz`/`fuzzing`/`intrusive`/
      `brute-force` tags and `code`/`file` protocols are refused at profile construction,
      re-audited at adapter entry, and filtered again on results returned, so a mutated
      profile or a multi-tag template can't smuggle one through. 21 tests target the floor
      alone. `thorough` requires explicit opt-in (`--accept-profile` / `accept_profile`).
- [x] Discovery adapters: `crtsh`, `subfinder`, `tcp_connect`, `nmap`, `http_probe` — the
      old modules rebuilt as adapters, no parallel implementation left behind.
- [x] `discovery/adapters/nuclei.py`: real vulnerability *detection* (not just version
      inference), governed entirely by the resolved profile. Verified against the
      installed binary (v3.11.1, 13,619 templates; the `safe` profile selects 4,754 of
      them) — the live process's argv matched `profile.nuclei_args()` exactly.
- [x] Provenance: raw tool output persists to an `observations` table before
      normalization; findings carry `detection_method` (`version_inference` vs
      `active_detection`), `detected_by_tool`, and an `evidence` string. An active
      nuclei detection supersedes an inferred finding for the same (asset, CVE) rather
      than duplicating it.
- [x] `GET /api/v1/observations` — the evidence chain is queryable, not just internal.
- [x] Dashboard: scan-profile selector with the `thorough` opt-in gate mirrored in the UI,
      and a confirmed/inferred badge distinguishing `active_detection` from
      `version_inference` on every finding.
- [x] `core/http.py` retry/backoff session wired into KEV, EPSS and NVD calls.
- [x] Dashboard: an "Evidence" tab browsing raw observations with per-tool provenance.
- [x] Database migrations (Alembic). Fresh databases are built by migrations; databases created
      before migrations existed are adopted only if their schema matches, and refused with a
      clear error otherwise. A test asserts migrations and models cannot drift apart.
- [x] `core/proc.py`: every external tool runs through one helper that closes stdin and turns
      timeouts and crashes into an explicit `ScannerError`, surfaced in the scan summary
      instead of looking like "found nothing".
- [x] A confirmed nuclei run against the lab, with numbers on record — see
      [VALIDATION.md](VALIDATION.md), including the bugs it found.

## Phase 2 — Delivery & polish

- [x] Dashboard (`frontend/`): ranked findings list + per-asset detail view, asset inventory, scan trigger with authorization gate, and an enrichment-freshness banner
- [x] `GET /api/v1/assets`, `GET /api/v1/enrichment/status`, `PATCH /api/v1/findings/{id}` (status updates)
- [x] Deployment guide ([DEPLOYMENT.md](DEPLOYMENT.md)) — verified against a real Postgres 16 stack;
      the Dockerfile now ships hash-pinned nuclei and nmap, runs unprivileged, and `.dockerignore`
      keeps `.env` and the databases out of the image
- [x] Demo script ([DEMO.md](DEMO.md))
- [x] Dashboard redesign (design-system pass): a token-based design system, WCAG 2.1 AA (zero axe violations on
      every screen), keyboard-operable tables and tabs, URL-driven filters/sort/pagination, search, scan
      history with persisted warnings, an Evidence view linked from findings, and editable asset criticality
      (manual decisions survive re-scans and re-rank that asset immediately). See [frontend/README.md](../frontend/README.md).
- [x] Dashboard visual redesign: a light theme, a left sidebar
      (a top bar on phones), a page header with a "New scan" action on every screen, and a new
      **Overview** landing page (KPI cards, Top risks, Risk breakdown chart, Recent scans) backed by
      `GET /api/v1/overview`. Layout patterns follow the reference in `docs/design/`; no other vendor's
      branding or content was used. Contrast was checked pairing by pairing and every screen was audited with axe.
- [x] Frontend end-to-end test (`npm run test:e2e`): 100 checks in a real browser, incl. registration, session
      persistence, domain verification, cross-account isolation, and axe on every screen
- [x] **Accounts and domain ownership** — the product moved from single-operator to per-user.
      - Schema (`0004`, `0005`): `users`, `domains`, `auth_sessions`; nullable `user_id`/`domain_id` on scans and
        assets; asset identity is now per owner. Additive, `tenant_id` kept. Verified on SQLite and PostgreSQL 16.
      - Auth: Argon2id passwords, JWT access tokens (~15 min), rotating refresh tokens in an httpOnly cookie with
        replay detection, sign-in throttling, and one generic message for every failed sign-in
        (`core/security.py`, `core/throttle.py`, `api/auth.py`).
      - Ownership: a scan takes a **verified `domain_id`**, never an `authorized: true` claim. Domains are proven
        with a DNS TXT record (`core/verification.py`); first to prove control owns it.
      - Isolation: every endpoint is scoped to the caller; another user's record answers 404, identical to a
        missing one. 14 tests exist only to try to cross that line.
      - Dashboard: sign-in/registration, a Domains screen with the record to publish, and a scan form that picks a
        verified domain.
      - Data from before accounts has no owner and is invisible until `scripts/claim_legacy.py` assigns it.
      - **Not yet**: email verification, password reset, and "sign out everywhere".
- [x] **Profile and dashboard shell.** The dashboard title/logo is no longer a link (it used to send people back
      to the landing page); a separate "Landing page" button sits in the top bar. A **Profile** page shows the
      name, photo, email, sign-in method and last sign-in, taken from the sign-in provider's *verified* token (a Google
      photo, refreshed each sign-in) — migration `0006`, `core/profile.py`. The navigation is grouped, and the
      account and sign-out live in the top bar. Audited with axe on 10 page states and checked at phone width.
      - **Security fixes found on the way** (see [VALIDATION.md](VALIDATION.md)): the synthetic test sign-in tokens
        were an authentication bypass and now work only with `CERBERUS_ALLOW_TEST_TOKENS=1`; and an unverified
        Firebase email could link to (take over) an existing account with the same address, and now cannot.
- [x] **Deployment provider ownership verification** — people without a custom domain can prove control of a
      Vercel, Netlify or Cloudflare Pages app through their platform account, **in addition to** DNS TXT
      verification, which is unchanged. See [API.md §4](API.md#4-deployment-providers) and
      [DEPLOYMENT.md §7](DEPLOYMENT.md#7-deployment-providers).
      - `providers/` abstraction (one module per platform), OAuth authorization-code flow with single-use,
        user- and browser-bound `state` (PKCE for Cloudflare), exact redirect URIs, tokens Fernet-encrypted at rest
        and never sent to the browser, `connected_providers` and `oauth_states` tables, four `provider_*` columns on
        `domains` (migration `0007`), eight endpoints, and a Targets page ("Custom domain" or "Deployment").
      - Only the platform's own free addresses (`*.vercel.app`, `*.netlify.app`, `*.pages.dev`) can be verified this
        way: a custom domain listed on a project proves nothing about DNS control.
      - Scan authorization is unchanged; a platform-verified target is additionally re-confirmed with the platform
        just before each scan, and refused if it cannot be.
      - Tested against fakes of each platform's documented responses, including cross-user isolation, forged and
        replayed OAuth state, and disconnect. Migrations checked on SQLite, copies of the real databases and PostgreSQL 16.
      - Vercel can also be connected with a **pasted access token** (no integration to create or publish): same encryption,
        ownership checks and isolation; broader token, so the UI says to scope it to one team and expire it.
      - **Not yet:** a connection to a real Vercel, Netlify or Cloudflare account has never been made, so all three
        clients are unproven against the live services. Netlify's token endpoint is undocumented and its tokens have
        no scopes; Cloudflare's Pages scope name is unpublished; a Vercel integration must be public before others can
        install it. More platforms (GitHub Pages, Render, Fly.io, Railway) would each be one module.
- [ ] One-pager / slide deck

## Testing levels (see [RULES_OF_ENGAGEMENT.md](RULES_OF_ENGAGEMENT.md))

- [x] **Level 1 — unit/integration:** scope, adapters, profiles, nuclei parsing (including
      malformed JSONL and records captured from the real binary), migrations, scoring,
      ingestion, API
- [x] **Level 1 — Docker vulnerable lab:** pinned Apache 2.4.49 / 2.4.50 with an
      intentionally opened config, bound to loopback ([lab/](../lab/README.md))
- [x] **Level 2 — authorized public target:** `scanme.nmap.org`, opt-in, port/service
      discovery only (`tests/integration/test_public_targets.py`)
- [ ] **Level 3 — own infrastructure:** deferred until a VPS exists, by explicit choice.

## Phase 3 — Scale features (originally listed in README, deferred past v1 per [PRD §6](PRD.md#6-out-of-scope-for-v1))

- [ ] Cloud connector support (AWS/Azure/GCP asset inventory)
- [x] ~~Asset criticality tagging UI~~ — done in the dashboard redesign
- [ ] Slack/Jira integration (`integrations/`)
- [ ] Continuous re-verification of provider-verified targets (today they are re-checked at scan time only)
- [ ] Revoking the token at the platform when a connection is disconnected (today it is only forgotten here)
- [ ] Organisations/teams (several people sharing one set of domains) — deliberately out of scope for now
- [ ] Multi-tenant support with row-level security
- [ ] Graph-based blast-radius analysis
- [ ] Learned scoring model (trained on confirmed-exploit outcomes)
- [ ] Public API for MSSP/partner use
