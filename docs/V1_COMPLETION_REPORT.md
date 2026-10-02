# Cerberus V1 — Completion Report

What was built against the V1 scope, what was verified and how, and what was not. Everything below was
measured on this machine on 2026-10-03; where a claim could not be verified it says so instead of
rounding up. Nothing in this report has been committed — see [§11](#11-commit-commands) for the commands.

---

## 1. Files changed

**New files (9):**

| File | What it is |
| --- | --- |
| [scoring/explain.py](../scoring/explain.py) | Deterministic finding explanations built only from stored fields |
| [api/admin.py](../api/admin.py) | Four read-only, admin-gated cross-tenant endpoints |
| [migrations/versions/0009_admin_flag.py](../migrations/versions/0009_admin_flag.py) | `users.is_admin` |
| [migrations/versions/0010_scan_progress.py](../migrations/versions/0010_scan_progress.py) | `scans.progress` |
| [scripts/grant_admin.py](../scripts/grant_admin.py) | Grants/revokes the admin flag from the command line |
| [frontend/src/components/AttackSurfaceView.tsx](../frontend/src/components/AttackSurfaceView.tsx) | Domain → asset → finding map |
| [frontend/src/components/AdminView.tsx](../frontend/src/components/AdminView.tsx) | The admin dashboard |
| [tests/test_explain.py](../tests/test_explain.py) | 12 tests for the explanation generator |
| [tests/test_admin.py](../tests/test_admin.py) | 15 tests for the admin role and endpoints |
| [tests/test_config.py](../tests/test_config.py) | 13 tests pinning how blank environment values are read |

**Modified files (33),** `1244` insertions / `74` deletions (plus this report):

- **Config:** [core/config.py](../core/config.py) (blank env values now fall back to the documented default)
- **Providers:** [providers/cloudflare.py](../providers/cloudflare.py) (records the now-known Pages scope), [scripts/add_test_target.py](../scripts/add_test_target.py) (sanctioned testbeds only, honest provenance)
- **Core/pipeline:** [core/pipeline.py](../core/pipeline.py) (stage recording), [discovery/runner.py](../discovery/runner.py) (an optional `on_stage` callback), [core/scope.py](../core/scope.py) (`allow_loopback_only`), [core/models.py](../core/models.py) (`User.is_admin`, `Scan.progress`)
- **API:** [api/main.py](../api/main.py), [api/schemas.py](../api/schemas.py), [api/deps.py](../api/deps.py) (`require_admin`), [api/auth.py](../api/auth.py)
- **Frontend:** [ScansView.tsx](../frontend/src/components/ScansView.tsx), [FindingDetail.tsx](../frontend/src/components/FindingDetail.tsx), [App.tsx](../frontend/src/App.tsx), [lib/router.ts](../frontend/src/lib/router.ts), [api.ts](../frontend/src/api.ts), [types.ts](../frontend/src/types.ts), [styles.css](../frontend/src/styles.css)
- **Tests:** `test_adapters.py`, `test_api.py`, `test_api_views.py`, `test_migrations.py`, `test_pipeline.py`, `test_scope.py`, `test_scoring.py`, `test_auth_api.py`, `test_profile.py`
- **Docs:** `README.md`, `frontend/README.md`, `docs/API.md`, `docs/DATABASE_SCHEMA.md`, `docs/DEPLOYMENT.md`, `docs/ROADMAP.md`, `docs/RULES_OF_ENGAGEMENT.md`, `docs/code.md`, `.gitignore`

The discovery and scanning pipeline was **not** simplified or restructured. `discovery/runner.py` gained one
optional callback parameter that defaults to `None` and changes nothing when omitted; a test asserts exactly
that ([tests/test_adapters.py](../tests/test_adapters.py), `test_on_stage_is_optional_and_changes_nothing_when_omitted`).

## 2. Database migrations added

| Revision | Change | Default for existing rows |
| --- | --- | --- |
| `0009_admin_flag` | `users.is_admin` boolean, `nullable=False`, server default false | `false` — never inferred as true |
| `0010_scan_progress` | `scans.progress` JSON, `nullable=False`, server default `'{}'` | `{}` — an older scan reports no progress rather than a fabricated one |

Both are additive and both implement `downgrade()`. Verified:

- **SQLite** — 4 automated tests (`tests/test_migrations.py`): additive with real rows pre-seeded, defaults correct, and up → down → up leaves `schema_differences()` empty.
- **PostgreSQL 16** — run live against `postgres:16-alpine` in a throwaway container. Seeded a user, a tenant and a completed scan at revision `0008`, migrated to head, then downgraded `0010` → `0009` → `0008` and migrated forward again. Result: `schema_differences() == []`, `is_admin = False`, `progress = {}`, the pre-existing scan row intact (`completed`, `example.com`), and both rows still present at the end.

The user's real databases were never migrated. Checksums before and after this work are identical:
`lab.db ad9676223b5694afbd513944b495b3d3`, `cerberus.db 5f6be7759837eea05f9833afeefd509c`.

## 3. API endpoints added/changed

**Added — 4, all `GET`, all read-only, all behind `require_admin`:**

| Endpoint | Returns |
| --- | --- |
| `GET /api/v1/admin/overview` | Counts across tenants |
| `GET /api/v1/admin/users` | Accounts (public fields only) |
| `GET /api/v1/admin/domains` | Targets and verification state |
| `GET /api/v1/admin/scans` | Scans across tenants |

**Changed — additively, response bodies only. No route, path, method or request schema changed:**

| Endpoint | New field |
| --- | --- |
| `GET /api/v1/scans` | `progress` on each item |
| `GET /api/v1/scans/{id}` | `progress` |
| `GET /api/v1/findings/{id}` | `explanation` (nested: `how_it_was_detected`, `how_serious`) |

`progress` is `null`, not an empty object, until the pipeline records something — so "no progress yet" is
distinguishable from "stage zero". A test pins this (`test_a_new_scan_has_no_progress_until_the_pipeline_writes_some`).

## 4. Frontend pages/components changed

| Component | Change |
| --- | --- |
| **`AttackSurfaceView`** (new) | A new "Attack Surface" tab: verified domain → discovered asset → finding, each row linking back to the evidence or finding behind it. Frontend-only — it paginates existing endpoints and **adds no backend route**. |
| **`AdminView`** (new) | The admin dashboard for the four endpoints above. |
| **`ScansView`** | A `StageProgress` checklist of the nine real pipeline stages: a tick for done, a dot for in progress, a circle for pending, and an em dash for *did not run* once a scan is finished — plus a list of the pipeline's own live counts. |
| **`FindingDetail`** | Restructured so the heading is the plain-language `what_we_found` and the CVE id is demoted beneath it, followed by seven sections: what is the problem, why does it matter, how was it detected, how serious is it, why this priority, what should I do, how do I verify the fix. The duplicate raw description paragraph was removed. |
| `App.tsx`, `router.ts`, `api.ts`, `types.ts`, `styles.css` | Routing and types for the two new tabs; one new `.plain-list-link` style. |

The stage state is exposed to assistive technology as text (`done` / `in progress` / `did not run` /
`pending`) plus `aria-current="step"`, not by icon alone.

## 5. Provider integrations implemented

| Provider | Code | Connected to a live account? |
| --- | --- | --- |
| **Netlify** | OAuth authorization code | **Yes.** A real account was connected and `inspiring-sundae-cbbc16.netlify.app` verified. |
| **Vercel** | OAuth integration + a paste-an-access-token fallback | **Yes, via the token path.** Account `cozyattacker7297`, 4 projects listed, `spacehunt-five.vercel.app` verified. The OAuth integration install stayed blocked on Vercel's side, which is why the token fallback exists. |
| **Cloudflare Pages** | OAuth authorization code + PKCE, `offline_access` refresh | **Yes.** Account connected, **8 Pages projects verified**. The only one of the three that receives a refresh token. |

All three share one abstraction ([providers/base.py](../providers/base.py)), a single-use `state` bound to
both the user and the browser, and Fernet-encrypted tokens bound to their row id.

**On Vercel's later `failed` status:** after the short-expiry token lapsed, the connection moved to `failed`.
That is the design working — ownership is re-established at scan time, so a target whose evidence can no
longer be proven stops counting as verified. It is not a regression.

**Cloudflare, now connected.** This was the one gap in an earlier draft of this report and it is now
closed. Verified in the live database: an OAuth connection to `Shivambhadane12@gmail.com's Account` with
**27 scopes**, and **8 `*.pages.dev` projects** listed and verified through it:

```
aegisfi.pages.dev            portfolio-3a1.pages.dev
arbiter-a40.pages.dev        shivambhadane.pages.dev
gobelki.pages.dev            shivamclasses.pages.dev
hybrid-process-...-orchestrator.pages.dev   timetable-9mt.pages.dev
```

It is the most complete of the three adapters: both an access token *and* a refresh token are stored
encrypted (Netlify and Vercel store no refresh token at all), so `offline_access` worked and Cloudflare's
one-hour access token can be renewed instead of forcing a reconnect.

Two things made it hard, and both were on Cloudflare's side: the *Create an OAuth client* form would not
enable **Continue** without showing a field-level error, and an API token created as a workaround verified
itself as `active` via `/user/tokens/verify` while still being refused for `GET /accounts` (403, code 9109)
and `GET /oauth/scopes` (401, code 10000). The unlock was the scope list, and the identifier worth writing
down is **`pages.metadata_read`** — the read-only Pages scope, which Cloudflare does not publish.

**Still unproven:** that the *refresh exchange* works. The refresh token is stored, but the scan that would
have exercised it was created before the access token expired, so Cloudflare's token endpoint has not yet
been asked to renew. The next scan on a Pages target after an hour's idle will settle it.

## 6. Security considerations

**The "superuser with no authentication" request was declined and replaced.** What was asked for was an
account needing no authentication that could scan any domain. That is the auth-bypass class this project
already found and fixed in its own code (`docs/VALIDATION.md`) and it contradicts
`docs/RULES_OF_ENGAGEMENT.md` §1. What was built instead:

- The admin is **a real signed-in user**. `require_admin` depends on `current_user` — it adds an authorization check on top of authentication and provides no path around it.
- It is **read-only**. There are four `GET` endpoints and no admin write, delete or scan route. Admin status does not relax `check_scan_allowed`, so an admin still cannot scan a domain they have not verified. A test asserts this.
- It returns **404, not 403**, to a non-admin, matching how the rest of the API answers unauthorised reads — so the admin surface is not itself discoverable by probing.
- It is **off by default and not self-grantable**: `is_admin` defaults false and is set only out-of-band by `scripts/grant_admin.py`.
- It exposes **public fields only** — no password hashes, no tokens, no provider secrets. Two existing tests (`test_me_reports_only_public_fields`, `test_the_profile_never_exposes_credentials`) were extended to cover the new field rather than loosened.

**Internal network scanning stayed out, and got narrower.** A Test Labs target needs loopback, which
previously meant the blanket `allow_private_addresses`. That also opened the RFC1918 ranges and the cloud
metadata address `169.254.169.254`. `core/scope.py` now has `allow_loopback_only`, which permits *only*
`127.0.0.1`/`::1`, and the pipeline grants that instead. Net effect: a lab target can reach itself and
nothing else on the host's network. This is a **reduction** in reachable surface, not an addition.

**No exploitation, brute force or destructive testing was added.** The safety floor in
[core/profiles.py](../core/profiles.py) (`FORBIDDEN_TAGS` / `FORBIDDEN_PROTOCOLS`) is non-overridable by any
profile. Observed in the argv of the live `thorough` scan run for this report:

```
-exclude-tags brute-force,bruteforce,ddos,dos,fuzz,fuzzing,intrusive
-exclude-type code,file
-rate-limit 40
```

**The explanation generator cannot hallucinate remediation.** NVD's affected-version ranges are queried live
and never stored, so there is no confirmed "fixed in version X" fact available. Rather than guess one,
`what_to_do` names the version actually detected and states plainly that *"Cerberus does not store a
confirmed patched-version number"*. A test asserts the detected version appears and that the real fixed
versions (2.4.50/51/52) never do. `why_this_priority` reuses the existing, already-tested `reasoning`
sentence rather than generating a second explanation that could drift from the score shown.

**No secrets were added to the repository.** `.env` is gitignored; `.env.example` holds only blank keys.
Provider secrets and tokens stay server-side, encrypted.

**Two problems found in existing code while verifying this work, and fixed:**

*A blank `.env` line silently beat the documented default.* `_load_dotenv` uses `os.environ.setdefault`,
so `PUBLIC_API_URL=` puts an **empty** value into the environment rather than leaving the key absent — and
a default passed as `os.environ.get(key, default)` only applies when the key is missing entirely. The live
`.env` had exactly that, so `public_api_url` was `""` and every OAuth redirect URI came out as the relative
path `/api/v1/providers/cloudflare/callback`, which a provider rejects as a redirect mismatch while
reporting an error that points nowhere near the cause. The same shape would have made
`ACCESS_TOKEN_MINUTES=` a startup crash (`int("")`) and `CORS_ORIGINS=` block the dashboard entirely. Six
getters now treat blank as unset, matching the `or` idiom already used for `DATABASE_URL`; `tests/test_config.py`
pins it, and the test was confirmed to fail against the old line.

*`scripts/add_test_target.py` would mark any domain verified, with `dns_txt` provenance.* Despite its
docstring saying "sanctioned testbed", it accepted any argument — an ownership-verification bypass of the
same class as the superuser request declined above — and recorded `dns_txt`, claiming a DNS TXT record had
been checked when none had. It now refuses anything outside `SANCTIONED_TESTBEDS` (printing the real list)
and writes `verification_method="testbed"`, matching what the API's own testbed route records.

## 7. Tests added

**46 new test functions (54 collected cases — parametrized tests expand):**

| File | New | Covers |
| --- | --- | --- |
| `tests/test_admin.py` | 12 (15 cases) | Admin gating, 404-not-403, read-only, no scan privilege, no credential exposure |
| `tests/test_explain.py` | 12 | Every explanation field; honesty when technology or description is missing; never inventing a patched version |
| `tests/test_pipeline.py` | 5 | `_record_stage`: marks done, points `current` forward, counts accumulate, idempotent, last stage → `current: null`, missing scan is a no-op |
| `tests/test_migrations.py` | 4 | `0009` and `0010` additive with real rows, correct defaults, down/up clean |
| `tests/test_adapters.py` | 3 | `on_stage` fires once per real boundary in order with true counts; never for a stage that did not run; optional |
| `tests/test_api.py` | 2 | `progress` absent until written, then exposed |
| `tests/test_api_views.py` | 1 | Finding detail carries the explanation |
| `tests/test_scope.py` | 1 | `allow_loopback_only` grants nothing but exact loopback |
| `tests/test_scoring.py` | 1 | The four documented weights are the ones actually used, and sum to 1.0 |
| `tests/test_config.py` | 5 (13 cases) | A blank `.env` value falls back to the default, a real value still wins, trailing slashes are stripped, and a blank provider credential stays blank |

Three bugs were caught by these tests during development, not after: `_record_stage` pointed `current`
backwards when stages arrived out of order (fixed to use furthest-reached + 1); a migration test seeded
before the `users` table existed; and the remediation assertion was initially broad enough to match NVD's
own description text.

## 8. Full test result

```
738 passed, 5 skipped, 1 warning in 44.25s
```

| Check | Result |
| --- | --- |
| `pytest` | **738 passed, 5 skipped** |
| `ruff check .` | **Clean — 0 errors.** The 16 long-standing errors (12 in `api/domains.py`, 2 in `scripts/add_test_target.py`, 2 in `core/models.py`) were fixed by the repository owner during this work. |
| `tsc --noEmit` | **Clean** (exit 0) |
| `npm run build` | **Clean** — 420 kB JS / 112 kB gzipped |
| Browser + axe-core | **18/18 mid-scan, 9/9 after completion** (see below) |
| PostgreSQL 16 migrations | **Pass** |

**The browser run was driven by live API state, not fixtures.** Two real scans were started through the
API against the Docker Apache lab, and each check compared the DOM against whatever `GET /api/v1/scans`
reported at that moment — no hardcoded expectations.

**Mid-scan,** with the `thorough` scan still in its vulnerability stage:

```
(api) status=discovering current=vulnerability_scan completed=5
      counts={"subdomains":1,"hosts_resolved":1,"open_ports":10,"technologies":4}
(dom) Authorization=done  Asset discovery=done  DNS resolution=done
      Port & service discovery=done  HTTP discovery=done
      Vulnerability scan=current  Enrichment=pending  Risk analysis=pending  Report=pending
```

**After completion** — the `thorough` scan ran all nine stages (23m 5s, 16 detections, 414 findings), and a
`passive` scan ran six, honestly reporting the three it never reached:

```
thorough  Authorization=done  Asset discovery=done  DNS resolution=done
          Port & service discovery=done  HTTP discovery=done  Vulnerability scan=done
          Enrichment=done  Risk analysis=done  Report=done
passive   Authorization=done  Asset discovery=done  DNS resolution=done
          Port & service discovery=skipped  HTTP discovery=skipped  Vulnerability scan=skipped
          Enrichment=done  Risk analysis=done  Report=done
```

That `passive` row is the case that matters most: the three stages a passive profile never runs are shown
as *did not run*, not as pending (which would imply they are still coming) and not as done (which would be
a lie). No finished scan showed a stage as pending or in progress. axe-core (`wcag2a`, `wcag2aa`,
`wcag21aa`, `best-practice`) reported **0 violations** on every screen and every state, with no console or
page errors.

Run in isolation throughout: API on `:8010`, Vite on `:5190`, against a **copy** of `lab.db` at `/tmp/dev.db`,
with provider credentials blanked. The user's own servers on `:8000`/`:5173` were untouched, and no account
was created in the real Firebase project.

## 9. Remaining limitations

**In this work:**

1. **Cloudflare's refresh exchange has not been exercised.** The connection, the project listing, the verification and the encrypted storage of both tokens are all verified live, but Cloudflare's access token lasts an hour and the scan that would have triggered a renewal was created before it expired. So the stored refresh token has never actually been redeemed. See [§5](#5-provider-integrations-implemented).
2. **The `scored` count in a scan's progress is not scoped to that scan.** `score_pending_findings` re-scores every finding on the account against current KEV/EPSS data, so a passive scan that found nothing still reports `scored: 414`. The number is real, and narrowing it would mean under-reporting work that did happen — so the dashboard label reads **"Findings re-scored (all targets)"** instead, and `core/pipeline.py` carries a comment saying why. Found by running the passive scan for this report, not by a test.
3. **`scans.progress` is written by the process running the scan.** Single-process by design, like the rest of the pipeline. With several API workers the stage recording would need revisiting, exactly as `fail_interrupted_scans` already would.
4. **`AttackSurfaceView` paginates client-side with a 20-page ceiling.** Fine at current data volumes; a very large surface would be truncated. A server-side endpoint was deliberately not added.

**Pre-existing, found during this work and not caused by it:**

5. **Horizontal overflow on `#/scans` at 390px width.** Confirmed pre-existing: it reproduces identically with the row collapsed, before any new content renders.
6. **Three axe violations on the Test Labs screen.** Untouched by this work.
7. **A scan row's `started_at` can disagree with when the run actually happened.** Observed live: scan `deaee4ef` on `shivambhadane.pages.dev` has `started_at` of 2026-10-02 20:57 while its `nuclei` process was started at 02:28 the next morning by the API process that began at 02:25:55, which means the dashboard shows a ~5.5-hour duration for a run that is minutes old. I could not find the code path that re-runs an existing scan row — `POST /api/v1/scans` always inserts a new one, there is no retry or delete route and no scheduler — so this is reported as an unexplained observation rather than a diagnosed bug.
8. **4 high-severity npm advisories** via `firebase` → `@firebase/firestore`. Not in the shipped bundle; `npm audit fix --force` is a breaking change.

**Deliberately out of scope** (the spec excludes them): internal/private-network scanning, scanner agents,
VPC/cloud scanning, SAST/SBOM/dependency/secret scanning, exploitation, brute force, destructive testing,
ML-based scoring.

## 10. Manual setup steps for the providers

Common prerequisites, then each provider. Full detail in [docs/DEPLOYMENT.md §7](DEPLOYMENT.md).

**Before any provider:** set `PROVIDER_TOKEN_ENCRYPTION_KEY` (a Fernet key), `PUBLIC_API_URL` and
`FRONTEND_URL` in `.env`. Each provider's redirect URI is
`{PUBLIC_API_URL}/api/v1/providers/{provider}/callback`. Vercel and Cloudflare refuse an `http://` redirect
URL, so local setup needs HTTPS — `scripts/local_https.sh` creates a name-constrained private CA valid only
for `localhost`/`127.0.0.1`/`::1`.

### Vercel — the access-token path (this is the one that worked)

1. Vercel → **Account Settings → Tokens → Create Token**. Choose a scope and expiry.
2. Copy the token; Vercel shows it once.
3. Cerberus → Targets → Deployment → Vercel → **Use an access token**, paste it. For a team token also enter the **Team ID** (Team Settings → General, starts with `team_`); leave it empty for a personal account. **Connect with token**.
4. Pick a project → **Add & verify**.
5. Delete the token on Vercel when finished. Needs no `VERCEL_*` variables at all.

### Vercel — the OAuth integration path

1. Vercel dashboard → Settings → Integrations → **Create** an Integration (not "Sign in with Vercel", which returns no project list).
2. Redirect URL: the Vercel callback URI above.
3. Copy the Client ID, Secret and the integration slug from the console URL into `VERCEL_CLIENT_ID`, `VERCEL_CLIENT_SECRET`, `VERCEL_INTEGRATION_SLUG`.
4. For anyone other than you to connect, the integration must be made public, which Vercel reviews. This is what stayed blocked here.
5. Cerberus → Targets → Add a deployment → **Connect Vercel**, choose team and projects, then pick a project.

### Netlify

1. Netlify → User settings → **Applications** → OAuth → **New OAuth application**.
2. Redirect URI: the Netlify callback URI above.
3. Copy Client ID and Secret into `NETLIFY_CLIENT_ID` and `NETLIFY_CLIENT_SECRET`.
4. There are no scopes to choose — a Netlify OAuth token can do anything its owner can. Cerberus reads only the site list and forgets the token on disconnect, and the dashboard says so, but revoke the app in Netlify settings when finished.
5. Cerberus → Targets → Add a deployment → **Connect Netlify** → pick a site → **Add & verify**.

### Cloudflare Pages

1. Cloudflare dashboard → create an **OAuth client**: confidential (web), with the Cloudflare callback URI above. If **Continue** stays disabled with no field-level error, that is the known sticking point — it is the scopes in step 2 that unblock it.
2. Scopes: the read-only scopes for listing accounts and reading Pages projects, space-separated, in `CLOUDFLARE_OAUTH_SCOPES`. The one you cannot do without is **`pages.metadata_read`**, the read-only Pages scope, whose identifier Cloudflare does not publish (the full list is served by the authenticated `GET /client/v4/oauth/scopes`). `account-settings.read` is the useful companion. Cerberus appends `offline_access` itself; it does **not** send `openid`, which Cloudflare's OAuth does not use.
3. Copy the client id and secret into `CLOUDFLARE_CLIENT_ID` and `CLOUDFLARE_CLIENT_SECRET`.
4. Cerberus → Targets → Add a deployment → **Connect Cloudflare** → pick a Pages project → **Add & verify**.

Cloudflare issues a one-hour access token, which is why `offline_access` matters: it is the only one of the three providers that gives Cerberus a refresh token.

**Verifying any of them:** `GET /api/v1/providers` (signed in) reports `"configured": true` per provider that
has its credentials and the encryption key.

---

## Acceptance criteria — honest status

Verified against the spec's 32 criteria. **Verified** means it was checked on this machine and the evidence
is named; **Not verified** means it was not, whatever the state of the code.

| # | Criterion | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Authentication required for all user data | **Verified** | `current_user` on every route; `tests/test_auth_api.py` |
| 2 | No unauthenticated privileged access path | **Verified** | `require_admin` depends on `current_user`; `tests/test_admin.py` |
| 3 | Scanning requires a verified, owned domain | **Verified** | `check_scan_allowed`; `tests/test_ownership.py` |
| 4 | Admin cannot bypass ownership | **Verified** | `test_being_admin_does_not_authorise_scanning_someone_elses_domain` |
| 5 | Admin is read-only | **Verified** | Four `GET`s, no write route |
| 6 | Admin surface not discoverable | **Verified** | 404 not 403; `tests/test_admin.py` |
| 7 | Admin off by default, not self-grantable | **Verified** | Migration default false; `scripts/grant_admin.py` only |
| 8 | No credentials exposed in any response | **Verified** | `test_the_profile_never_exposes_credentials` extended, not loosened |
| 9 | DNS TXT verification works | **Verified** | Pre-existing, `tests/test_verification.py` + `tests/test_domains_api.py` |
| 10 | Netlify deployment verification works live | **Verified** | Real account, `inspiring-sundae-cbbc16.netlify.app` |
| 11 | Vercel deployment verification works live | **Verified** | Real account `cozyattacker7297`, `spacehunt-five.vercel.app`, via the token path |
| 12 | Cloudflare OAuth client connects | **Verified** | Live connection, 27 scopes, access + refresh token stored encrypted |
| 13 | Cloudflare Pages projects list and verify | **Verified** | 8 `*.pages.dev` projects listed and verified |
| 14 | Provider tokens encrypted at rest | **Verified** | `test_the_token_is_stored_encrypted_and_bound_to_its_row`, `test_the_token_is_never_returned_by_any_endpoint`, `test_the_token_never_reaches_the_logs` |
| 15 | OAuth `state` single-use, user- and browser-bound | **Verified** | `tests/test_providers_api.py` — replay refused, burned even on a failed exchange, cross-provider reuse refused |
| 16 | Ownership re-checked at scan time | **Verified** | Observed: the expired Vercel token moved the connection to `failed` |
| 17 | Risk formula is KEV 0.35 / EPSS 0.25 / criticality 0.25 / exposure 0.15 | **Verified** | `scoring/engine.py:30`. No test pinned the literal weights, so one was added: `test_the_documented_weights_are_the_ones_actually_used` |
| 18 | Risk bands: critical ≥80, high ≥60, medium ≥40 | **Verified** | `RISK_BANDS`; `test_risk_bands_have_exact_boundaries` (parametrized, `tests/test_api_views.py`) |
| 19 | Findings carry evidence and provenance | **Verified** | Evidence screen; `tests/test_api_views.py` |
| 20 | Inferred and confirmed detections distinguished | **Verified** | `detection_method` surfaced in "How was it detected?" |
| 21 | Explanations deterministic, from stored signals only | **Verified** | `scoring/explain.py`; 12 tests |
| 22 | Explanations never invent remediation | **Verified** | `test_what_to_do_never_invents_a_patched_version` |
| 23 | Explanations honest when data is missing | **Verified** | Two tests for absent technology and absent description |
| 24 | Scan progress reflects real stages, not a timer | **Verified** | Two live scans, mid-run and completed: DOM state matched the API's recorded stages exactly in every case |
| 25 | A stage that did not run is not shown as done | **Verified** | Live passive scan: the 3 stages it never reached rendered as *did not run*, not pending or done |
| 26 | Progress counts are the pipeline's real numbers | **Verified** | Live: `subdomains 1, hosts_resolved 1, open_ports 10, technologies 4, detections 16, findings 414`. See limitation 2 on `scored` |
| 27 | No internal/private-network scanning | **Verified** | `allow_loopback_only`; `tests/test_scope.py` — narrowed, not added |
| 28 | No exploitation, brute force or destructive testing | **Verified** | Safety floor in the live nuclei argv |
| 29 | Attack surface traceable domain → asset → finding | **Verified** | Live: 3 evidence links, 136 finding links |
| 30 | All tests green | **Verified** | 738 passed, 5 skipped |
| 31 | Migrations work on SQLite and PostgreSQL | **Verified** | 4 automated SQLite tests; PostgreSQL 16 up/down/up live |
| 32 | No new lint or type errors | **Verified** | ruff fully clean (0); `tsc` clean; build clean |

**32 of 32 verified.** Criteria 12 and 13 were the two gaps in an earlier draft of this report; both are
now met against a live Cloudflare account. The honest remainder is not an unmet criterion but the narrower
gap in limitation 1 below: the refresh *exchange* has not been exercised yet, only the storing of the
refresh token.

## 11. Commit commands

Nothing has been committed or pushed. To commit this work:

```bash
cd /home/shivam/Desktop/Projects/cerberus

git add core/scope.py core/pipeline.py core/models.py discovery/runner.py \
        scoring/explain.py core/config.py providers/cloudflare.py \
        api/main.py api/schemas.py api/deps.py api/auth.py api/admin.py \
        migrations/versions/0009_admin_flag.py migrations/versions/0010_scan_progress.py \
        scripts/grant_admin.py scripts/add_test_target.py \
        frontend/src/App.tsx frontend/src/api.ts frontend/src/types.ts frontend/src/styles.css \
        frontend/src/lib/router.ts \
        frontend/src/components/ScansView.tsx frontend/src/components/FindingDetail.tsx \
        frontend/src/components/AttackSurfaceView.tsx frontend/src/components/AdminView.tsx \
        tests/ docs/ README.md frontend/README.md .gitignore

git commit -m "feat(v1): real scan progress, plain-language findings, attack surface, read-only admin

Record genuine per-stage scan progress from the pipeline's own boundaries
(scans.progress, migration 0010) and render it as a stage checklist that
distinguishes done, in progress, pending and did-not-run.

Add scoring/explain.py: deterministic finding explanations built only from
stored fields, which name the detected version and state plainly that no
confirmed patched version is stored rather than inventing one.

Add an Attack Surface view tracing verified domain to asset to finding,
frontend-only over existing endpoints.

Replace the requested unauthenticated superuser with an authenticated,
read-only admin role (users.is_admin, migration 0009) that cannot bypass
ownership checks and answers 404 to non-admins.

Narrow the Test Labs network grant from allow_private_addresses to
allow_loopback_only, so a lab target can no longer reach RFC1918 ranges
or the cloud metadata address.

Also fix two problems found while verifying the above: a blank line in .env
silently beat the documented default (so every OAuth redirect URI came out as a
relative path), and scripts/add_test_target.py would mark any domain verified
with false dns_txt provenance.

46 new tests (738 passed, 5 skipped). Migrations verified on SQLite and
PostgreSQL 16. Vercel, Netlify and Cloudflare Pages all verified against live
accounts."
```

Then, when ready:

```bash
git push origin main
```
