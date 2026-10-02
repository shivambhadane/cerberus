# Cerberus — API Documentation

**Base URL:** `http://localhost:8000` (dev) — configured via `API_HOST` / `API_PORT` in [.env](../.env.example)
**Format:** JSON over HTTPS in production; HTTP acceptable for local dev only.

## 1. Authentication

Every endpoint except `GET /healthz` and `/api/v1/auth/{register,login,refresh,logout}` requires a
signed-in user:

```
Authorization: Bearer <access token>
```

The bearer token is one of two things, tried in this order:

1. **A Firebase ID token** (Google, GitHub or email sign-in through the dashboard). It is verified
   against Google's published keys for the configured Firebase project (`FIREBASE_PROJECT_ID`); the
   first request from a new identity creates the account. Name, photo and sign-in method are read from
   the *verified token*, never from the request (`core/profile.py`), and refreshed on each sign-in.
   An address is linked to an existing account only when the provider says it verified it; an
   unverified address gets `401 email_not_verified` rather than someone else's account.
2. **A local access token** from `POST /api/v1/auth/register` or `/login`: a JWT signed with
   `API_SECRET_KEY` that lives about **15 minutes** (`ACCESS_TOKEN_MINUTES`). It carries only the
   user id: it is not a password and cannot be exchanged for one.

The synthetic `test-firebase-token:…` tokens the test suite uses are honoured **only** when the server
was started with `CERBERUS_ALLOW_TEST_TOKENS=1`. That variable is an authentication bypass by design
and must never be set on a real server.

Alongside it the API sets a **refresh token** as an httpOnly, `SameSite=Lax` cookie scoped to
`/api/v1/auth`. `POST /api/v1/auth/refresh` exchanges it for a new access token *and a new refresh
token* — they are single-use. Presenting one that was already used means a copy leaked, so the whole
login is revoked. Browser clients send `credentials: "include"`; the cookie is never readable from
JavaScript.

| Status | Code | What the client should do |
|---|---|---|
| 401 | `token_expired` | Call `/auth/refresh`, then retry the request once. |
| 401 | `unauthorized`, `token_invalid` | Sign in again. |
| 401 | `session_revoked`, `session_expired`, `invalid_session`, `no_session` | Sign in again (on `/auth/refresh`). |

**Everything a user can reach is their own.** Scans, assets, findings and evidence are filtered by
the caller; another user's record is answered exactly like one that does not exist (`404`), so the
API cannot be used to discover what other people hold. `GET /api/v1/enrichment/status` is the one
exception: CVE/KEV/EPSS data is global reference data, readable by any signed-in user.

## 2. Conventions

- All list endpoints are paginated via `limit` (default 20, max 100) and `offset`.
- Timestamps are ISO 8601 **UTC with an explicit zone** (`2026-09-20T06:24:23Z`). Clients convert for display; the dashboard shows Indian Standard Time (`frontend/src/lib/format.ts`).
- IDs are UUIDs.
- Errors follow a consistent shape (see [§6](#6-error-format)).

## 3. Endpoints

### `POST /api/v1/auth/register`

Create an account and sign in. Rate limited per client address.

**Request body:** `{ "email": "you@example.com", "password": "...", "name": "Optional" }`

Passwords must be 5–128 characters and must not be the email address; length is the rule, not
composition (NIST SP 800-63B). They are stored as Argon2id hashes and never returned.

The 5-character floor is set low for convenience in this portfolio project (`MIN_PASSWORD_LENGTH` in
`core/security.py`); it is not a defensible minimum for a real deployment.

**Response — `201 Created`** (and a `Set-Cookie` with the refresh token)

```json
{
  "user": {"id": "…", "email": "you@example.com", "name": "", "email_verified": false, "created_at": "…",
           "last_login_at": null, "picture_url": null, "auth_provider": null},
  "access_token": "eyJhbGciOiJIUzI1NiIs…",
  "token_type": "bearer",
  "expires_in": 900
}
```

Errors: `400 invalid_email`, `400 weak_password` (the message says what to change),
`409 email_taken`, `429 too_many_attempts`.

---

### `POST /api/v1/auth/login`

Same response shape as register. Rate limited per account **and** per client address.

A wrong password, an unknown email and a disabled account all return the same
`401 invalid_credentials`, and take the same time, so the endpoint cannot be used to find out which
addresses have accounts.

---

### `POST /api/v1/auth/refresh`

Exchanges the refresh cookie for a new access token and a new refresh cookie. Takes no body.

---

### `POST /api/v1/auth/logout`

Ends the session and clears the cookie. `204 No Content`, and safe to call twice.

---

### `GET /api/v1/auth/me`

```json
{
  "id": "…", "email": "you@example.com", "name": "Shivam", "email_verified": true, "created_at": "…",
  "last_login_at": "2026-09-20T10:15:00Z",
  "picture_url": "https://lh3.googleusercontent.com/a/…",
  "auth_provider": "google.com"
}
```

`picture_url` (an `https` URL only; anything else is dropped) and `auth_provider` (`google.com`,
`github.com`, `password`) come from the sign-in provider's verified token and are `null` for accounts
that have only used the local password login. The dashboard's Profile page shows them.

---

### `POST /api/v1/domains`

Claim a domain. Claiming is not owning: the domain starts `pending` and cannot be scanned until it
is verified.

**Request body:** `{ "domain": "example.com" }` — a bare name; URLs, ports, paths, wildcards and IP
addresses are refused with `400 invalid_domain`.

**Response — `201 Created`**

```json
{
  "id": "…",
  "domain": "example.com",
  "verification_status": "pending",
  "verification_method": "dns_txt",
  "verified_at": null,
  "created_at": "…",
  "provider": null,
  "provider_project_id": null,
  "verification": {
    "method": "dns_txt",
    "record_type": "TXT",
    "record_name": "_cerberus-challenge.example.com",
    "record_value": "cerberus-verify=<secret token>"
  }
}
```

`record_value` contains a secret unique to this claim, and is only ever returned to the claimant.
Errors: `409 domain_exists`, `400 domain_limit` (25 per account).

A domain in this response is verified by **DNS**. A deployment on Vercel, Netlify or Cloudflare Pages
can instead be verified through the owner's connected platform account
([`POST /api/v1/domains/provider`](#post-apiv1domainsprovider)). Such a domain has `provider` set to
`vercel`, `netlify` or `cloudflare`, `verification_method` equal to that name, and `verification` is
`null`: there is no DNS record to publish. DNS verification is unchanged and remains the only way to
verify a custom domain.

---

### `GET /api/v1/domains`, `GET /api/v1/domains/{id}`

Your domains only. Another user's id returns `404 not_found`, identical to an id that does not exist.

---

### `POST /api/v1/domains/{id}/verify`

Look for the TXT record now. Rate limited per account (30/hour).

**Response — `200 OK`** — whether or not it verified, because a record that has not propagated yet is
a normal state, not an error:

```json
{
  "verified": false,
  "reason": "record_not_found",
  "detail": "No TXT record found at _cerberus-challenge.example.com. DNS changes can take a few minutes…",
  "domain": { "...": "the domain, with its current status" }
}
```

`reason` is one of `verified`, `record_not_found`, `token_mismatch`, `lookup_failed`.
`lookup_failed` means DNS could not be reached and says nothing about the record — it is deliberately
distinct from "not there". If another account has already verified that domain, `409
domain_already_verified`: whoever proves control first owns it.

---

### `POST /api/v1/domains/provider`

**Add & verify** a deployment in one step, using a connected platform account. The response is the
domain, already `verified` — or an error, and nothing is created.

**Request body**

```json
{ "connection_id": "…", "project_id": "prj_abc123", "hostname": "college-erp.vercel.app" }
```

None of the three is trusted. `connection_id` must be one of the caller's own; the project is then
fetched **from the platform, with that connection's token**, so the platform decides whether this
account can see it; and `hostname` must be one the platform itself lists on that project. Any failed
step is `403 ownership_not_proven`, and a connection that is not yours is `404 connection_not_found`,
identical to one that does not exist.

Only the platform's own free addresses can be verified this way: exactly one label under
`vercel.app`, `netlify.app` or `pages.dev` (`400 not_a_platform_hostname` otherwise). A custom domain
attached to a project proves nothing about DNS control; add it with `POST /api/v1/domains` and verify
it with a TXT record.

**Response — `200 OK`**

```json
{
  "id": "…", "domain": "college-erp.vercel.app", "verification_status": "verified",
  "verification_method": "vercel", "verified_at": "…", "created_at": "…",
  "provider": "vercel", "provider_project_id": "prj_abc123", "verification": null
}
```

Errors: `400 not_a_platform_hostname`, `400 invalid_domain`, `403 ownership_not_proven`,
`404 connection_not_found`, `409 connection_expired`, `409 domain_already_verified`,
`429 too_many_attempts`, `502 provider_error`, `503 provider_unavailable`,
`503 provider_not_configured` — see [§ Provider errors](#provider-errors).

---

### `POST /api/v1/domains/{id}/verify/provider`

Verify an existing `pending` or `failed` target of yours through a connected account. **Request body:**
`{ "connection_id": "…", "project_id": "…" }`: the hostname is the target's own and is not accepted from
the client. Response and errors as above. This is how a target whose connection was disconnected, or
whose project was removed, is verified again.

---

### `GET /api/v1/providers`

The deployment providers this server supports, and the caller's connections to each.

```json
{
  "providers": [
    { "provider": "vercel", "label": "Vercel", "configured": true,
      "connections": [ { "id": "…", "provider": "vercel", "label": "Vercel: shivam-dev",
                         "connected_at": "…", "scopes": ["project", "user", "team"] } ] },
    { "provider": "netlify", "label": "Netlify", "configured": false, "connections": [] }
  ]
}
```

`configured: false` means the operator has not registered an OAuth app (or set
`PROVIDER_TOKEN_ENCRYPTION_KEY`) on this server, so the OAuth flow cannot be used. `token_paste: true` means an
access token can be pasted instead ([below](#post-apiv1providersprovidertoken)); it needs only the encryption key
and is offered for Vercel. A connection's `method` is `"oauth"` or `"token"`. A connection carries **no token,
secret or refresh token**: those never leave the server.

---

### `POST /api/v1/providers/{provider}/connect`

Start connecting an account. `{provider}` is `vercel`, `netlify` or `cloudflare` (else `404`). Takes no
body.

**Response — `200 OK`:** `{ "authorization_url": "https://…" }` — the platform's consent page, with a
random `state` (and, for Cloudflare, a PKCE challenge) already attached. The dashboard navigates the
browser there and refuses anything that is not `https:`. The response also sets an httpOnly
`cerberus_oauth` cookie, scoped to `/api/v1/providers` and valid for 10 minutes, which ties the flow to
this browser.

Errors: `503 provider_not_configured`, `429 too_many_pending` (10 unfinished flows per account),
`400 too_many_connections` (10 per account).

---

### `POST /api/v1/providers/{provider}/token`

Connect with an **access token** the person made on the platform, instead of OAuth. Vercel only for now
(`token_paste` in `GET /providers` says where). It exists because Vercel's OAuth needs an *integration* the
operator has to create and, for other people to use it, publish; a token needs none of that.

**Request body:** `{ "token": "…", "team_id": "team_…" }`. `team_id` is optional and only for a token limited to
a team; it must look like `team_` followed by letters and digits.

The token is checked for shape (8–512 characters from a bearer token's alphabet; surrounding whitespace and
quotes from copy-paste are trimmed, anything else is refused), then **used at once** to ask the platform who it
belongs to (`GET /v2/user`). That answer, never the request, becomes the connection's account id. It is stored
encrypted exactly like an OAuth token and **never returned, logged or shown again**. Pasting a new token for the
same account updates the same connection, so targets it verified stay verified.

**Response — `200 OK`:** a connection, with `"method": "token"`.

Errors: `400 invalid_token` (wrong shape, or the platform did not accept it; the message never repeats the value),
`400 not_supported` (a provider with no token option), `400 too_many_connections`, `404 not_found` (unknown
provider), `429 too_many_attempts` (10 wrong tokens per hour per account; correct ones are not counted),
`502 provider_error`, `503 provider_unavailable`, `503 provider_not_configured` (no encryption key).

Everything done with a token connection (project list, Add & verify, the scan-time re-check, disconnect) goes
through the same code and the same isolation as an OAuth one. A token that later expires or is revoked is
`409 connection_expired`, and the dashboard asks for a new token instead of sending the person to the platform.

---

### `GET /api/v1/providers/{provider}/callback`

Where the **platform** sends the browser after consent. It is registered with the platform as the
redirect URI (`{PUBLIC_API_URL}/api/v1/providers/{provider}/callback`) and is not for API clients: it
takes no bearer token (the browser arrives from another site), and it answers with a `303` back to the
dashboard, never with JSON:

- success — `{FRONTEND_URL}/platform/#/domains?provider=vercel&connected=1&account=<connection id>`
- failure — `{FRONTEND_URL}/platform/#/domains?provider=vercel&error=<code>`

`error` is `access_denied` (the person declined), or one of `invalid_state`, `authorization_failed`,
`provider_not_configured`, `provider_unavailable`, `too_many_connections`, `provider_error`. It is a
short code we chose, never text from the platform, and a token or authorisation code is never put in
the URL. The callback completes only if the `state` is known, unused, unexpired, issued for this
provider, and presented by the browser that started the flow (the `cerberus_oauth` cookie); the `state`
is single-use. Everything else is `invalid_state` and reveals nothing about why.

---

### `GET /api/v1/connections`

The caller's connections across all providers, oldest first: `[ { "id", "provider", "label",
"connected_at", "scopes" } ]`. Never includes a token.

---

### `GET /api/v1/connections/{id}/projects`

The projects the connected account controls, read live from the platform with the stored token
(refreshed first when it has expired and a refresh token exists).

```json
{
  "connection": { "id": "…", "provider": "vercel", "label": "Vercel: shivam-dev", "connected_at": "…", "scopes": [] },
  "projects": [
    { "id": "prj_abc123", "name": "college-erp",
      "hostnames": ["college-erp.vercel.app"],
      "verified_hostnames": [] }
  ]
}
```

`hostnames` lists only the platform addresses that can be verified (`*.vercel.app` and the like);
`verified_hostnames` is the subset the caller has already added. Ids and names are the platform's, not
the caller's. Listing projects and Add & verify share one limit of 60 requests per hour per account. Errors: `404 connection_not_found`,
`409 connection_expired`, `502 provider_error`, `503 provider_unavailable`.

---

### `POST /api/v1/connections/{id}/disconnect`

Forget a connection: its stored tokens are deleted and it is removed. Takes no body.

```json
{ "disconnected": true, "targets_reset": 2 }
```

Every target that connection verified goes back to `pending` (`targets_reset` says how many) and
**cannot be scanned** until it is verified again, by DNS or through a connection. Nothing is changed on
the platform: the OAuth app also stays authorised on the platform's side until the person removes it
there, which the dashboard tells them. Disconnecting a connection that is not yours is
`404 connection_not_found`.

---

### `GET /api/v1/domains/testbeds`

**Test Labs.** The fixed list of sanctioned public benchmark sites (Acunetix TestASP/TestPHP, IBM Altoro
Mutual) and local Docker labs (the built-in Apache CVE lab, OWASP Juice Shop, DVWA) that Cerberus knows
about, annotated with whether the caller has already added and verified each one.

```json
{
  "total": 6,
  "testbeds": [
    {
      "id": "apache-lab", "name": "Cerberus Apache 2.4.49/50 Lab", "category": "docker",
      "domain": "127.0.0.1", "url": "http://127.0.0.1:18081", "ports": [18081, 18082],
      "docker_command": "docker compose -f lab/docker-compose.yml up -d",
      "docker_teardown": "docker compose -f lab/docker-compose.yml down",
      "description": "…", "vulnerabilities": ["CVE-2021-41773 …"], "tags": ["Docker Lab", "CISA KEV"],
      "provider_disclaimer": "Controlled repeatable Docker testbed bound to 127.0.0.1.",
      "already_added": false, "domain_id": null
    }
  ]
}
```

The list itself (`SANCTIONED_TESTBEDS` in `api/domains.py`) is a hardcoded allowlist, not something a
client can extend: no domain outside it can be added through this endpoint.

---

### `POST /api/v1/domains/testbeds/{id}`

Add one of the testbeds above as an **immediately verified** target — no DNS record, no connected
platform account. `{id}` is one of the ids this endpoint's `GET` lists (`apache-lab`, `juice-shop`,
`dvwa`, `testasp`, `testphp`, `demo-testfire`); anything else is `404 not_found`.

**Response — `200 OK`:** the domain, already `verification_status: "verified"` and
`verification_method: "testbed"`.

**Security note, stated plainly:** this is the one path in the API where "verified" does not mean DNS or
platform-account proof — it means *the operator shipped this address on a fixed allowlist*. For the three
Docker labs, the domain is `127.0.0.1`, and `core/pipeline.py` grants that one scan `allow_loopback_only`
(`core/scope.py`): the exact loopback addresses only, never the RFC1918 ranges or the cloud metadata
address a blanket private-address allowance would also open. That any signed-in user can reach this
server's own loopback interface at all is intentional for a single-operator install (you are the only
"any signed-in user"), and worth gating on a shared deployment — see
[DEPLOYMENT.md §5](DEPLOYMENT.md#5-scanning-from-the-deployed-api).

Errors: `404 not_found` (unknown testbed id), `400 domain_limit` (25 domains per account),
`409 domain_exists` (a race against a concurrent request for the same testbed).

---

### `POST /api/v1/scans`

Run the discovery → enrichment → scoring pipeline against a domain **you have verified**.

**Request body**

```json
{
  "domain_id": "b3f1c2e0-…",
  "profile": "safe",
  "accept_profile": false
}
```

| Field | Notes |
|---|---|
| `domain_id` | A verified domain of yours. The scan's scope is that domain and its subdomains. |
| `profile` | `passive`, `safe` (default) or `thorough`. Governs what scanners may do; see [RoE §4](RULES_OF_ENGAGEMENT.md#4-scan-profiles). |
| `accept_profile` | Must be `true` to use an intrusive profile (`thorough`). Refused with `400 invalid_profile` otherwise. |

There is deliberately **no** `authorized` field. A caller asserting "I am authorised" is not evidence
of anything; the evidence is the verified domain, checked server-side on every request
(`core/ownership.py`). Nor is there a field to permit private or loopback addresses: that is
operator-level configuration (`discovery.allow_private_addresses`), because a caller who could set it
could aim the server at its own internal network. The one exception is a Test Labs target
(`verification_method` `testbed`/`lab`), always exactly `127.0.0.1`/`localhost`/`::1`, for which the
pipeline grants only the exact loopback address (`core/scope.py`'s `allow_loopback_only`) — never the
RFC1918 ranges or the cloud metadata address a caller-supplied flag would risk.

**Real per-stage progress.** While a scan runs, `GET /api/v1/scans/{id}` and `GET /api/v1/scans` (in
each row) carry a `progress` object, updated as each real pipeline stage genuinely finishes - never a
timer, never a guess:

```json
{
  "progress": {
    "stages": ["authorization", "asset_discovery", "dns_resolution", "port_service_discovery",
               "http_discovery", "vulnerability_scan", "enrichment", "risk_analysis", "report"],
    "completed": ["authorization", "asset_discovery", "dns_resolution", "port_service_discovery"],
    "current": "http_discovery",
    "counts": {"subdomains": 1, "hosts_resolved": 1, "open_ports": 2}
  }
}
```

`progress` is `null` for a scan the background task has not written anything for yet - never a
fabricated 0%. A stage absent from `completed` once the scan has finished (`status: "completed"`)
simply never ran for that profile (a `passive` scan stops after `dns_resolution`); it is never invented
to make the checklist look busier than the scan actually was. See `core/pipeline.py`'s `SCAN_STAGES`
and `_record_stage`, and `discovery/runner.py`'s `on_stage` callback, which is the only thing allowed
to report a stage done.

Errors: `404 not_found` (no such domain **or** it is not yours), `403 domain_not_verified`,
`409 scan_in_progress` (one scan at a time per account), `400 invalid_profile`.

**Response — `202 Accepted`**

```json
{
  "scan_id": "b3f1c2e0-1234-4a56-9abc-def012345678",
  "status": "pending",
  "profile": "safe"
}
```

---

### `GET /api/v1/scans`

Scan history, newest first, with how much each scan recorded.

**Query params:** `limit` (default 20, max 100), `offset`.

**Response — `200 OK`**

```json
{
  "total": 3,
  "scans": [
    {
      "scan_id": "b3f1c2e0-...",
      "target_domain": "example.com",
      "profile": "safe",
      "status": "completed",
      "started_at": "2026-09-19T10:00:00Z",
      "completed_at": "2026-09-19T10:13:22Z",
      "error": null,
      "warnings": ["nuclei: nuclei timed out after 1800s"],
      "observation_count": 5
    }
  ]
}
```

`warnings` are non-fatal problems: a scanner that failed to run, or a stale enrichment cache. A scan
can be `completed` and still have been degraded; without this the only trace was CLI output.

---

### `GET /api/v1/scans/{scan_id}`

Check the status of a running or completed scan.

**Response — `200 OK`**

```json
{
  "scan_id": "b3f1c2e0-1234-4a56-9abc-def012345678",
  "target_domain": "example.com",
  "profile": "safe",
  "status": "completed",
  "started_at": "2026-09-13T10:00:00Z",
  "completed_at": "2026-09-13T10:04:12Z",
  "error": null,
  "warnings": []
}
```

`error` carries the failure reason when `status` is `failed`, and is `null` otherwise.

`status` is one of: `pending`, `discovering`, `enriching`, `scoring`, `completed`, `failed`.

---

### `GET /api/v1/assets`

List discovered assets.

**Query params**

| Param | Type | Default | Notes |
|---|---|---|---|
| `tenant_id` | uuid | — | required in multi-tenant deployments |
| `scan_id` | uuid | — | filter to assets from one scan |
| `limit` | int | 20 | |
| `offset` | int | 0 | |

**Response — `200 OK`**

```json
{
  "total": 42,
  "assets": [
    {
      "id": "a1b2c3d4-...",
      "hostname": "api.example.com",
      "ip_address": "203.0.113.10",
      "port": 443,
      "protocol": "tcp",
      "technology": "nginx/1.24",
      "discovered_by_tool": "nmap",
      "criticality": "high",
      "criticality_reason": "hostname indicates a production or data-tier system",
      "criticality_source": "heuristic",
      "finding_count": 12,
      "first_seen_at": "2026-08-01T00:00:00Z",
      "last_seen_at": "2026-09-13T10:04:00Z"
    }
  ]
}
```

`criticality_source` is `heuristic` (a guess from the hostname and port) or `manual` (a person's
decision). Only the second survives a re-scan.

---

### `PATCH /api/v1/assets/{asset_id}/criticality`

Set how much an asset matters. Criticality is 25% of every finding's score by default, so this
changes the ranking.

**Request body**

```json
{ "level": "critical", "reason": "customer-facing checkout" }
```

`level` is one of `low`, `medium`, `high`, `critical`; `reason` is optional (max 500 characters,
defaults to "set manually") and appears in the score's explanation.

**Response — `200 OK`:** the updated asset. The asset's findings are re-scored immediately, and only
that asset's, so the ranking is not left stale until the next scan. `400 invalid_request` for an
unknown level, `404 not_found` for an unknown asset.

---

### `GET /api/v1/findings`

The core endpoint: ranked, explainable findings. Matches [README usage example](../README.md#api).

**Query params**

| Param | Type | Default | Notes |
|---|---|---|---|
| `tenant_id` | uuid | — | |
| `sort` | string | `risk_score` | `risk_score` \| `detected_at` \| `cvss_score` \| `epss_score` |
| `order` | string | `desc` | `asc` \| `desc` |
| `limit` | int | 20 | max 100 |
| `offset` | int | 0 | |
| `min_risk_score` | float | — | filter, e.g. `min_risk_score=70` |
| `kev_only` | boolean | false | only findings with `kev_listed: true` |
| `q` | string | — | case-insensitive match on CVE id or hostname (max 100 chars) |
| `status` | string | — | comma-separated `open`, `acknowledged`, `resolved`, `false_positive`, or `active` (= open + acknowledged). Unknown values are `400` |
| `detection_method` | string | — | `version_inference` or `active_detection` |
| `asset_id` | uuid | — | findings for one asset |

**Response — `200 OK`**

```json
{
  "total": 7,
  "findings": [
    {
      "id": "f1e2d3c4-...",
      "asset_id": "a1b2c3d4-...",
      "asset": "api.example.com:443",
      "cve_id": "CVE-2021-41773",
      "cvss_score": 9.8,
      "kev_listed": true,
      "epss_score": 0.99992,
      "asset_criticality": "high",
      "risk_score": 89.6,
      "status": "open",
      "reasoning": "Actively exploited (CISA KEV, added 2021-11-03); 100% predicted exploitation probability (EPSS); high-criticality asset (hostname indicates a production or data-tier system); internet-facing web service on port 443, critical severity (CVSS 9.8); confirmed by active probe.",
      "detection_method": "active_detection",
      "detected_by_tool": "nuclei",
      "detected_at": "2026-09-13T10:04:00Z"
    }
  ]
}
```

`asset` is rendered as `hostname:port`; `asset_id` links it to `/api/v1/assets`. Results default to
`risk_score` descending. Findings with no value for the sort column (an unscored finding, or one
with no CVSS) sort **last** in either direction, and ties break on CVE id then finding id so paging
is stable.

`detection_method` says how strongly the finding is evidenced, and is **not** an input to the
risk score:

| Value | Meaning |
|---|---|
| `version_inference` | The service reported a version that NVD lists as affected. A claim about the version, not a test of the host. |
| `active_detection` | A scanner probe (nuclei) matched against the target. Detection evidence that the weakness is present and reachable — not evidence of compromise. |

An `active_detection` supersedes a `version_inference` for the same asset and CVE rather than
creating a second finding.

---

### `GET /api/v1/findings/{finding_id}`

Full detail for a single finding, including enrichment source data.

**Response — `200 OK`**

```json
{
  "id": "f1e2d3c4-...",
  "asset": {
    "id": "a1b2c3d4-...",
    "hostname": "api.example.com",
    "port": 443
  },
  "cve_id": "CVE-2021-41773",
  "cvss_score": 9.8,
  "kev_listed": true,
  "kev_date_added": "2021-11-03",
  "epss_score": 0.99992,
  "has_public_exploit": true,
  "asset_criticality": "high",
  "asset_criticality_source": "heuristic",
  "asset_criticality_reason": "hostname indicates a production or data-tier system",
  "risk_score": 89.6,
  "status": "open",
  "reasoning": "Actively exploited (CISA KEV, added 2021-11-03); 100% predicted exploitation probability (EPSS); high-criticality asset (hostname indicates a production or data-tier system); internet-facing web service on port 443, critical severity (CVSS 9.8).",
  "description": "A flaw in Apache HTTP Server 2.4.49 allows path traversal...",
  "detection_method": "active_detection",
  "detected_by_tool": "nuclei",
  "evidence": "Detected by nuclei template 'CVE-2021-41773' (high severity) matching at http://api.example.com:443/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd. This is detection evidence that the weakness is present and reachable, not evidence of compromise.",
  "detected_at": "2026-09-13T10:04:00Z",
  "explanation": {
    "what_we_found": "Your server at api.example.com:443 is running Apache httpd/2.4.49, which is affected by CVE-2021-41773, a known security vulnerability.",
    "what_is_the_problem": "A flaw in Apache HTTP Server 2.4.49 allows path traversal...",
    "why_it_matters": "This system is reachable from the internet, so anyone can attempt to use this weakness. CISA's Known Exploited Vulnerabilities catalog lists this as being actively used by attackers right now, not just theoretically possible.",
    "how_it_was_detected": {
      "host": "api.example.com", "port": 443, "technology": "Apache httpd/2.4.49",
      "detection_method": "active_detection", "detected_by_tool": "nuclei"
    },
    "how_serious": {
      "risk_score": 89.6, "cvss_score": 9.8, "epss_score": 0.99992,
      "kev_listed": true, "asset_criticality": "high"
    },
    "why_this_priority": "Actively exploited (CISA KEV, added 2021-11-03); 100% predicted exploitation probability (EPSS); high-criticality asset (hostname indicates a production or data-tier system); internet-facing web service on port 443, critical severity (CVSS 9.8).",
    "what_to_do": "Update Apache httpd beyond the version currently detected (Apache httpd/2.4.49). Cerberus does not store a confirmed patched-version number - check the vendor's own release notes or security advisories for CVE-2021-41773 to find the exact version that fixes it, then apply it.",
    "how_to_verify": "Apply the fix, then start a new scan of this target. If this finding no longer appears in your ranked list, it worked. If it still appears, confirm the update was actually installed and that the affected service was restarted."
  }
}
```

`explanation` answers the question a developer actually asks, in order, before the raw CVE/CVSS/CPE
numbers (those stay in the response too, for anyone who wants them). It is **computed at read time from
data already stored on the finding** (`scoring/explain.py`), not a model and not a new column: the same
`reasoning` sentence shown elsewhere powers `why_this_priority` directly, so there is only ever one
explanation of why a finding ranks where it does. `what_to_do` never invents a patched-version number -
NVD's affected-version ranges are queried live and not stored (see [code.md](code.md)), so the only
honest remediation fact Cerberus has is the technology string it actually detected.

---

### `PATCH /api/v1/findings/{finding_id}`

Update a finding's status (e.g. after remediation).

**Request body**

```json
{ "status": "resolved" }
```

`status` is one of: `open`, `acknowledged`, `resolved`, `false_positive`.

**Response — `200 OK`** — the updated finding object (same shape as `GET /api/v1/findings/{finding_id}`).

---

### `GET /api/v1/observations`

Raw, tool-attributed output exactly as recorded before normalization. Every asset and finding
traces back to rows here: an asset says what Cerberus concluded, an observation says what a
tool actually saw.

**Query params**

| Param | Type | Default | Notes |
|---|---|---|---|
| `scan_id` | uuid | — | observations from one scan |
| `kind` | string | — | `subdomain` \| `open_port` \| `technology` \| `vulnerability` |
| `source_tool` | string | — | e.g. `nmap`, `nuclei`, `tcp_connect`, `crtsh` |
| `target` | string | — | exact `host:port`: the evidence behind one asset |
| `limit` | int | 50 | max 200 |
| `offset` | int | 0 | |

**Response — `200 OK`**

```json
{
  "total": 6,
  "observations": [
    {
      "id": "0d6e...",
      "scan_id": "b3f1c2e0-...",
      "kind": "vulnerability",
      "target": "127.0.0.1:18081",
      "source_tool": "nuclei",
      "source_version": "v3.11.1",
      "data": {
        "template_id": "CVE-2021-41773",
        "severity": "high",
        "cve_ids": ["CVE-2021-41773"],
        "matched_at": "http://127.0.0.1:18081/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        "profile": "safe"
      },
      "observed_at": "2026-09-18T15:48:09Z"
    }
  ]
}
```

---

### `GET /api/v1/overview`

The headline numbers for the dashboard's landing page, computed in the database so a client does not
have to download every finding to count them.

**Response — `200 OK`**

```json
{
  "findings": {
    "active": 136,
    "actively_exploited": 5,
    "confirmed": 1,
    "by_risk_band": { "critical": 5, "high": 2, "medium": 18, "low": 111, "unscored": 0 },
    "by_detection": { "active_detection": 1, "version_inference": 135 }
  },
  "assets": {
    "total": 2,
    "by_criticality": { "low": 0, "medium": 1, "high": 0, "critical": 1, "unset": 0 }
  },
  "scans_total": 1,
  "last_scan": {
    "scan_id": "98d5a8ff-...",
    "target_domain": "127.0.0.1",
    "profile": "safe",
    "status": "completed",
    "started_at": "2026-09-18T16:11:12Z",
    "completed_at": "2026-09-18T16:24:33Z",
    "error": null,
    "warnings": [],
    "observation_count": 5
  }
}
```

- Every `findings` figure counts **active** findings only (`open` and `acknowledged`), the same set
  `GET /api/v1/findings` returns by default, so the numbers on the overview always match the list they
  link to. `actively_exploited` is the subset listed in CISA KEV; `confirmed` is the subset detected by a
  scanner probe (`active_detection`).
- `by_risk_band` uses the bands defined once in `scoring/engine.py` (`RISK_BANDS`: critical 80 and up,
  high 60, medium 40, low below). A finding with no score is counted as `unscored`. The four bands plus
  `unscored` always sum to `active`.
- Every key is always present, with `0` where nothing matched, so a client never has to default missing
  keys.
- `last_scan` is `null` until the first scan has been started.

---

### `GET /api/v1/enrichment/status`

Check when global enrichment sources were last refreshed. Useful for confirming scoring is using current KEV/EPSS data.

**Response — `200 OK`**

```json
{
  "sources": [
    { "name": "epss", "last_refreshed_at": "2026-09-13T00:00:00Z", "record_count": 1709 },
    { "name": "kev", "last_refreshed_at": "2026-09-13T00:00:00Z", "record_count": 1709 }
  ]
}
```

---

### `GET /healthz`

Unauthenticated liveness check.

**Response — `200 OK`**

```json
{ "status": "ok" }
```

## 4. Deployment providers

Users without a custom domain can prove control of an app on **Vercel**, **Netlify** or **Cloudflare
Pages** by connecting the account it is deployed on. It is an addition to DNS TXT verification, not a
replacement: nothing about DNS verification, or about which targets may be scanned, changed.

### 4.1 What can be verified

Only the address a platform gives an app for free, and only when it is exactly one label under the
platform's suffix:

| Provider | Verifiable address | Not verifiable this way |
|---|---|---|
| Vercel | `<name>.vercel.app` | any custom domain attached to the project |
| Netlify | `<name>.netlify.app` | any custom domain attached to the site |
| Cloudflare Pages | `<name>.pages.dev` | any custom domain attached to the project |

A custom domain that is *listed on a project* proves nothing about who controls its DNS: platforms let
an account attach a domain it does not control (Netlify does not require DNS to point at it first), so
accepting "it is on my project" would let anyone "verify" somebody else's domain. Custom domains keep
using DNS TXT verification, and the dashboard says so where a project lists one.

### 4.2 The verification process

1. **Connect.** `POST /providers/{provider}/connect` creates a random `state` (256 bits, stored only as
   a hash), a browser-binding cookie and, for Cloudflare, a PKCE verifier, and returns the platform's
   consent URL. The person approves on the platform's own site.
2. **Callback.** The platform redirects to `GET /providers/{provider}/callback` with a `code` and the
   `state`. Cerberus checks the state (below), exchanges the code for tokens **on the server**, then asks
   the platform who the token belongs to (`GET /user` or equivalent) and stores that as the connection's
   account id. The account id is never taken from the browser. The browser is sent back to the dashboard
   with a short outcome code and no token.
3. **Choose.** `GET /connections/{id}/projects` lists the projects that account controls, read live from
   the platform, and the platform addresses on each.
4. **Add & verify.** `POST /domains/provider` sends three ids. Cerberus fetches that project from the
   platform **using that connection's token**: a project the account cannot see is refused by the
   platform, not guessed at here. The hostname must then be one the platform itself reports for that
   project. The target is stored `verified`, with `provider`, `provider_connection_id`,
   `provider_project_id` and `provider_resource_id` (the team or account it sits under).
5. **Scan.** Scanning is authorised by exactly the same rule as before (see §4.5).

### 4.3 Security model

| Concern | What is done |
|---|---|
| Authorization-code flow only | The token is obtained server-to-server. It is never in a URL, a redirect, or a response to the browser. Netlify's implicit grant, which would put the token in the browser, is not used. |
| `state` | Random, single-use, expires in 10 minutes, bound to the user **and** provider that started it, stored only as a hash. It is burned before anything else can fail, so a replayed callback never gets a second attempt. |
| Browser binding | The `cerberus_oauth` cookie (httpOnly, `SameSite=Lax`, `Secure` under `COOKIE_SECURE=1`, path `/api/v1/providers`) is checked against a hash stored with the state. A link forwarded to someone else, or a page trying to finish another person's flow, fails. |
| Refusals are uniform | A missing, unknown, reused, expired, wrong-provider, wrong-browser or wrong-user state all produce the same `invalid_state`, so the callback cannot be used to probe. |
| Redirect URI | Built only from `PUBLIC_API_URL` and the provider name, never from the request, and must match what is registered with the platform exactly. |
| PKCE | Used for Cloudflare (S256). The verifier is encrypted at rest and single-use. |
| Secrets | Client secrets and the encryption key exist only in the server's environment. The browser is given a provider's consent URL and nothing else about it. |
| Provider ids are not trusted | `connection_id`, `project_id` and `hostname` come from the browser and are each re-checked: the connection must be the caller's, the project must be visible to that connection's token on the platform, and the hostname must be listed on that project. Ids are also validated before they are put in a URL path. |
| Isolation | Another user's connection, domain or project is `404`, identical to one that does not exist. A domain can be verified by only one account at a time (the existing partial unique index), whichever proves control first. |
| Provider 401 | A platform rejecting a stored token is `409 connection_expired`, never our own `401`, which would sign the person out of Cerberus. |
| Rate limits | Project listing and Add & verify: 60/hour per account. Wrong access tokens: 10/hour per account. Unfinished OAuth flows: 10 per account. Connections: 10 per account. |
| Pasted access tokens | The one place a secret comes *from* the browser: it is typed once, sent over the same connection as any request, proved by using it, stored encrypted, and cleared from the page as soon as it is sent. No endpoint returns it, an invalid one is never echoed (validation is done in code, not by a schema that would quote it), and it is kept out of logs. |

### 4.4 Token storage

Provider tokens are credentials for someone else's cloud account.

- Encrypted at rest with **Fernet** (AES-128-CBC with an HMAC-SHA-256 tag) under
  `PROVIDER_TOKEN_ENCRYPTION_KEY`, which lives only in the environment, never in the database or the
  repository. Access token, refresh token and PKCE verifier are all encrypted.
- Each ciphertext is **bound to its row**: what is encrypted is `<connection id>\n<token>`, and the id is
  checked on decryption, so a ciphertext copied to another row by someone with write access to the
  database does not decrypt there.
- **Never returned.** No endpoint returns a token, refresh token or client secret, and they are never
  logged. `connected_providers` is the only place they exist.
- **Rotation.** The variable takes several comma-separated keys: the first encrypts, all decrypt.
  Prepend a new key and existing rows keep working until they are rewritten.
- **Loss.** With the key gone, stored tokens cannot be read; people reconnect. Nothing else is lost.
- Only what is needed is kept: from a platform's responses Cerberus uses the account id and label, and
  each project's id, name, owning team or account, and platform addresses. Nothing else in a response
  (repositories, environment variables, deployments) is stored, logged or returned.

### 4.5 Scan authorization is unchanged

A scan is authorised by `core/ownership.py`: the caller owns the domain, it is `verified`, and the
target is inside it. That code, the scanner and the pipeline were not changed. The only addition is a
check at `POST /scans`, run **after** that authorisation passes and before the scan is queued, for a
target that was proved through a platform. It can only make a scan *less* likely to start, never more:

Vercel, Netlify and Cloudflare all release a project's name when it is deleted, and anyone can then
register it. A verification that was true last month must not authorise scanning that name today. So
Cerberus asks the platform again, right then, using the stored connection:

- the platform still lists the address on that project → the scan proceeds;
- the platform says it is no longer this account's → the target becomes `failed`, the scan is refused
  (`403 ownership_lost`), and the person must verify again;
- the token no longer works → `409 connection_expired`; the person reconnects;
- the platform cannot be reached → `503 provider_unavailable`; nothing is changed and the scan does not
  start. **A scan is never started on a proof that could not be re-checked.**

DNS-verified targets skip all of this.

### 4.6 Limitations

- **Nothing was tested against a live Vercel, Netlify or Cloudflare account.** The provider clients are
  written from each platform's documentation and tested against faithful fakes of its responses. The
  first real connection is the real test; expect to adjust field names if a platform's response differs
  from its docs.
- **Vercel access tokens** (the paste option) are broader than Cerberus needs: Vercel has no read-only token, so a
  pasted one can do whatever its owner can do within its scope. Cerberus only reads project names and addresses,
  but the person is trusting it with a powerful secret. The form says so and recommends a token limited to one
  team with a short expiry, deleted on Vercel when finished. A token that expires must be replaced by hand.
- **Vercel** uses an *Integration*. Vercel's newer "Sign in with Vercel" only carries identity, and its
  permissions for making API requests are documented as being in private beta. An Integration must be
  **public** (and pass Vercel's review) before people other than its creator can install it; a private
  one works for your own team only. Scopes are set in the Vercel console, not requested in the URL.
- **Netlify** documents only the implicit grant. Cerberus uses the authorization-code grant, which
  Netlify describes in a blog post and third parties use, but whose token endpoint is **not in Netlify's
  current API reference**. It is unverified here. Netlify OAuth has **no scopes**: the token can do
  anything the person can. Cerberus only reads (`GET /user`, `GET /sites`) and forgets the token on
  disconnect, but the person should also revoke the app in Netlify's settings when finished.
- **Cloudflare**'s OAuth is self-managed (authorization code + PKCE). The identifier of its read-only
  Pages scope is not published in the public docs, so the operator supplies it in
  `CLOUDFLARE_OAUTH_SCOPES`; the provider reports itself as not configured until they do.
- Only free platform addresses can be verified (§4.1). Vercel lists at most 50 projects and Netlify 200
  sites per account, and each connection sees one account or team; connect again for another.
- Tokens are re-checked when used, not continuously: someone who is removed from a team after
  verifying is caught at the next scan, not immediately.
- The callback and the refresh cookie are `SameSite=Lax`, so the dashboard and the API must be on the
  same site (for example `app.example.com` and `api.example.com`, or one origin behind a reverse proxy).
  Use the same host name everywhere: `localhost` and `127.0.0.1` are different sites for cookies.

### 4.7 Provider errors

| HTTP | `code` | Meaning |
|---|---|---|
| 400 | `invalid_state` | The OAuth state was missing, unknown, used, expired or from another browser (callback only, as a redirect code). |
| 400 | `authorization_failed` | The platform refused the authorisation code. |
| 400 | `too_many_connections` | 10 connections per account. Disconnect one. |
| 400 | `invalid_token` | A pasted access token was malformed or not accepted by the platform. |
| 400 | `not_supported` | That provider has no access-token option. |
| 400 | `invalid_team_id` | The `team_id` sent with a pasted token is not shaped like `team_` + letters/digits. Distinct from `invalid_token`: nothing was sent to the platform, and it does not count toward the 10/hour wrong-token limit. |
| 400 | `not_a_platform_hostname` | Not a `*.vercel.app` / `*.netlify.app` / `*.pages.dev` address. Use DNS. |
| 400 | `invalid_domain` | The hostname is not a valid bare domain. |
| 403 | `ownership_not_proven` | The platform does not show that hostname on a project this account controls. |
| 403 | `ownership_lost` | A previously verified target is no longer this account's (raised at scan time). |
| 404 | `connection_not_found` | Not your connection, or none with that id. |
| 404 | `not_found` | Unsupported provider, or not your domain. |
| 409 | `connection_expired` | The stored token stopped working or cannot be refreshed. Reconnect. |
| 409 | `domain_already_verified` | Another account verified that address first. |
| 429 | `too_many_pending` | 10 unfinished OAuth flows. Wait ten minutes. |
| 429 | `too_many_attempts` | Provider rate limit (60/hour). `Retry-After` is set. |
| 502 | `provider_error` | The platform answered in a way Cerberus could not use. |
| 503 | `provider_unavailable` | The platform could not be reached. Nothing was changed. |
| 503 | `provider_not_configured` | No OAuth app or `PROVIDER_TOKEN_ENCRYPTION_KEY` on this server. |

### 4.8 How to add a provider

A provider is one module. Nothing in the database changes (the columns are plain strings), and nothing
in the scanner or scan authorization does either.

1. **Write `providers/<name>.py`** with a class that subclasses `providers.base.DeploymentProvider` and
   implements `build_authorization_url`, `exchange_code`, `get_account`, `list_projects` and
   `get_project`; also `refresh` if the platform issues refresh tokens. Return
   `ProviderProject(id, name, hostnames, scope_id)` where `hostnames` are the platform's own addresses,
   passed through `platform_hostnames(...)`. Use `self.http` for every call so tests can substitute it,
   `safe_id(...)` before putting any id in a URL path, and `raise_for_status(...)` to map errors. Do not
   override `verify_target`: it is where the two shared rules (platform hostnames only; the platform
   decides visibility) are enforced.
   To offer the access-token option, set `supports_token = True` and implement `tokens_from_pasted`; nothing else
   changes (storage, isolation and re-checks are shared).
2. **Register it.** Add a branch in `providers.get_provider`, its name to `PROVIDER_NAMES` in
   `providers/__init__.py` and `core/models.py`, and its suffix to `PLATFORM_SUFFIXES` in
   `providers/base.py`. Credentials are read from `<NAME>_CLIENT_ID` and `<NAME>_CLIENT_SECRET`.
3. **Redirect URI.** Register `{PUBLIC_API_URL}/api/v1/providers/<name>/callback` with the platform.
4. **Frontend.** Add the name to `ProviderName` in `frontend/src/types.ts`, its address to
   `PLATFORM_ADDRESS` (`DeploymentProviders.tsx`) and its label to `PROVIDER_LABELS`
   (`ProfileView.tsx`), and a `.provider-<name>` colour in `styles.css`.
5. **Tests.** Add routes for it to `tests/provider_fakes.py` and mirror the existing cases in
   `tests/test_provider_clients.py`, `test_providers_api.py`, `test_provider_ownership.py` and
   `test_provider_isolation.py`. The suite never contacts a real platform.
6. **Document** its setup in [DEPLOYMENT.md](DEPLOYMENT.md#7-deployment-providers) and any limitation in §4.6.

### 4.9 Disconnecting

From the dashboard (Targets → the provider's card → **Disconnect**, or the API's
`POST /connections/{id}/disconnect`). Cerberus deletes the connection and its encrypted tokens, and every
target it verified returns to `pending`: **a connection that no longer exists cannot keep vouching for
a hostname**, and those targets cannot be scanned until verified again. Cerberus does not call the
platform to revoke the token; the OAuth app remains authorised on the platform's side until the person
removes it in the platform's own settings for authorised apps. The dashboard says so.

## 5. Admin

Read-only, cross-tenant visibility for an account with `is_admin` set. It is a second thing the term
"admin" could mean in a product like this, deliberately narrower than the other one: **it grants no
scanning power.** An admin signs in exactly like anyone else, and `POST /scans` has no idea the admin
flag exists — it is the same `core/ownership.py` check for everyone, so an admin can scan only a domain
*they themselves* own and verified, same as any other account. There is also no endpoint, here or
anywhere else, that sets `is_admin`: only an operator with direct database access can
(`scripts/grant_admin.py`), the same trust boundary as `scripts/claim_legacy.py`.

Every route below requires `is_admin: true` on the caller and is otherwise `404 not_found` — the same
answer a route that does not exist would give, so a non-admin probing `/api/v1/admin/*` learns nothing
from the response.

### `GET /api/v1/admin/overview`

Counts across every account, not just the caller's (contrast with `GET /api/v1/overview`).

```json
{
  "user_count": 7,
  "domain_counts": { "verified": 5, "pending": 2 },
  "scan_counts": { "completed": 6, "running": 1 },
  "finding_counts": { "critical": 3, "high": 12, "medium": 40, "low": 55, "unscored": 0 }
}
```

`finding_counts` is open findings only (`status = "open"`), by risk band.

---

### `GET /api/v1/admin/users`

Paginated (`limit`, `offset`, as elsewhere). Every account, newest first.

```json
{
  "total": 7,
  "users": [
    { "id": "…", "email": "alice@example.com", "name": "Alice", "is_admin": false,
      "created_at": "…", "last_login_at": "…", "domain_count": 2, "scan_count": 5 }
  ]
}
```

---

### `GET /api/v1/admin/domains`

Every account's targets, each with its owner's email.

```json
{
  "total": 12,
  "domains": [
    { "id": "…", "domain": "alice.example.com", "owner_email": "alice@example.com",
      "verification_status": "verified", "verification_method": "dns_txt", "created_at": "…" }
  ]
}
```

---

### `GET /api/v1/admin/scans`

Every account's scans, each with its owner's email and how many findings it produced.
`owner_email` is `null` for a scan that predates accounts (see `scripts/claim_legacy.py`) —
never invented.

```json
{
  "total": 40,
  "scans": [
    { "scan_id": "…", "owner_email": "bob@example.com", "target_domain": "bob.example.com",
      "profile": "safe", "status": "completed", "started_at": "…", "completed_at": "…",
      "finding_count": 9 }
  ]
}
```

### Granting admin

```bash
python scripts/grant_admin.py you@example.com            # grant
python scripts/grant_admin.py you@example.com --revoke    # revoke
```

An operator-only script, deliberately: it needs the same direct database access as
`scripts/claim_legacy.py`, and there is no API path to the same effect.

## 6. Rate Limiting

There is no general per-client rate limit (single-operator use, per [PRD §3](PRD.md#3-non-goals-v1)). Sign-in and registration are limited per account and per address, DNS verification to 30/hour per account, and provider calls to 60/hour per account (§4.3). `POST /api/v1/scans` is serialized server-side — only one scan runs per tenant at a time — to avoid overlapping active reconnaissance against the same target.

## 7. Error Format

```json
{
  "error": {
    "code": "invalid_request",
    "message": "authorized must be true to start a scan"
  }
}
```

| HTTP status | `code` | Meaning |
|---|---|---|
| 400 | `invalid_request` | Malformed body/params, or `authorized: false` |
| 400 | `invalid_profile` | Unknown profile, or an intrusive profile requested without `accept_profile: true` |
| 401 | `unauthorized` | Missing/invalid bearer token |
| 404 | `not_found` | No resource with that ID |
| 409 | `scan_in_progress` | A scan is already running for this tenant/target |
| — | provider codes | Deployment-provider errors have their own table: [§4.7](#47-provider-errors) |
| 500 | `internal_error` | Unhandled server error |
