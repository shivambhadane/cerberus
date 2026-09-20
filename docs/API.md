# Cerberus — API Documentation

**Base URL:** `http://localhost:8000` (dev) — configured via `API_HOST` / `API_PORT` in [.env](../.env.example)
**Format:** JSON over HTTPS in production; HTTP acceptable for local dev only.

## 1. Authentication

Every endpoint except `GET /healthz` and `/api/v1/auth/{register,login,refresh,logout}` requires a
signed-in user:

```
Authorization: Bearer <access token>
```

An access token comes from `POST /api/v1/auth/register` or `/login`, is a JWT signed with
`API_SECRET_KEY`, and lives about **15 minutes** (`ACCESS_TOKEN_MINUTES`). It carries only the user
id: it is not a password and cannot be exchanged for one.

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
  "user": {"id": "…", "email": "you@example.com", "name": "", "email_verified": false, "created_at": "…"},
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
{ "id": "…", "email": "you@example.com", "name": "Shivam", "email_verified": false, "created_at": "…" }
```

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
could aim the server at its own internal network.

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
  "detected_at": "2026-09-13T10:04:00Z"
}
```

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

## 4. Rate Limiting

v1 has no per-client rate limiting (single-operator use, per [PRD §3](PRD.md#3-non-goals-v1)). `POST /api/v1/scans` is serialized server-side — only one scan runs per tenant at a time — to avoid overlapping active reconnaissance against the same target.

## 5. Error Format

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
| 500 | `internal_error` | Unhandled server error |
