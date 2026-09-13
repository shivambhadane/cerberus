# Cerberus — API Documentation

**Base URL:** `http://localhost:8000` (dev) — configured via `API_HOST` / `API_PORT` in [.env](../.env.example)
**Format:** JSON over HTTPS in production; HTTP acceptable for local dev only.

## 1. Authentication

All endpoints except `GET /healthz` require a bearer token:

```
Authorization: Bearer <API_SECRET_KEY>
```

`API_SECRET_KEY` is set in [.env](../.env.example). v1 uses a single static key (no per-user auth) — see [PRD §3, Non-Goals](PRD.md#3-non-goals-v1).

## 2. Conventions

- All list endpoints are paginated via `limit` (default 20, max 100) and `offset`.
- Timestamps are ISO 8601 UTC.
- IDs are UUIDs.
- Errors follow a consistent shape (see [§6](#6-error-format)).

## 3. Endpoints

### `POST /api/v1/scans`

Trigger a new discovery → enrichment → scoring pipeline run against a target.

**Request body**

```json
{
  "target_domain": "example.com",
  "authorized": true
}
```

`authorized` must be `true` or the request is rejected with `400` — see [Rules of Engagement](RULES_OF_ENGAGEMENT.md). This flag records operator attestation; it does not itself verify ownership.

**Response — `202 Accepted`**

```json
{
  "scan_id": "b3f1c2e0-1234-4a56-9abc-def012345678",
  "status": "pending"
}
```

---

### `GET /api/v1/scans/{scan_id}`

Check the status of a running or completed scan.

**Response — `200 OK`**

```json
{
  "scan_id": "b3f1c2e0-1234-4a56-9abc-def012345678",
  "target_domain": "example.com",
  "status": "completed",
  "started_at": "2026-09-13T10:00:00Z",
  "completed_at": "2026-09-13T10:04:12Z"
}
```

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
      "first_seen_at": "2026-08-01T00:00:00Z",
      "last_seen_at": "2026-09-13T10:04:00Z"
    }
  ]
}
```

---

### `GET /api/v1/findings`

The core endpoint: ranked, explainable findings. Matches [README usage example](../README.md#api).

**Query params**

| Param | Type | Default | Notes |
|---|---|---|---|
| `tenant_id` | uuid | — | |
| `sort` | string | `risk_score` | `risk_score` \| `detected_at` |
| `order` | string | `desc` | `asc` \| `desc` |
| `limit` | int | 20 | max 100 |
| `offset` | int | 0 | |
| `min_risk_score` | float | — | filter, e.g. `min_risk_score=70` |
| `kev_only` | boolean | false | only findings with `kev_listed: true` |

**Response — `200 OK`**

```json
{
  "total": 7,
  "findings": [
    {
      "id": "f1e2d3c4-...",
      "asset": "api.example.com",
      "cve_id": "CVE-2023-XXXXX",
      "cvss_score": 6.5,
      "kev_listed": true,
      "epss_score": 0.94,
      "asset_criticality": "high",
      "risk_score": 98,
      "status": "open",
      "reasoning": "Actively exploited (CISA KEV), 94% predicted exploitation probability, affects a production-tagged, internet-facing asset.",
      "detected_at": "2026-09-13T10:04:00Z"
    }
  ]
}
```

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
  "cve_id": "CVE-2023-XXXXX",
  "cvss_score": 6.5,
  "kev_listed": true,
  "kev_date_added": "2023-11-01",
  "epss_score": 0.94,
  "has_public_exploit": true,
  "asset_criticality": "high",
  "risk_score": 98,
  "status": "open",
  "reasoning": "Actively exploited (CISA KEV), 94% predicted exploitation probability, affects a production-tagged, internet-facing asset.",
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

### `GET /api/v1/enrichment/status`

Check when global enrichment sources were last refreshed. Useful for confirming scoring is using current KEV/EPSS data.

**Response — `200 OK`**

```json
{
  "sources": [
    { "name": "nvd", "last_refreshed_at": "2026-09-13T00:00:00Z" },
    { "name": "kev", "last_refreshed_at": "2026-09-13T00:00:00Z" },
    { "name": "epss", "last_refreshed_at": "2026-09-13T00:00:00Z" },
    { "name": "osv", "last_refreshed_at": "2026-09-12T00:00:00Z" }
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
| 401 | `unauthorized` | Missing/invalid bearer token |
| 404 | `not_found` | No resource with that ID |
| 409 | `scan_in_progress` | A scan is already running for this tenant/target |
| 500 | `internal_error` | Unhandled server error |
