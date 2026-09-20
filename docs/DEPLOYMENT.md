# Deployment

How to run Cerberus as a service: the API plus PostgreSQL in Docker Compose, with `nmap` and
`nuclei` baked into the image so scans get real service detection and active detection.

Everything marked **verified** below was run against a real Postgres 16 stack while writing this;
everything under [Not verified](#not-verified) was not. Read that section before relying on it.

## What you get

| Service | Image | Notes |
|---|---|---|
| `postgres` | `postgres:16-alpine` | data in the `postgres_data` volume |
| `api` | built from [`Dockerfile`](../Dockerfile) | FastAPI; runs migrations on startup |

The API image contains `nmap` (from the distro), `nuclei` v3.11.1 (pinned by SHA-256 in the
Dockerfile, for both amd64 and arm64), and the nuclei template set as of the build. It runs as an
unprivileged user (uid 10001); the connect scan (`-sT`) needs no raw-socket capability.

The dashboard is **not** part of the compose stack. Build it (`cd frontend && npm run build`) and
serve `frontend/dist/` from any static host.

## 1. Configure

Create `.env` next to `docker-compose.yml` (it is git-ignored and excluded from the image by
`.dockerignore`):

```bash
cat > .env << EOF
POSTGRES_PASSWORD=$(openssl rand -hex 16)
API_SECRET_KEY=$(openssl rand -hex 24)
NVD_API_KEY=            # optional but strongly recommended, see below
CORS_ORIGINS=https://dashboard.example.com
COOKIE_SECURE=1         # the refresh cookie over HTTPS only
EOF
```

| Variable | Required | Notes |
|---|---|---|
| `POSTGRES_PASSWORD` | **yes** | Compose refuses to start without it. Keep it URL-safe (hex is fine): it is embedded in the database URL. |
| `API_SECRET_KEY` | **yes** | Signs every sign-in token. Compose refuses to start without it, and the API refuses to start if it is empty, the placeholder `change-me`, or shorter than 32 characters. Changing it signs everyone out. |
| `COOKIE_SECURE` | **yes, in production** | `1` marks the refresh cookie Secure, so browsers send it over HTTPS only. The default `0` exists for `http://localhost`. |
| `ACCESS_TOKEN_MINUTES`, `REFRESH_TOKEN_DAYS` | no | Session lifetimes (default 15 minutes / 14 days). |
| `NVD_API_KEY` | no | Free from NVD. Without it enrichment is limited to 5 requests per 30s and scans are markedly slower. |
| `CORS_ORIGINS` | if you use the dashboard | Comma-separated origins allowed to call the API from a browser. It also allowlists which origins may use the session cookie, so list the dashboard's real origin and nothing else. |

There are deliberately no defaults for the two secrets. A default that ships in the repository is a
credential every reader of the repository already knows.

## 2. Start

```bash
docker compose up -d --build
docker compose ps
```

Migrations run automatically at API startup. A fresh database is built entirely by migrations; see
[DATABASE_SCHEMA.md §5](DATABASE_SCHEMA.md#5-migrations).

**Load the enrichment data before the first scan:**

```bash
docker compose exec api python scripts/refresh_enrichment.py
```

Without it every finding is scored as if nothing were actively exploited, which inverts the ranking
Cerberus exists to produce. Scans and the dashboard warn loudly when the cache is empty or stale;
run this daily (cron or a systemd timer).

## 3. Verify

```bash
curl -s http://127.0.0.1:8000/healthz                       # {"status":"ok"}
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/api/v1/findings   # 401
curl -s -H "Authorization: Bearer $API_SECRET_KEY" http://127.0.0.1:8000/api/v1/findings
```

Confirm the tools are present in the running container, since their absence degrades scans
silently to version inference only:

```bash
docker compose exec api sh -c 'nuclei -version; nmap --version | head -1'
docker compose exec api python -c "
import discovery.adapters
from core.adapters import available, ObservationKind as K
print([s.name for s in available(K.OPEN_PORT)], [s.name for s in available(K.VULNERABILITY)])"
# ['tcp_connect', 'nmap'] ['nuclei']
```

## 4. Expose it safely

Both published ports bind to `127.0.0.1`. The API can launch active scans, so do not publish it on
`0.0.0.0`. Put a TLS-terminating reverse proxy in front of it. For example, with Caddy (automatic
certificates):

```
cerberus.example.com {
    reverse_proxy 127.0.0.1:8000
}
```

The database port is bound to loopback for convenience; if the API and database share a host you can
remove that `ports:` entry entirely, since the API reaches Postgres over the compose network.

## 5. Scanning from the deployed API

- A scan runs **inside the API process** as a background thread. A full `safe`-profile scan of two
  targets took about 14 minutes at the profile's 20 requests/second limit. It does not block other
  requests, but it does not survive a restart: at startup any scan still marked active is marked
  `failed` ("interrupted") so it cannot block future scans forever. That is only correct if the API is the
  **only** thing running scans against its database: do not run several workers or replicas, and
  do not start an API while a CLI scan against the same database is still running, or that
  scan will be marked failed.
- Only one scan runs per tenant at a time (`409 scan_in_progress` otherwise).
- Loopback and private addresses are refused, and the API has no parameter to allow them. That is a
  deliberate defence against pointing the server at its own network. To scan a private lab, use the
  CLI with `--allow-private` (see [lab/README.md](../lab/README.md)).
- Scan only what you are authorized to. See [RULES_OF_ENGAGEMENT.md](RULES_OF_ENGAGEMENT.md).

## 6. Operating it

**Updating nuclei templates.** Templates are baked in at build time and auto-update is disabled at
scan time, so an image corresponds to one fixed template set and a scan is reproducible from the
image. The set drifts quickly: a build four days after another selected 4,829 templates under the
`safe` profile versus 4,754. To update, rebuild without cache:

```bash
docker compose build --no-cache api && docker compose up -d api
```

**Backups.** The database is the only state:

```bash
docker compose exec -T postgres pg_dump -U cerberus cerberus > cerberus-$(date +%F).sql
```

**Upgrades.** Pull, rebuild, restart; pending migrations run on startup. A database created before
migrations existed is adopted only if its schema matches, and refused with an error otherwise.

## Verified

Run against a real Postgres 16 + API stack built from this repository:

- Compose refuses to start without `POSTGRES_PASSWORD` or `API_SECRET_KEY`.
- Both ports bind to `127.0.0.1` only.
- The image runs as uid 10001, contains `nuclei` v3.11.1 (hash-verified at build) and `nmap`, and
  contains no `.env` and no `.db` files. The build context is ~0.2 MB.
- Migrations `0001 → 0002` apply cleanly on Postgres, including changing a live `varchar(128)`
  column to `text`.
- The API returns `401` with no token or the well-known `change-me`, and `200` with the real key.
- The full pipeline (discovery, nmap, nuclei, NVD/KEV/EPSS enrichment, scoring) writes correctly to
  Postgres: 136 findings, 0 duplicates, no tool errors.

That last check found a bug that SQLite had hidden: a real CISA KEV product field is 179 characters
and the column was `VARCHAR(128)`, so the enrichment refresh crashed on Postgres while every local
test passed. See [VALIDATION.md](VALIDATION.md).

## Not verified

- A TLS reverse proxy in front of the API (the Caddy snippet above is an example, not tested here).
- More than one API worker, or more than one API replica.
- Kubernetes, or any orchestrator other than Docker Compose.
- Serving the built dashboard from a static host.
- arm64 images (the checksum is pinned but the build was only run on amd64).
