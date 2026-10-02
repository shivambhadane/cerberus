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
| `FIREBASE_PROJECT_ID` | no | The Firebase project whose ID tokens (Google, GitHub, email sign-in) the API accepts. Defaults to the project this repository was built against; set it to your own if you use your own Firebase project. |
| `PROVIDER_TOKEN_ENCRYPTION_KEY`, `PUBLIC_API_URL`, `FRONTEND_URL`, `<PROVIDER>_CLIENT_ID` / `_SECRET`, … | only for [deployment providers](#7-deployment-providers) | Let people verify a Vercel, Netlify or Cloudflare Pages app through their platform account. Optional: without them DNS verification works exactly as before. |

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
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/api/v1/findings   # 401 without a sign-in
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer change-me" http://127.0.0.1:8000/api/v1/findings   # 401
```

`API_SECRET_KEY` signs sign-in tokens; it is not itself a bearer token. Sign in through the dashboard,
or `POST /api/v1/auth/register`, and send the `access_token` it returns as the bearer token (see
[API.md §1](API.md#1-authentication)). Also confirm the test-only sign-in bypass is off: the API logs an
error at startup if `CERBERUS_ALLOW_TEST_TOKENS=1` is set, and it must never be.

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
- Loopback and private addresses are refused by default (`core/scope.py`), which is a deliberate
  defence against pointing the server at its own network. The CLI's own `--allow-private` flag is an
  explicit operator opt-in for scanning a private lab (see [lab/README.md](../lab/README.md)).
  **Exception:** the dashboard's Test Labs screen (`POST /api/v1/domains/testbeds/{id}`) lets any
  signed-in user add `127.0.0.1` as a verified target. For that one scan, `core/scope.py`'s
  `allow_loopback_only` grants the *exact* loopback addresses only (`127.0.0.1`, `::1`) — never the
  RFC1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and never the cloud metadata address
  (`169.254.169.254`), which a blanket "allow private addresses" would also have opened. This was
  tightened from an earlier, broader grant; see `tests/test_scope.py` for the boundary it now enforces.
  It remains true that any signed-in user can scan this server's own loopback interface, which is fine
  on a single-operator laptop and worth gating before a multi-user deployment.
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

Back up `PROVIDER_TOKEN_ENCRYPTION_KEY` **separately** from that dump, if you use deployment providers.
The dump holds only ciphertext, so it is safe to store without the key, and useless for reading
tokens without it; a restore needs the same key (or people reconnect their accounts).

**Upgrades.** Pull, rebuild, restart; pending migrations run on startup. A database created before
migrations existed is adopted only if its schema matches, and refused with an error otherwise.

## 7. Deployment providers

Optional. People without a custom domain can prove control of an app on **Vercel**, **Netlify** or
**Cloudflare Pages** by connecting the account it is deployed on (Targets → *Add a deployment*). DNS TXT
verification is unchanged and stays the only way to verify a custom domain. What the feature does, its
security model and its limits are in [API.md §4](API.md#4-deployment-providers); this section is what
the operator has to set up. A provider you have not set up shows as "Not set up on this server".

**Nothing here has been run against a live platform.** The steps below come from each platform's
documentation. Treat the first real connection as the test, and see [API.md §4.6](API.md#46-limitations).

### 7.1 Server settings

| Variable | Notes |
|---|---|
| `PROVIDER_TOKEN_ENCRYPTION_KEY` | **Required** for any provider. A Fernet key that encrypts the stored tokens: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. `./run.sh` generates one for local use. Keep it out of the repository and **back it up**: if it is lost the stored tokens cannot be read and people reconnect. To rotate, put the new key first and keep the old one after a comma. |
| `PUBLIC_API_URL` | The API's public base URL, for example `https://api.example.com`. The OAuth redirect URIs are built from it. Use `https://` in production; it defaults to `http://localhost:8000`. |
| `FRONTEND_URL` | Where the dashboard is served, for example `https://app.example.com`. After a connection the browser is sent to `{FRONTEND_URL}/platform/#/domains`. Defaults to `http://localhost:5173`. |
| `COOKIE_SECURE=1` | Required in production. The OAuth cookie is marked `Secure` under it, like the refresh cookie. |
| `VERCEL_CLIENT_ID`, `VERCEL_CLIENT_SECRET`, `VERCEL_INTEGRATION_SLUG` | From the Vercel integration (§7.3). |
| `NETLIFY_CLIENT_ID`, `NETLIFY_CLIENT_SECRET` | From the Netlify OAuth application (§7.4). |
| `CLOUDFLARE_CLIENT_ID`, `CLOUDFLARE_CLIENT_SECRET`, `CLOUDFLARE_OAUTH_SCOPES` | From the Cloudflare OAuth client (§7.5). The scopes are space-separated. |

Client secrets and the encryption key are read only by the API process. They are never sent to the
browser, logged, or returned by any endpoint. The compose file passes `.env` to the API container, so
nothing else needs changing. Restart the API after editing `.env`.

Keep the dashboard and the API on the **same site** (`app.example.com` and `api.example.com`, or one
origin behind a reverse proxy), and use one host name for both: the OAuth cookie is `SameSite=Lax`, so
under `localhost` for one and `127.0.0.1` for the other the callback will be refused as `invalid_state`.

### 7.2 Redirect (callback) URLs

Register exactly this with each platform, character for character (no trailing slash, no wildcard):

| Provider | Redirect URI |
|---|---|
| Vercel | `{PUBLIC_API_URL}/api/v1/providers/vercel/callback` |
| Netlify | `{PUBLIC_API_URL}/api/v1/providers/netlify/callback` |
| Cloudflare | `{PUBLIC_API_URL}/api/v1/providers/cloudflare/callback` |

For local development that is `http://localhost:8000/api/v1/providers/<provider>/callback`. Some
platforms refuse an `http://` redirect URL (Cloudflare's form would not let one continue, and Vercel's may
not accept one either), so there is a local HTTPS mode:

```bash
./run.sh https        # once: make and trust the certificate, and switch the mode on
./run.sh              # restarts the API and the dashboard on https://localhost
./run.sh https off    # back to plain http
```

The redirect URIs then become `https://localhost:8000/api/v1/providers/<provider>/callback`, and the
dashboard is at `https://localhost:5173`. `./run.sh` sets `PUBLIC_API_URL`, `FRONTEND_URL`, `CORS_ORIGINS`
and `COOKIE_SECURE=1` for the processes it starts, so `.env` needs no change. Register the `https://` URIs with
each platform (a URI registered as `http://` will not match).

Why the dashboard has to move too, not only the API: the OAuth cookie is `Secure` and `SameSite=Lax`, and browsers
treat `http://localhost` and `https://localhost` as different sites, so an https API with an http dashboard would
lose the cookie and every connection would end in `invalid_state`.

What `scripts/local_https.sh` does, and why it is safe to trust:
- It creates a private CA in `.certs/` (git-ignored, key mode 600) whose certificate has a **name constraint**:
  it can vouch only for `localhost`, `127.0.0.1` and `::1`. A test confirms a certificate for `example.com` signed by
  it is rejected, so even a stolen key could not impersonate any other site to this browser.
- It signs a `localhost` certificate (397 days; renewed by running the script again).
- It adds the CA to **Chrome's certificate store for your user** (`~/.pki/nssdb`). Nothing system-wide, no `sudo`.
  Restart Chrome if it was open. Firefox has its own store: import `.certs/ca.pem` there by hand.
- Undo it: `./run.sh https untrust` (and delete `.certs/`).

Verified in real Chrome, with no certificate bypass: the dashboard and API load over https, the refresh and
OAuth cookies are `Secure`/`httpOnly`/`SameSite=Lax`, and the OAuth cookie is sent on the callback navigation.
Not verified: that Cloudflare or Vercel accept `https://localhost` as a redirect URL.
For anything other than local development use a real HTTPS host, as in §4.

### 7.3 Vercel

Vercel is connected through an **Integration**, not "Sign in with Vercel": Sign in with Vercel only
carries identity, and its permissions for API requests are documented as being in private beta.

1. In the Vercel dashboard create a new **Integration** (Settings → Integrations → Create, or the
   integration console). Menu names change; the fields you need are below.
2. **Name and slug.** The slug is the last part of the install URL,
   `https://vercel.com/integrations/<slug>`. Put it in `VERCEL_INTEGRATION_SLUG`.
3. **Redirect URL:** the Vercel URI from §7.2.
4. **Permissions (scopes): read-only** for the user, the team and projects, which is what listing a
   project and its domains needs. Grant nothing that writes. Scopes are set here, not requested in the
   URL, so a scope that is missing shows up as `provider_error` on the first project listing.
5. Copy the **Client ID** and **Client Secret** into `VERCEL_CLIENT_ID` and `VERCEL_CLIENT_SECRET`.
6. **Visibility.** A private integration can be installed only by its creator's own team, which is enough
   for you. For *other* people to connect, it must be made public, which Vercel reviews.
7. In Cerberus: Targets → Add a deployment → **Connect Vercel**, choose the team and the projects to
   share on Vercel's page, then pick a project.

#### 7.3b Vercel without an integration: an access token

If the integration cannot be created or installed (its install link shows a 404, or you do not want to publish one),
Vercel can be connected with an **access token** instead. This needs **no `VERCEL_*` variables at all**, only
`PROVIDER_TOKEN_ENCRYPTION_KEY`.

1. In Vercel open **Account Settings → Tokens → Create Token**.
2. **Scope:** pick the team that owns the app (or your personal account). **Expiration:** a short one.
3. Copy the token (Vercel shows it once).
4. In Cerberus: Targets → Deployment → Vercel → **Use an access token**. Paste it. If it is limited to a team, also
   enter the **Team ID** (Team Settings → General; it starts with `team_`). Leave the Team ID empty for a personal
   account. Click **Connect with token**.
5. Choose a project and **Add & verify** as usual.

Trade-offs, stated plainly: Vercel has no read-only token, so this one can do everything its owner can within the scope
you chose, which is more than Cerberus needs (it only reads project names and addresses). It is stored encrypted, is never
shown again, and disappears from Cerberus when you disconnect. Delete it on Vercel when you are done. When it expires,
Cerberus asks for a new one (targets it verified stay verified).

This path has been exercised against a live Vercel account: a real token listed the account's projects and
verified a `*.vercel.app` address. One thing that surprised us is worth repeating here — when the token later
expired, the connection's status became `failed` rather than staying `connected`. That is the scan-time
re-check working as designed, not a regression: ownership is proven again at scan time, so a target whose
evidence can no longer be re-established stops counting as verified.

### 7.4 Netlify

1. Netlify → User settings → **Applications** → OAuth → **New OAuth application**.
2. **Redirect URI:** the Netlify URI from §7.2.
3. Copy the **Client ID** and **Secret** into `NETLIFY_CLIENT_ID` and `NETLIFY_CLIENT_SECRET`.
4. There are no scopes to choose. **Netlify OAuth has no scopes, so a token can do anything the person
   can.** Cerberus only reads the site list and forgets the token on disconnect, and the dashboard says
   so, but the person should also revoke the app in their Netlify settings when done.
5. Netlify's public reference documents the implicit grant; the authorization-code token endpoint
   Cerberus uses is not in it. If the first connection fails with `authorization_failed`, this is the
   likely reason — in practice the authorization-code flow did work.

This is the provider that has been end-to-end verified against a live account: a real Netlify OAuth
connection listed the account's sites and verified a `*.netlify.app` address.

### 7.5 Cloudflare Pages

Cloudflare's OAuth is self-managed: authorization code with PKCE, refresh tokens through `offline_access`.

1. In the Cloudflare dashboard create an **OAuth client** for your account (see Cloudflare's *Create an
   OAuth client* documentation): a confidential (web) client, with the redirect URI from §7.2.
2. **Scopes.** Choose the read-only scopes that let the client list accounts and read Pages projects,
   and put the exact identifiers, space-separated, in `CLOUDFLARE_OAUTH_SCOPES`. Until the variable is
   set the provider shows as not set up.

   The one you cannot do without is **`pages.metadata_read`** — that is the read-only Pages scope, and
   Cloudflare does not publish its identifier in the public docs (the full list is served by the
   authenticated `GET /client/v4/oauth/scopes`), so it is recorded here. `account-settings.read` is the
   useful companion, for listing the accounts a project could belong to.

   Cerberus appends **`offline_access`** itself, to get a refresh token. It does *not* send `openid`:
   despite the OIDC discovery document, Cloudflare's OAuth does not use it, and the account id comes
   from `GET /client/v4/accounts` instead.
3. Copy the client id and secret into `CLOUDFLARE_CLIENT_ID` and `CLOUDFLARE_CLIENT_SECRET`.

**Verified live.** A Cloudflare account has been connected through this flow and 8 Pages projects were
listed and verified from it. Cloudflare is in fact the most complete of the three adapters: it is the only
one that receives a **refresh token** (via `offline_access`), so its access token — which Cloudflare issues
with a one-hour lifetime — can be renewed rather than needing a reconnect.

Getting there was the awkward part, so for anyone repeating it: the *Create an OAuth client* form may
refuse to enable **Continue** without showing a field-level error, and an API token created as a workaround
can verify itself (`/user/tokens/verify` → active) while still being refused for `GET /accounts` (403, code
9109) and `GET /oauth/scopes` (401, code 10000). The scope identifiers in step 2 are what unblock it, and
`pages.metadata_read` is the one that matters.

### 7.6 Checking it

`GET /api/v1/providers` (signed in) reports `"configured": true` for each provider that has its
credentials and the encryption key. The dashboard shows the same. To disconnect an account, use
Targets → the provider's card → **Disconnect**; its stored tokens are deleted and the targets it
verified return to "not verified". The OAuth app also stays authorised in the platform's own settings
until the person removes it there.

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

Also run on Postgres 16.15: migrations `0005 → 0007 → 0005 → 0007` with a user and a DNS-verified
domain seeded (rows preserved; schema identical to the models after the last step).

## Not verified

- A TLS reverse proxy in front of the API (the Caddy snippet above is an example, not tested here).
- More than one API worker, or more than one API replica.
- Kubernetes, or any orchestrator other than Docker Compose.
- Serving the built dashboard from a static host.
- arm64 images (the checksum is pinned but the build was only run on amd64).
- Connecting a real Vercel, Netlify or Cloudflare account (§7). The provider code is exercised against
  fakes of each platform's documented responses only.
