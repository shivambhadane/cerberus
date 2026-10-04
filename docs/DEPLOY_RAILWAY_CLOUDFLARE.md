# Deploying Cerberus: Railway (Backend + PostgreSQL) & Cloudflare Pages (Frontend)

This guide walks you through deploying Cerberus in production using:
- **Backend & Scanners**: [Railway](https://railway.app) (FastAPI, PostgreSQL 16, `nmap`, and `nuclei`).
- **Frontend Dashboard & Landing**: [Cloudflare Pages](https://pages.cloudflare.com) (Static Vite SPA with client-side routing).

```
   ┌────────────────────────────────────────────────────────┐
   │                  Cloudflare Pages                      │
   │           https://<your-app>.pages.dev                 │
   │  - Landing Page (/) & Dashboard (/platform/#/...)      │
   │  - Firebase Auth (Google / GitHub / Password)          │
   └──────────────────────────┬─────────────────────────────┘
                              │ HTTPS API calls (Bearer token)
                              ▼
   ┌────────────────────────────────────────────────────────┐
   │                  Railway Web Service                   │
   │       https://<your-service>.up.railway.app            │
   │  - Docker container (Python 3.12, nmap, nuclei)        │
   │  - FastAPI API + Background Scan Threads               │
   │  - Auto-runs database migrations on startup            │
   └──────────────────────────┬─────────────────────────────┘
                              │ Internal / DATABASE_URL
                              ▼
   ┌────────────────────────────────────────────────────────┐
   │               Railway PostgreSQL Service               │
   │  - Persistent managed database                         │
   └────────────────────────────────────────────────────────┘
```

---

## Prerequisites & Secrets Generation

Before deploying, generate the required cryptographic keys on your local terminal. Do **not** commit these keys to git:

### 1. API Secret Key (JWT Signing)
Must be at least 32 characters long:
```bash
openssl rand -hex 24
```
*Save this output for `API_SECRET_KEY`.*

### 2. Provider Token Encryption Key (Fernet Key)
Used to encrypt deployment provider tokens (Cloudflare, Vercel, Netlify) at rest:
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
*Save this output for `PROVIDER_TOKEN_ENCRYPTION_KEY`.*

---

## Part 1: Deploy Backend & Database on Railway

### Step 1: Create a Railway Project
1. Log in to [Railway](https://railway.app).
2. Click **New Project** → Select **Provision PostgreSQL**.
   - Railway will provision a managed PostgreSQL instance with automatic backups and a private internal connection.

### Step 2: Deploy Backend Service from GitHub
1. In the same Railway project canvas, click **+ Create** / **New Service** → **GitHub Repo**.
2. Select your repository: `shivambhadane/cerberus`.
3. Railway automatically detects `Dockerfile` and `railway.toml`.

### Step 3: Configure Environment Variables in Railway
Click on your backend service → Go to the **Variables** tab → Add the following environment variables:

| Variable | Recommended Value / Source | Description |
|---|---|---|
| `DATABASE_URL` | `${{Postgres.DATABASE_URL}}` | Select **Add Reference** and pick `Postgres.DATABASE_URL`. |
| `API_SECRET_KEY` | *(Your generated 48-char hex)* | Signs authentication tokens. |
| `PROVIDER_TOKEN_ENCRYPTION_KEY` | *(Your generated Fernet key)* | Encrypts connected provider credentials. |
| `COOKIE_SECURE` | `1` | Enforces HTTPS-only cookies in production. |
| `PUBLIC_API_URL` | `https://${{RAILWAY_PUBLIC_DOMAIN}}` | The public URL of this Railway service. |
| `CORS_ORIGINS` | `https://<your-app>.pages.dev` | Set temporarily, or update once your Cloudflare Pages URL is known. |
| `FRONTEND_URL` | `https://<your-app>.pages.dev` | Dashboard URL for OAuth callback redirects. |
| `NVD_API_KEY` | *(Optional)* | Optional NVD API key to avoid 5 req/30s rate limits. |

### Step 4: Generate a Public Domain for Railway API
1. Go to your backend service's **Settings** tab.
2. Scroll to **Networking** → Click **Generate Domain** (e.g., `cerberus-production.up.railway.app`).
3. Note this domain: `https://<your-railway-app>.up.railway.app`.

### Step 5: Initialize Threat Intelligence Cache (CISA KEV & EPSS)
When the service deploys, database migrations run automatically on startup.
Before running scans, seed the CISA KEV and EPSS vulnerability database:
1. In Railway, click on your backend service → open the **Deployments** tab → Click **View Logs** to verify that migrations ran cleanly (`migrated database (empty) -> 0010_scan_progress`).
2. Click the **Exec** or **Terminal** tab in the Railway web dashboard (or use the `railway` CLI locally with `railway run`), and run:
   ```bash
   python scripts/refresh_enrichment.py
   ```
   *You should see output confirming KEV records and EPSS scores were fetched and cached.*

---

## Part 2: Deploy Frontend on Cloudflare Pages

### Step 1: Create a Cloudflare Pages Project
1. Log in to the [Cloudflare Dashboard](https://dash.cloudflare.com).
2. In the left navigation, go to **Compute (Workers) → Workers & Pages** (or **Workers & Pages → Overview**).
3. Click **Create Application** → Select the **Pages** tab → Click **Connect to Git**.
4. Authorize Cloudflare to access your GitHub account and select `shivambhadane/cerberus`.

### Step 2: Configure Build Settings
Fill in the deployment configuration:

- **Project name**: `cerberus` (or your preferred name, which gives `cerberus.pages.dev`).
- **Production branch**: `main`.
- **Framework preset**: `Vite` (or `None`).
- **Root directory**: `frontend` *(Important: Cerberus frontend files reside in `frontend/`)*.
- **Build command**: `npm run build`
- **Build output directory**: `dist`

### Step 3: Configure Environment Variables
Under **Environment variables (advanced)**, add:

| Variable | Value | Description |
|---|---|---|
| `VITE_API_URL` | `https://<your-railway-app>.up.railway.app` | Points the frontend API client to your Railway backend. |

*(Note: The Firebase credentials in `frontend/src/lib/firebase.ts` already default to your configured `cerberus-a2be4` project. You can override them here with `VITE_FIREBASE_API_KEY` etc. if desired).*

### Step 4: Deploy
Click **Save and Deploy**. Cloudflare Pages will build the project and assign a production URL:
`https://<your-app>.pages.dev`

---

## Part 3: Firebase Authentication Configuration

Since Firebase Auth enforces domain whitelisting, you must authorize your Cloudflare Pages domain so users can sign in:

1. Open the [Firebase Console](https://console.firebase.google.com).
2. Select your project: **cerberus-a2be4**.
3. In the left navigation, click **Authentication** → Go to the **Settings** tab.
4. Click **Authorized domains** → **Add domain**.
5. Add your Cloudflare Pages domain:
   - `<your-app>.pages.dev`
   - *(If using a custom domain later, e.g. `cerberus.yourdomain.com`, add that as well)*.
6. Click **Save**.

---

## Part 4: Update CORS & Frontend URLs on Railway

Now that your Cloudflare Pages domain is active (e.g. `https://cerberus.pages.dev`):

1. Go back to your **Railway Backend Service** → **Variables** tab.
2. Update:
   - `CORS_ORIGINS`: `https://<your-app>.pages.dev`
   - `FRONTEND_URL`: `https://<your-app>.pages.dev`
3. Railway will automatically redeploy the backend with the updated configuration.

---

## Part 5: Deployment Providers (Cloudflare Pages, Netlify, Vercel)

If you plan to use Deployment Provider integrations:

1. **Cloudflare Pages OAuth**:
   - Update your Cloudflare OAuth app's redirect URI in the Cloudflare dashboard:
     `https://<your-railway-app>.up.railway.app/api/v1/providers/cloudflare/callback`
   - Set `CLOUDFLARE_CLIENT_ID`, `CLOUDFLARE_CLIENT_SECRET`, and `CLOUDFLARE_OAUTH_SCOPES` on Railway.
2. **Netlify OAuth**:
   - Set Redirect URI on Netlify to:
     `https://<your-railway-app>.up.railway.app/api/v1/providers/netlify/callback`
   - Set `NETLIFY_CLIENT_ID` and `NETLIFY_CLIENT_SECRET` on Railway.
3. **Vercel**:
   - Users can connect directly using their Personal Access Token on the dashboard without OAuth setup!

---

## Part 6: Verification & Health Checks

Once deployed, verify each component:

1. **Backend Health Check**:
   ```bash
   curl -i https://<your-railway-app>.up.railway.app/healthz
   # Expected: HTTP 200 OK {"status":"ok"}
   ```

2. **Frontend Routing & Landing**:
   - Visit `https://<your-app>.pages.dev/` — The high-converting landing page loads.
   - Click **Login** / **Platform** — Navigates to `https://<your-app>.pages.dev/platform/#/overview`.

3. **Sign In & Scanner Tools**:
   - Sign in with Google, GitHub, or Email.
   - Check the **Test Labs** or **Targets** view.
   - Run a scan on a verified target or testbed.
   - Check scan progress stages in real time.
