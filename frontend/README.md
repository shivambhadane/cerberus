# frontend

Cerberus dashboard — stage 5 delivery layer. React + TypeScript, built with Vite.

```bash
npm install
npm run dev        # http://localhost:5173
```

The API must be running and must allow this origin:

```bash
API_SECRET_KEY=devkey CORS_ORIGINS=http://localhost:5173 \
  uvicorn api.main:app --port 8000
```

On first load the dashboard asks for the API bearer token (`API_SECRET_KEY`) and keeps
it in `localStorage`. Point it at a different API with `VITE_API_URL`.

## Views

- **Findings** — findings ranked by risk score, with the KEV badge and CVSS shown side by
  side so the divergence is visible: an actively-exploited CVSS 7.5 outranks a quiet 9.8.
  Selecting a row opens the full enrichment detail and its reasoning, and allows a status change.
- **Assets** — discovered hosts, ports, and fingerprinted technologies.
- **Scan** — triggers a scan. The button stays disabled until the authorization attestation
  is checked, mirroring the CLI's `--authorized` flag and
  [docs/RULES_OF_ENGAGEMENT.md](../docs/RULES_OF_ENGAGEMENT.md).

A banner reports enrichment-cache freshness. If the KEV cache is empty or stale the ranking
cannot be trusted, so the dashboard says so rather than showing confident-looking bad data.
