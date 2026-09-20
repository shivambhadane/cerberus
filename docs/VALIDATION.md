# Validation

What a real end-to-end run produced, and what it found wrong. Everything here was run against the
[Docker lab](../lab/README.md) with the real tools, not fixtures. Two things it does **not** cover:
real internet infrastructure (Level 3), and any target other than two Apache containers.

## The run

| | |
|---|---|
| Entry point | `python cerberus.py scan --target 127.0.0.1 --authorized --allow-private --no-subdomains --ports 18081,18082` |
| Targets | Apache 2.4.49 on `:18081`, Apache 2.4.50 on `:18082` (loopback only) |
| Profile | `safe` (default): 4,754 of 13,619 templates selected |
| Tools | nmap 7.95, nuclei v3.11.1, `tcp_connect` |
| Rate limit | 20 req/s (profile default) |
| Duration | 802 s |
| Database | fresh, built entirely by migrations (`0001 → 0002`) |
| Tool errors | none |

### Observations recorded (raw, before normalization)

| Tool | Kind | Count |
|---|---|---|
| tcp_connect | open_port | 2 |
| nmap | open_port | 2 |
| nuclei | vulnerability | 1 |

### Findings

| | |
|---|---|
| Assets | 2, both identified by nmap (`Apache httpd/2.4.49`, `Apache httpd/2.4.50`) |
| Findings | **136** (69 on 2.4.49, 67 on 2.4.50) |
| `active_detection` | 1 |
| `version_inference` | 135 |
| KEV-listed | 5 |
| With CVSS / EPSS | 136 / 136 |
| Duplicate (asset, CVE) rows | **0** |
| Lower-case CVE ids | 0 |

### The two lab CVEs

Ground truth, established with `curl` independently of Cerberus:

| | CVE-2021-41773 | CVE-2021-42013 |
|---|---|---|
| 2.4.49 (`:18081`) | exploitable | exploitable |
| 2.4.50 (`:18082`) | fixed | exploitable |

What Cerberus recorded:

| Asset | CVE | Detection | Score |
|---|---|---|---|
| `:18081` | CVE-2021-41773 | `active_detection` (nuclei) | 83.6 |
| `:18081` | CVE-2021-42013 | `version_inference` | 83.6 |
| `:18082` | CVE-2021-42013 | `version_inference` | 83.6 |
| `:18082` | CVE-2021-41773 | *(correctly absent)* | |

- **No duplicate inference + detection rows.** The active detection superseded its inferred finding
  rather than adding a second one.
- **Precision held:** CVE-2021-41773 is absent on 2.4.50, which fixed it.
- **Nuclei confirmed 1 of the 3 real (asset, CVE) pairs.** CVE-2021-42013 is exploitable on both
  hosts, but nuclei's template did not match it on either. With `-v`, the requests it sent for that
  template contained a duplicated path segment. Version inference flagged it correctly, so a
  `version_inference` finding is not "unconfirmed, probably false": here it was a true positive the
  probe missed. This is why both evidence types are kept and labelled.

### Ranking

| Rank | CVE | CVSS | KEV | EPSS | Score |
|---|---|---|---|---|---|
| 1-3 | CVE-2021-42013 / 41773 | 9.8 | yes | ~100% | 83.6 |
| 4-5 | CVE-2024-38475 | 9.1 | yes | ~100% | 83.1 |
| 6-7 | CVE-2021-44790 | 9.8 | no | 97% | 61.8 |

`CVE-2024-38475` (CVSS 9.1, KEV) outranks `CVE-2021-44790` (CVSS 9.8, not KEV) by 21 points.
Three findings tie at 83.6, including the confirmed one: detection method is reported in the
reasoning but deliberately does not change the score, because it measures confidence that the
weakness exists, not how dangerous it is.

### Rate limit, measured from the target's side

| | Requests received | Over 802 s |
|---|---|---|
| httpd-2449 | 7,126 | 8.9 req/s |
| httpd-2450 | 7,127 | 8.9 req/s |
| **Combined** | **14,253** | **17.8 req/s** (limit: 20) |

Counted from the containers' access logs, independent of nuclei's own reporting.

## Two more runs

- **Postgres 16.** The full chain was run against a real Postgres stack: 136 findings, 0 duplicates,
  no tool errors (see [DEPLOYMENT.md](DEPLOYMENT.md)).
- **`scanme.nmap.org`.** The opt-in Level 2 tests (port and service discovery only, ports 22 and 80)
  passed against the live host.

## What the validation found wrong

None of these were visible to the unit tests. Each has a regression test.

| # | Bug | How it surfaced |
|---|---|---|
| 1 | nuclei **hung indefinitely** when stdin was inherited (0.4 s with stdin closed), and the adapter then returned no detections as if it had found nothing | first real invocation; fixed by `core/proc.py`, which also makes timeouts and crashes explicit `ScannerError`s |
| 2 | Real nuclei emits a **bare host** with the port in a separate field, so every detection failed to match its asset and was discarded | first adapter run; my fixtures had assumed a different shape |
| 3 | Nuclei writes CVE ids **lower-case**, so they never joined KEV/EPSS data | same run |
| 4 | nmap labels hosts by **reverse-DNS name**; I trusted it as identity and scope rejected every result. On a real host this means nmap contributes nothing | nmap reported 0 open ports on open ports |
| 5 | `discovery.ports`, timeout and concurrency config were **silently ignored** after the adapter refactor | the lab's ports aren't in the defaults |
| 6 | The `passive` profile **still port-scanned** and probed the target, contradicting its documentation | reading the runner against the RoE |
| 7 | The NVD client read **one page**: 19 of 69 CVEs for Apache 2.4.49 were dropped, any of which could have been KEV-listed | exactly 100 findings from 2 assets looked like a cap |
| 8 | `VARCHAR(128)` overflowed on a real 179-character CISA KEV product: the **enrichment refresh crashes on PostgreSQL**. SQLite never enforces the limit, so every local run passed | first run against Postgres |
| 9 | Wiring in migrations **silenced all scan logging** (Alembic reset the root logger) | a scan log with no Cerberus lines |
| 10 | `scripts/init_db.py` **printed the database password** | its own output during the Postgres run |
| 11 | No `.dockerignore`: `COPY . .` would bake **`.env`** and both databases into the image | auditing the build context |
| 12 | API **auth bypass**: with `API_SECRET_KEY=""`, the header `Bearer ` returned 200; `change-me` was also accepted | testing compose's required-variable check |
| 13 | A restart mid-scan left the row `discovering` forever, so **every future scan returned 409** | reading how scans run inside the API process |
| 14 | The Docker image had **no nmap or nuclei**, so a containerized deployment silently degraded to version inference | writing the deployment guide |
| 15 | The **Thorough profile named a protocol nuclei does not accept** (`network`; nuclei 3.x calls it `tcp`). nuclei exits 2 before scanning, so every Thorough scan ran without nuclei. The warning said only `no stderr` because nuclei reports flag errors on stdout | two dashboard scans finished with `nuclei exited 2: no stderr`; reproduced against the lab. Profiles now validate protocol names at construction, error messages fall back to stdout, and a test runs the real nuclei over every profile's flags. A Thorough lab scan now completes with no tool errors (7 detections) |
| 16 | Alembic's autogenerated migration for the accounts work wrote boolean defaults as `DEFAULT 0` / `DEFAULT 1`, which **PostgreSQL rejects**, and left the new foreign keys unnamed, so the downgrade could not drop them. Both would have passed every SQLite test | running the migration against a throwaway PostgreSQL 16 before trusting it. Fixed with `sa.false()`/`sa.true()` and named constraints; a test now asserts the migration file contains neither literal |
| 17 | **Every timestamp was wrong by the viewer's UTC offset.** SQLite returns datetimes without their zone, the API sent them bare (`2026-09-20T06:24:23`), and a browser parses that as *its own* local time. A scan started a minute ago showed "6 h ago" in India (UTC+5:30). PostgreSQL would have hidden it, since `timestamptz` returns aware values | reported from the dashboard. All datetimes now serialise as UTC with a `Z`, the client treats zone-less strings as UTC, and display is pinned to Asia/Kolkata. Two backend tests fail without the fix; the browser test runs in the India timezone with a scan created that instant |

## Limits

- Two Apache containers is a narrow target. It says nothing about CDNs, WAFs, rate limiting,
  unreachable hosts, IPv6, or services other than HTTP.
- nuclei's `safe` profile found 1 detection across 4,754 templates and 2 targets. That is a
  statement about this lab, not about nuclei's coverage in general.
- CPE matching is version-string based; distributions that back-port patches will be over-reported.
- Level 3 (your own infrastructure: several subdomains, mixed services, HTTPS, cloud assets) has not
  been attempted, and is where this starts to look like an ASM platform rather than a scanner wrapper.
