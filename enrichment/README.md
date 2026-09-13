# enrichment

Vulnerability intelligence and CVE matching — stage 3 of the pipeline.

- [sources.py](sources.py) — CISA KEV feed, FIRST.org EPSS (batched), and a
  rate-limited NVD 2.0 client for the CPE dictionary and CVE lookups
- [cache.py](cache.py) — upserts into the global, tenant-independent `cve_enrichment` table
- [matcher.py](matcher.py) — turns a fingerprint like `Apache/2.4.49` into CVEs: resolve the
  product to candidate CPE vendor/product bases, ask NVD for version-affected CVEs, and fall
  back to KEV product-name matching when no CPE resolves

NVD applies affected-version ranges server-side, so Cerberus keeps no version-range table.

OSV.dev is listed in the README data sources but is not wired up: it covers open-source
*package* vulnerabilities, which needs dependency scanning rather than network fingerprinting.

**Input:** assets with detected technologies
**Output:** `findings` rows joined to cached enrichment data.
