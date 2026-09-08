# enrichment

CVE/KEV/EPSS/OSV data pullers and cache — stage 3 of the pipeline.

Pulls and caches global (tenant-independent) threat intelligence: NVD CVE records, CISA KEV, FIRST.org EPSS scores, and OSV.dev advisories. Refreshed on a schedule (see `scoring.weights` and `enrichment.refresh_interval_hours` in [config.yaml](../config.yaml)), not per-scan.

**Input:** CVE identifiers found on assets during ingestion
**Output:** enrichment records (KEV status, EPSS score, CVSS score, known exploits) joined onto findings.
