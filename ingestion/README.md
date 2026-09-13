# ingestion

Normalization and deduplication — stage 2 of the pipeline.

- [normalize.py](normalize.py) — upserts discovered assets, deduplicating on
  `(tenant, hostname, port, protocol)` so a re-scan refreshes `last_seen_at`
  instead of creating duplicate rows
- [criticality.py](criticality.py) — infers asset criticality from hostname naming
  conventions and exposed service ports. Manual `asset_criticality` rows always win
  and are never overwritten by a re-scan.

**Input:** `DiscoveredAsset` records from `discovery/`
**Output:** normalized `assets` rows in the shared database.
