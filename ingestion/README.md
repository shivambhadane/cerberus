# ingestion

Normalization and deduplication workers — stage 2 of the pipeline.

Takes raw output from `discovery/`, maps it onto the common asset/finding data model, deduplicates against previously seen assets, and persists it to Postgres.

**Input:** raw discovery output
**Output:** normalized asset and finding records in the shared database.
