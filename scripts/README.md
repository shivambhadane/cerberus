# scripts

Setup and data-refresh scripts.

- [init_db.py](init_db.py) — creates the schema from the SQLAlchemy models
- [refresh_enrichment.py](refresh_enrichment.py) — pulls the latest CISA KEV catalogue and
  EPSS scores into the local enrichment cache

Run `refresh_enrichment.py` on a schedule (daily by default, per
`enrichment.refresh_interval_hours` in [config.yaml](../config.yaml)) so scoring reflects
current exploitation data.
