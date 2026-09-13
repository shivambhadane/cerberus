# api

REST API — stage 5 delivery layer.

[main.py](main.py) is a FastAPI app serving ranked findings, asset inventory, scan control,
and enrichment freshness. Every endpoint except `/healthz` requires
`Authorization: Bearer $API_SECRET_KEY`.

```bash
uvicorn api.main:app --reload     # interactive docs at /docs
```

Full endpoint contracts: [docs/API.md](../docs/API.md).
