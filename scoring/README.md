# scoring

Exploitability scoring engine — stage 4 of the pipeline, deployed as a standalone Python microservice.

Combines enrichment data (KEV status, EPSS probability) with asset criticality and exposure context into a single, explainable risk score per finding, using the weights in [config.yaml](../config.yaml).

**Input:** enriched findings + asset criticality tags
**Output:** ranked findings with a `risk_score` and human-readable `reasoning`, served to `api/`.
