# scoring

Exploitability scoring — stage 4 of the pipeline.

[engine.py](engine.py) blends four signals, weighted per [config.yaml](../config.yaml):

| Signal | Weight | Meaning |
|---|---|---|
| `kev_status` | 0.35 | Is it being exploited in the wild right now? |
| `epss_score` | 0.25 | How likely is exploitation in the next 30 days? |
| `asset_criticality` | 0.25 | How much do we care about the affected system? |
| `exposure_context` | 0.15 | How reachable is it, and how much does the flaw grant? |

CVSS is deliberately not a top-level weight — severity is not danger. It enters only
through `exposure_context`, so a critical-severity flaw nobody exploits ranks below a
medium-severity one under active attack. Every score carries a `reasoning` string
explaining which signals drove it.

**Input:** findings joined to enrichment data and asset criticality
**Output:** `risk_score` (0-100) and `reasoning` written back onto each finding.
