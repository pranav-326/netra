# Service: Threat Engine (Layer 4)

## Purpose
Core correlation and decision engine:
- Aggregates findings across Layer 3 analyzers and Layer 5 threat intelligence.
- Evaluates IOC indicators, signature matching (YARA rules), and heuristic policy rules.
- Executes machine learning classification models.
- Classifies verdict into: `MALICIOUS`, `SUSPICIOUS`, or `BENIGN`.
- Emits standardized threat evaluation reports to PostgreSQL and OpenSearch.
