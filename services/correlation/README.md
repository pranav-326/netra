# Service: Correlation & Graph Analysis (Layer 6)

## Purpose
Constructs the threat landscape graph in Neo4j and detects campaigns:
- Ingests nodes: `Sender`, `Domain`, `IP`, `AttachmentHash`, `URL`, `ThreatCampaign`.
- Maps edges: `(:Sender)-[:SENT]->(:Email)`, `(:Email)-[:HAS_URL]->(:URL)`, `(:URL)-[:HOSTED_ON]->(:IP)`.
- Campaign clustering based on similarity algorithms (SimHash, Jaccard similarity on body templates, shared attack infrastructure).
- Discovers hidden relationships across distinct phishing runs.
