# Netra - Email Threat Intelligence & Analysis Pipeline

Netra is an enterprise-grade Email Threat Intelligence and Forensic Analysis Platform designed to ingest, parse, analyze, correlate, and score email-based cyber threats in real time.

---

## Architecture Overview

The system is decomposed into 10 logical layers:
- **Layer 1: Input Layer (Email Ingestion)** - `.eml` uploads, raw RFC 5322 text, IMAP/SMTP hooks.
- **Layer 2: Preprocessing & Parsing** - Header chain analysis, HTML normalization, attachment decoding, URL extraction.
- **Layer 3: Analysis Engines** - SPF/DKIM/DMARC authentication, URL lexical/reputation checks, content NLP, attachment forensics.
- **Layer 4: Threat Engine** - IOC correlation, YARA rule evaluation, behavioral indicators, ML threat classification.
- **Layer 5: Threat Intelligence** - Multi-source threat enrichment (VirusTotal, AbuseIPDB, WHOIS, URLhaus, MISP).
- **Layer 6: Correlation & Graph Analysis** - Infrastructure mapping in Neo4j, campaign similarity clustering.
- **Layer 7: Risk, Explainability & Output** - Risk scoring (0–100), SHAP/LIME explainability, PDF/JSON forensic reports.
- **Layer 8: Data & Infrastructure (Core)** - PostgreSQL, Neo4j, OpenSearch, Redis, MinIO S3.
- **Layer 9: Security & Compliance** - Keycloak OIDC/RBAC, audit trails, PII/data masking.
- **Layer 10: External Feeds** - Real-time DNSBL, threat lists, and reputation feeds.

---

## Layer 8 Infrastructure Stack (Docker Compose)

The local development infrastructure stack is provisioned via `docker-compose.yml`:

| Service | Port(s) | Functionality | Mount / Volume |
| :--- | :--- | :--- | :--- |
| **PostgreSQL 16** | `5432` | Relational metadata, parsed headers, IOCs, audit logs | `netra_postgres_data` |
| **Redis 7** | `6379` | Fast caching, task queue (Celery), pipeline event bus | `netra_redis_data` |
| **OpenSearch 2.13** | `9200`, `9600` | Full-text search on email bodies, forensic logs, vector index | `netra_opensearch_data` |
| **Neo4j 5** | `7474` (UI), `7687` (Bolt) | Attack infrastructure graph, campaign cluster relationships | `netra_neo4j_data`, `netra_neo4j_logs` |
| **MinIO** | `9000` (S3), `9001` (UI) | Object storage for raw EML evidence & extracted attachments | `netra_minio_data` |
| **MinIO Init** | _Ephemeral_ | Auto-provisions `raw-emails`, `attachments`, `quarantine`, `reports` | None (cli tool) |

---

## Network Architecture & Volume Mounts

### Network Configuration (`netra-network`)
- All database and storage containers are attached to an isolated bridge network named `netra-network`.
- **Service Discovery**: Containers communicate internally using service names as hostnames (e.g., `postgres:5432`, `redis:6379`, `minio:9000`, `neo4j:7687`, `opensearch:9200`).
- **Isolation**: Prevents external exposure except for mapped development host ports. Future microservices connect to `netra-network` to seamlessly access all datastores.

### Persistent Volume Mounts
Named Docker volumes ensure data is preserved across container restarts, rebuilds, and migrations:
- `netra_postgres_data`: Persists the PostgreSQL data directory `/var/lib/postgresql/data`.
- `netra_redis_data`: Persists Redis snapshots and append-only files (AOF) in `/data`.
- `netra_opensearch_data`: Persists OpenSearch indices and cluster state in `/usr/share/opensearch/data`.
- `netra_neo4j_data` & `netra_neo4j_logs`: Persists the Neo4j graph database state and query transaction logs.
- `netra_minio_data`: Persists raw object blobs (email samples, quarantined malware) in `/data`.

---

## Live Pipeline Telemetry (Server-Sent Events)

The web UI does not simulate progress. Every stage indicator and every latency number
shown during an analysis originates from an event published by the service that actually
performed the work.

### How it works

1. Each service wraps its unit of work in a `StageTimer` and, after handing the email to
   the next queue, publishes a `PipelineEvent` (`common/src/netra_common/events.py`).
2. The event goes to two places: a per-email Redis pub/sub channel
   (`pipeline_events:{email_id}`) for live push, and a TTL'd replay list
   (`pipeline_events_log:{email_id}`) so a browser that attaches late still sees the
   stages that already completed.
3. The API Gateway exposes that stream over SSE. The browser subscribes and renders
   stages as they land.

### Stage sequence

| # | Stage | Emitting service | Layer |
| :-- | :--- | :--- | :--- |
| 1 | Ingestion | `ingestion` | 1 |
| 2 | MIME Parsing | `parser` | 2 |
| 3 | Analysis Engines | `analyzer` | 3 |
| 4 | Threat Scoring | `threat_engine` | 4 |
| 5 | Threat Intel | `threat_intel` | 5 |
| 6 | Graph Correlation | `correlation` | 6 |
| 7 | Report Persistence | `api_gateway` | 7 |

### Endpoints

| Endpoint | Purpose |
| :--- | :--- |
| `GET /api/v1/pipeline/stages` | Canonical stage definitions (the UI renders labels from this, never from hardcoded values) |
| `GET /api/v1/pipeline/events/{email_id}` | SSE stream of live stage transitions; terminates on the persistence stage, on a stage failure, or after `NETRA_SSE_TIMEOUT_SECONDS` (default 45s) |
| `GET /api/v1/pipeline/events/{email_id}/history` | Non-streaming fallback returning the recorded events for an email |

Watch a real run from the command line:

```bash
EMAIL_ID=$(curl -s -X POST http://localhost:8000/api/v1/ingest/text \
  -H 'Content-Type: application/json' \
  -d "{\"raw_email\": $(python3 -c 'import json,sys;print(json.dumps(open("tests/samples/phishing_sample.eml").read()))')}" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["email_id"])')

curl -N "http://localhost:8080/api/v1/pipeline/events/$EMAIL_ID"
```

### Failure behaviour

If a worker is down, the pipeline visibly stalls at the last stage that reported, the UI
stays on the analysis page with the stage count it reached, and no report is produced.
Verify it:

```bash
docker compose stop analyzer
```

Submit an email — the UI halts at stage 2/7 (`MIME Parsing`), `/api/v1/reports/{id}`
returns 404, and the stream emits a `timeout` frame after 45 seconds.

### Offline Parse Preview

The analysis page has an opt-in **Offline Parse Preview** toggle for inspecting a message
when the pipeline is unavailable. It transcribes structure only — headers, relay chain,
URLs, attachments, and the SHA-256 — and renders it inline on the analysis page.

It produces **no risk score and no classification**. Netra has exactly one scoring engine,
[`services/threat_engine/src/scorer.py`](services/threat_engine/src/scorer.py), and it runs
server-side. Every number and verdict in the product traces back to it.

Consequences of that rule, enforced in the code:

- `frontend/src/lib/emlParser.js` parses; it does not score. The former in-browser scoring
  heuristic has been removed.
- Authentication results are **echoed** from the `Authentication-Results` header the
  receiving MTA wrote, and marked `not stated` when absent. The preview never infers a
  result from a missing header.
- Fields that cannot be determined from the message are shown as `not present` rather than
  filled with a plausible default.
- `/result` and `/report` render only backend-scored records or clearly-labelled bundled
  sample cases. There is no client-side report path.

---

## Explainability: the score is the explanation

Netra scores with a deterministic rule engine, and the risk score is *defined* as the
clamped sum of per-rule contributions. There is no post-hoc attribution step because
there is no opaque model to attribute — the explanation is the computation.

`services/threat_engine/src/scorer.py` emits a `RuleContribution` for every rule that
fires:

```json
{
  "rule_id": "CNT-BEC-COMPOUND",
  "category": "content",
  "label": "High-confidence BEC compound vector",
  "points": 20,
  "evidence": "urgent financial request: CNT-BEC-FINANCIAL and CNT-URGENCY both fired"
}
```

The UI renders these as a waterfall chart (`frontend/src/components/ScoreWaterfall.jsx`):
each bar starts where the previous one ended, so the running total is visible at every
step, and the verdict scale beneath it shows which threshold produced the label.

Properties this buys, all covered by `tests/test_score_explainability.py`:

- **Exact, not approximate.** `risk_score == sum(c.points for c in rule_contributions)`.
- **Reproducible.** The same email always yields the same score and the same bars.
- **Contestable.** An analyst can dispute one line — `URL-TYPOSQUAT`, +40 — rather than
  arguing with a probability.
- **Honest about the ceiling.** `score_before_clamp` is preserved, so a message whose
  evidence sums to 210 shows "clamped from 210 to 100" instead of silently capping.

> Netra deliberately ships no ML classifier. For an evidentiary tool where an analyst
> must justify a quarantine decision, a rule engine that shows its arithmetic is a
> stronger position than a model that needs SHAP to guess at its own reasoning.

---

## The learned scoring layer

Netra's rule engine is a linear additive scorer with hand-set weights. This layer adds a
**logistic regression** trained on labelled corpora, contributing one more bar to the same
waterfall. It is a second opinion, never an override.

### Why logistic regression, and not a deep model

- The score is already `sum(weight x feature)`. A linear model keeps that arithmetic, so
  the explanation stays **exact** — per-feature contribution is `coefficient x value`, and
  those terms sum to the logit by definition. No SHAP or LIME approximation is needed
  because nothing is opaque.
- The artifact is **plain JSON a human can read** (11 coefficients, 4 KB). A pickle would
  be opaque and a code-execution risk.
- Inference is **pure Python** — no scikit-learn, numpy, or pickle in any service image.
  Training is a dev-machine activity. Same email, same score, forever.

### Measured performance

Trained on **7,321 messages** (4,570 phishing / 2,751 benign) from the
SpamAssassin public corpus (ham) and the Nazario phishing corpus — both chosen because
they carry **full headers**, which half the features depend on.

| Metric | Value |
| :--- | ---: |
| ROC AUC | **0.8669** |
| PR AUC | 0.9208 |
| Precision | 0.9512 |
| Recall | 0.7258 |
| Decision threshold | 0.4508 (derived, not chosen) |

All figures are **stratified 5-fold out-of-fold** — no message contributes to the model
that scores it. Confusion matrix: TN=2581, FP=170, FN=1253, TP=3317.
The threshold is selected as the highest recall meeting a 95% precision target, which is
the question the hand-tuned `61` could never answer.

Full report including the ROC curve and the learned-vs-hand-set weight comparison:
`ml/reports/evaluation.md`.

### Two failures found during training, and what they cost

**An earlier model scored ROC AUC 0.99 by learning the corpora apart, not phishing.**
Its strongest features were `has_html_body` (+4.04) and `url_count` (-3.89): 2002
mailing-list ham is plaintext, 2000s phishing is HTML, so the model learned the
collection era. Signs were backwards on real signals — more URLs read as *safer*.
Seven formatting features are now excluded by default (`FORMAT_LEAKAGE_FEATURES`), and
honest accuracy fell from 0.99 to **0.8669**. That drop is the real number.

**A near-constant feature flagged a clean email as SUSPICIOUS.** `auth_anomaly_count`
had mean 3.998 and std 0.057 across training, because neither corpus predates
SPF/DKIM deployment. Standardisation mapped a correctly authenticated modern email
(0 anomalies) to **-70 sigma**, and a small coefficient turned that into +26 points.
Two guards now exist: the trainer drops features with training std below `MIN_FEATURE_STD`
(0.1), and inference clips any standardised value to ±5 sigma.

### Honest limits

- **The corpora predate SPF/DKIM/DMARC.** No message in either set carries an
  `Authentication-Results` header, so all authentication features were dropped as
  near-constant. The model contributes **nothing** on sender authentication — that
  dimension is handled entirely by the rule engine. The two layers are complementary,
  which is exactly why neither replaces the other.
- **No executables appear in either corpus**, so attachment features were dropped too.
  `ATT-EXEC` remains a pure rule.
- Individual coefficients are not independently interpretable under correlated inputs;
  only the **sum** is. See "Reading these coefficients" in the evaluation report.

### Retraining

```bash
pip install -e ./common -r requirements-ml.txt
python -m ml.corpus --phishing data/phishing --benign data/benign --out data/features.jsonl
python -m ml.train_scorer --features data/features.jsonl
```

`ml/corpus.py` runs the **production** parser and analyzer over every corpus message
rather than reimplementing extraction, so train/serve skew is structurally impossible.

If the artifact is missing or malformed the pipeline logs it and runs rules-only —
identical behaviour to before this layer existed.

## Layer 5: Threat Intelligence

Two providers share one `enrich_iocs(iocs) -> EnrichmentData` interface, selected at
startup by `build_intel_provider()`:

| Provider | Covers | Selected when |
| :--- | :--- | :--- |
| `CompositeIntelProvider` | IPs via the **live AbuseIPDB API**, everything else via the mock | `ABUSEIPDB_API_KEY` is set |
| `MockIntelProvider` | Curated local dataset for IPs, domains, URLs and hashes | no key configured |

### Provenance labelling

Every `EnrichedIOC` carries the provider that actually produced it, and simulated data
says so:

```
ip             45.154.255.89              AbuseIPDB (live)
domain         overdue-vendorgroup.net    Internal Feeds (simulated)
sha256         4e91bc82...                VirusTotal (simulated)
```

`enrichment_sources` lists only feeds that returned a verdict — an empty list means
nothing matched, not that no feed was consulted.

### Configuration

Set the key in `.env` (never in source; `.env` is gitignored):

```bash
ABUSEIPDB_API_KEY=your_key_here
ABUSEIPDB_ENABLED=true
ABUSEIPDB_MALICIOUS_THRESHOLD=50    # abuseConfidenceScore at or above which an IP is malicious
ABUSEIPDB_CACHE_TTL_SECONDS=21600   # 6h Redis cache
```

Get a free key at https://www.abuseipdb.com/account/api. Without one the pipeline runs
identically on the simulated dataset.

### Living inside the free tier (1,000 checks/day)

- **Non-routable addresses are never sent upstream.** Private, loopback, link-local,
  multicast and reserved ranges cannot have public abuse reports, so spending quota on
  them is waste. Filtered in `is_publicly_routable()`.
- **Verdicts are cached in Redis**, shared across worker restarts and replicas. A
  campaign of 50 emails from one relay costs one lookup, not fifty. Measured:
  738ms uncached → 1ms cached.
- **Clean results are negative-cached** for an hour, so repeat benign senders are free.
- **Remaining quota is read from `X-RateLimit-Remaining`** and logged, with a warning
  below 25 — exhaustion is visible, not silent.

### Failure behaviour

Threat intel is enrichment; it must never be able to drop an email. Every failure path —
timeout, HTTP 429, rejected key, malformed body — returns `None`, and the composite
provider falls back **per indicator**: an IP the live API could not answer keeps its
simulated verdict and its `(simulated)` label, while IPs that did resolve keep their live
one. A 429 or 401 suspends further calls for the run so a dead key does not add latency
to every email.

`None` means *"no live data"*, never *"clean"* — conflating those would let an outage
silently exonerate malicious infrastructure. Covered by
`tests/test_threat_intel_providers.py`.

## Campaign Correlation Graph

The correlation service (stage 6) writes an attack-infrastructure graph into Neo4j:
`Email`, `IP`, `Domain`, `URL`, `FileHash` and `Campaign` nodes joined by
`ORIGINATED_FROM`, `USES_DOMAIN`, `CONTAINS_URL`, `ATTACHED_FILE` and
`PART_OF_CAMPAIGN` edges.

`services/api_gateway/src/graph_reader.py` reads that graph back as a subgraph centred
on one email, and the report page renders it
(`frontend/src/components/CampaignGraph.jsx`) as a deterministic three-ring layout:
the analysed email at the centre, the IOCs it touches on the inner ring, and every other
ingested email reaching those same IOCs on the outer ring. Bridging IOCs are drawn larger
and labelled with how many emails reach them.

| Endpoint | Purpose |
| :--- | :--- |
| `GET /api/v1/graph/{email_id}` | Nodes, edges, campaign, and stats for one email's subgraph |

```bash
curl -s http://localhost:8080/api/v1/graph/<email_id> | python3 -m json.tool
```

This is the claim a per-message rule engine cannot make on its own: not "this email is
malicious", but *"this email shares 8 indicators with 15 other messages we have ingested,
and they form campaign CAMP-05697282."*

The layout is fixed rather than force-directed so the same case always draws the same
picture — a forensic artifact people compare across runs should not rearrange itself.
When Neo4j is unreachable the panel says **"Graph unavailable"** and states explicitly
that this is not the same as "no shared infrastructure found".

## Running the Tests

```bash
pip install -e ./common -r requirements-dev.txt
pytest tests -q
```

## Step-by-Step Setup Instructions

### 1. Prerequisites
Ensure you have the following installed on your machine:
- **Docker Engine** (version 24.0+ recommended) & **Docker Compose V2** (`docker compose`)
- **Python 3.11+** (for service development)
- `curl` (for health checks)

### 2. Environment Configuration
Verify that the `.env` file exists in the project root (copied from `.env.example`):
```bash
# In the project root directory
cp .env.example .env
```
Inspect or customize the credentials in `.env` if desired.

### 3. Launch the Infrastructure Stack
Start all Layer 8 services in detached mode:
```bash
docker compose up -d
```

### 4. Verify Provisioning & Health
Wait a few seconds for containers to initialize and execute the included health check script:
```bash
./scripts/healthcheck.sh
```

Or check container status with Docker Compose:
```bash
docker compose ps
```

### 5. Accessing Management UIs
Once running, you can access the respective management consoles locally:
- **MinIO Object Console**: [http://localhost:9001](http://localhost:9001)
  - _Username_: `netra_minio_admin`
  - _Password_: `netra_minio_secret_2026`
- **Neo4j Graph Browser**: [http://localhost:7474](http://localhost:7474)
  - _Username_: `neo4j`
  - _Password_: `netra_secret_graph_2026`
- **OpenSearch Cluster Status**: [http://localhost:9200/_cluster/health](http://localhost:9200/_cluster/health)
- **PostgreSQL**: Connect via any client (`psql`, DBeaver, TablePlus) on `localhost:5432`:
  - _Database_: `netra_db`
  - _User_: `netra_admin`
  - _Password_: `netra_secure_password_2026`

### 6. Stopping the Stack
- To stop the infrastructure without deleting persisted data:
  ```bash
  docker compose stop
  ```
- To spin down and remove containers while preserving persistent volumes:
  ```bash
  docker compose down
  ```
- To wipe containers and delete all persisted volumes (complete reset):
  ```bash
  docker compose down -v
  ```
