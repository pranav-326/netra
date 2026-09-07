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
