# Service: API Gateway & Management API (Layer 7 & 9)

## Purpose
Unified API Gateway serving the analyst frontend and downstream SIEM integrations:
- Exposes RESTful endpoints for analyst dashboard querying, manual sample submission, and triage overrides.
- Provides threat scoring explanations, metrics, and report generation (JSON/PDF).
- Connects with OpenSearch for fast fulltext/IOC searches.
- Integrates Keycloak for OAuth2/OIDC RBAC authentication.
- Produces immutable audit logs for compliance.
