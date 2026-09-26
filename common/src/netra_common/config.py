"""Centralized configuration definitions for Netra services."""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Environment
    ENVIRONMENT: str = Field(default="development")
    LOG_LEVEL: str = Field(default="INFO")

    # PostgreSQL (Layer 8)
    POSTGRES_HOST: str = Field(default="localhost")
    POSTGRES_PORT: int = Field(default=5432)
    POSTGRES_DB: str = Field(default="netra_db")
    POSTGRES_USER: str = Field(default="netra_admin")
    POSTGRES_PASSWORD: str = Field(default="netra_secure_password_2026")

    @property
    def postgres_async_url(self) -> str:
        return f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"

    # Redis (Layer 8)
    REDIS_HOST: str = Field(default="localhost")
    REDIS_PORT: int = Field(default=6379)
    REDIS_PASSWORD: str = Field(default="")

    @property
    def redis_url(self) -> str:
        if self.REDIS_PASSWORD:
            return f"redis://:{self.REDIS_PASSWORD}@{self.REDIS_HOST}:{self.REDIS_PORT}/0"
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/0"

    # OpenSearch (Layer 8)
    OPENSEARCH_HOST: str = Field(default="localhost")
    OPENSEARCH_PORT: int = Field(default=9200)

    @property
    def opensearch_url(self) -> str:
        return f"http://{self.OPENSEARCH_HOST}:{self.OPENSEARCH_PORT}"

    # Neo4j (Layer 8)
    NEO4J_HOST: str = Field(default="localhost")
    NEO4J_BOLT_PORT: int = Field(default=7687)
    NEO4J_USER: str = Field(default="neo4j")
    NEO4J_PASSWORD: str = Field(default="netra_secret_graph_2026")

    @property
    def neo4j_bolt_url(self) -> str:
        return f"bolt://{self.NEO4J_HOST}:{self.NEO4J_BOLT_PORT}"

    # MinIO / S3 (Layer 8)
    MINIO_ENDPOINT: str = Field(default="localhost:9000")
    MINIO_ROOT_USER: str = Field(default="netra_minio_admin")
    MINIO_ROOT_PASSWORD: str = Field(default="netra_minio_secret_2026")
    MINIO_SECURE: bool = Field(default=False)
    RAW_EMAILS_BUCKET: str = Field(default="raw-emails")
    ATTACHMENTS_BUCKET: str = Field(default="attachments")
    QUARANTINE_BUCKET: str = Field(default="quarantine")
    REPORTS_BUCKET: str = Field(default="reports")

    # ------------------------------------------------------------------
    # Layer 5: External Threat Intelligence
    # ------------------------------------------------------------------
    # AbuseIPDB free tier allows 1,000 checks/day, so IP lookups are cached in Redis
    # and private/reserved ranges are never sent upstream.
    ABUSEIPDB_API_KEY: str = Field(default="", description="AbuseIPDB API key; live IP enrichment is disabled when empty")
    ABUSEIPDB_ENABLED: bool = Field(default=True, description="Master switch for live IP enrichment")
    ABUSEIPDB_TIMEOUT_SECONDS: float = Field(default=4.0, description="Per-request timeout for AbuseIPDB")
    ABUSEIPDB_MAX_AGE_DAYS: int = Field(default=90, description="Report age window passed to AbuseIPDB")
    ABUSEIPDB_MALICIOUS_THRESHOLD: int = Field(default=50, description="abuseConfidenceScore at or above which an IP is treated as malicious")
    ABUSEIPDB_CACHE_TTL_SECONDS: int = Field(default=21600, description="Redis cache TTL for AbuseIPDB verdicts (6h) to conserve free-tier quota")

    @property
    def abuseipdb_active(self) -> bool:
        """Live IP enrichment runs only when explicitly enabled and a key is present."""
        return bool(self.ABUSEIPDB_ENABLED and self.ABUSEIPDB_API_KEY.strip())

    # ------------------------------------------------------------------
    # Layer 9: Authentication
    # ------------------------------------------------------------------
    # Shared by every service that verifies tokens. Services refuse to start without it
    # rather than run unauthenticated.
    NETRA_AUTH_SECRET: str = Field(default="", description="HMAC key for signing access tokens (32+ random bytes)")
    NETRA_TOKEN_TTL_SECONDS: int = Field(default=8 * 3600, description="Access token lifetime: one working shift")
    # Accounts created on first gateway start when the users table is empty.
    NETRA_ADMIN_USERNAME: str = Field(default="admin")
    NETRA_ADMIN_PASSWORD: str = Field(default="", description="Bootstrap admin password; no admin is created when empty")
    NETRA_ANALYST_USERNAME: str = Field(default="analyst")
    NETRA_ANALYST_PASSWORD: str = Field(default="", description="Optional bootstrap analyst password")


settings = Settings()
