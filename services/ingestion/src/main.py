"""Netra Ingestion Service - Layer 1 (Input Layer)
FastAPI service accepting .eml uploads and raw email text, persisting to MinIO,
and publishing ingestion events to Redis.
"""

import hashlib
import time
import uuid
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, Any

from fastapi import Depends, FastAPI, File, Request, UploadFile, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import redis.asyncio as aioredis

from netra_common.audit import AUDIT_QUEUE, AuditEvent
from netra_common.config import settings
from netra_common.events import AsyncPipelineEventPublisher, PipelineStage
from netra_common.fastapi_auth import client_ip, require_role
from netra_common.models.email import IngestionEvent
from netra_common.security import ROLE_ANALYST, Principal, require_secret
from netra_common.storage.minio_client import MinioStorageClient

# Setup logging
logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("netra.ingestion")

# Global clients
redis_client: aioredis.Redis = None
minio_client: MinioStorageClient = None
event_publisher: AsyncPipelineEventPublisher = None
INGESTION_QUEUE = "email_ingestion_queue"
OWNER_KEY_TTL_SECONDS = 7 * 24 * 60 * 60


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize Redis and MinIO storage clients on service startup."""
    global redis_client, minio_client, event_publisher
    logger.info("Initializing Netra Ingestion Service...")
    require_secret(settings.NETRA_AUTH_SECRET)

    # Redis connection
    redis_client = aioredis.from_url(
        settings.redis_url,
        decode_responses=True
    )

    # Evidence store (SeaweedFS over S3). Ingestion is the first service to touch it,
    # so it provisions every evidence bucket.
    minio_client = MinioStorageClient(
        endpoint=settings.S3_ENDPOINT,
        access_key=settings.S3_ACCESS_KEY,
        secret_key=settings.S3_SECRET_KEY,
        secure=settings.S3_SECURE,
    )
    for bucket in settings.evidence_buckets:
        minio_client.ensure_bucket(bucket)

    # Pipeline telemetry publisher (Layer 1 stage events)
    event_publisher = AsyncPipelineEventPublisher(redis_client)

    logger.info("Ingestion Service dependencies initialized.")
    yield

    # Teardown
    if redis_client:
        await redis_client.close()
    logger.info("Ingestion Service cleanly stopped.")


app = FastAPI(
    title="Netra Email Ingestion API",
    version="1.0.0",
    description="Layer 1 Input Layer: Ingests raw RFC 5322 emails into MinIO & notifies pipeline via Redis.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


async def queue_with_audit(event: IngestionEvent, raw: bytes, principal: Principal, request: Request) -> None:
    """Queue the email and its chain-of-custody record in one Redis transaction.

    Either both land or neither does, so no email enters the pipeline unrecorded. The
    SHA-256 lets anyone later verify the object in MinIO is the bytes that were submitted.
    """
    audit = AuditEvent(
        service="ingestion",
        username=principal.username,
        role=principal.role,
        action="email.ingest",
        resource=event.email_id,
        client_ip=client_ip(request),
        detail={
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
            "source_type": event.source_type,
            "original_filename": event.original_filename,
            "object": f"{event.bucket}/{event.object_key}",
        },
    )
    async with redis_client.pipeline(transaction=True) as pipe:
        pipe.lpush(INGESTION_QUEUE, event.model_dump_json())
        pipe.lpush(AUDIT_QUEUE, audit.model_dump_json())
        pipe.set(f"email_owner:{event.email_id}", principal.username, ex=OWNER_KEY_TTL_SECONDS)
        await pipe.execute()


class RawEmailTextRequest(BaseModel):
    """Request payload for raw email text ingestion."""
    raw_email: str = Field(..., min_length=1, description="Raw RFC 5322 email string including headers and body")


class IngestionResponse(BaseModel):
    """Response returned upon successful email ingestion."""
    status: str = "accepted"
    email_id: str
    bucket: str
    object_key: str
    file_size_bytes: int
    source_type: str
    ingested_at: datetime


@app.get("/health", tags=["Health"])
async def health_check():
    """Service health check verifying MinIO and Redis readiness."""
    redis_ok = False
    try:
        if redis_client:
            redis_ok = await redis_client.ping()
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")

    storage_ok = minio_client.check_health() if minio_client else False

    healthy = redis_ok and storage_ok
    status_code = status.HTTP_200_OK if healthy else status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "healthy" if healthy else "degraded",
        "redis_connected": redis_ok,
        "object_store_connected": storage_ok,
    }


@app.post(
    "/api/v1/ingest/file",
    response_model=IngestionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["Ingestion"],
)
async def ingest_eml_file(
    request: Request,
    file: UploadFile = File(...),
    principal: Principal = Depends(require_role(ROLE_ANALYST)),
):
    """Upload a raw .eml file."""
    started = time.perf_counter()
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing file name.")

    try:
        content = await file.read()
    except Exception as e:
        logger.error(f"Error reading uploaded file: {e}")
        raise HTTPException(status_code=400, detail="Unable to read uploaded file.")

    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    email_id = str(uuid.uuid4())
    object_key = f"{email_id}.eml"

    # Persist raw bytes in MinIO
    try:
        minio_client.put_bytes(
            bucket_name=settings.RAW_EMAILS_BUCKET,
            object_name=object_key,
            data=content,
            content_type="message/rfc822",
        )
    except Exception as e:
        logger.error(f"Failed to persist {object_key} to MinIO: {e}")
        raise HTTPException(status_code=500, detail="Storage backend failure.")

    # Emit ingestion event to Redis
    event = IngestionEvent(
        email_id=email_id,
        bucket=settings.RAW_EMAILS_BUCKET,
        object_key=object_key,
        ingested_at=datetime.utcnow(),
        source_type="file",
        file_size_bytes=len(content),
        original_filename=file.filename,
    )

    try:
        await queue_with_audit(event, content, principal, request)
    except Exception as e:
        logger.error(f"Failed to push event {email_id} to Redis: {e}")
        raise HTTPException(status_code=500, detail="Message broker failure.")

    logger.info(f"Ingested EML file: email_id={email_id}, size={len(content)} bytes")

    await event_publisher.emit(
        email_id,
        PipelineStage.INGESTED,
        latency_ms=(time.perf_counter() - started) * 1000.0,
        detail=f"Stored {file.filename} ({len(content)} bytes) to {settings.RAW_EMAILS_BUCKET}",
    )

    return IngestionResponse(
        email_id=email_id,
        bucket=settings.RAW_EMAILS_BUCKET,
        object_key=object_key,
        file_size_bytes=len(content),
        source_type="file",
        ingested_at=event.ingested_at,
    )


@app.post(
    "/api/v1/ingest/text",
    response_model=IngestionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["Ingestion"],
)
async def ingest_raw_text(
    payload: RawEmailTextRequest,
    request: Request,
    principal: Principal = Depends(require_role(ROLE_ANALYST)),
):
    """Ingest raw email text/headers provided via JSON."""
    started = time.perf_counter()
    raw_bytes = payload.raw_email.encode("utf-8")
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Raw email text is empty.")

    email_id = str(uuid.uuid4())
    object_key = f"{email_id}.eml"

    # Persist raw bytes in MinIO
    try:
        minio_client.put_bytes(
            bucket_name=settings.RAW_EMAILS_BUCKET,
            object_name=object_key,
            data=raw_bytes,
            content_type="message/rfc822",
        )
    except Exception as e:
        logger.error(f"Failed to persist {object_key} to MinIO: {e}")
        raise HTTPException(status_code=500, detail="Storage backend failure.")

    # Emit ingestion event to Redis
    event = IngestionEvent(
        email_id=email_id,
        bucket=settings.RAW_EMAILS_BUCKET,
        object_key=object_key,
        ingested_at=datetime.utcnow(),
        source_type="text",
        file_size_bytes=len(raw_bytes),
    )

    try:
        await queue_with_audit(event, raw_bytes, principal, request)
    except Exception as e:
        logger.error(f"Failed to push event {email_id} to Redis: {e}")
        raise HTTPException(status_code=500, detail="Message broker failure.")

    logger.info(f"Ingested raw email text: email_id={email_id}, size={len(raw_bytes)} bytes")

    await event_publisher.emit(
        email_id,
        PipelineStage.INGESTED,
        latency_ms=(time.perf_counter() - started) * 1000.0,
        detail=f"Stored {len(raw_bytes)} bytes of raw RFC 5322 text to {settings.RAW_EMAILS_BUCKET}",
    )

    return IngestionResponse(
        email_id=email_id,
        bucket=settings.RAW_EMAILS_BUCKET,
        object_key=object_key,
        file_size_bytes=len(raw_bytes),
        source_type="text",
        ingested_at=event.ingested_at,
    )
