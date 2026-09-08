"""Netra Ingestion Service - Layer 1 (Input Layer)
FastAPI service accepting .eml uploads and raw email text, persisting to MinIO,
and publishing ingestion events to Redis.
"""

import time
import uuid
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, Any

from fastapi import FastAPI, File, UploadFile, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import redis.asyncio as aioredis

from netra_common.config import settings
from netra_common.events import AsyncPipelineEventPublisher, PipelineStage
from netra_common.models.email import IngestionEvent
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize Redis and MinIO storage clients on service startup."""
    global redis_client, minio_client, event_publisher
    logger.info("Initializing Netra Ingestion Service...")

    # Redis connection
    redis_client = aioredis.from_url(
        settings.redis_url,
        decode_responses=True
    )

    # MinIO client
    minio_client = MinioStorageClient(
        endpoint=settings.MINIO_ENDPOINT,
        access_key=settings.MINIO_ROOT_USER,
        secret_key=settings.MINIO_ROOT_PASSWORD,
        secure=settings.MINIO_SECURE,
    )
    minio_client.ensure_bucket(settings.RAW_EMAILS_BUCKET)

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

    minio_ok = minio_client.check_health() if minio_client else False

    healthy = redis_ok and minio_ok
    status_code = status.HTTP_200_OK if healthy else status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "healthy" if healthy else "degraded",
        "redis_connected": redis_ok,
        "minio_connected": minio_ok,
    }


@app.post(
    "/api/v1/ingest/file",
    response_model=IngestionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["Ingestion"],
)
async def ingest_eml_file(file: UploadFile = File(...)):
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
        await redis_client.lpush(INGESTION_QUEUE, event.model_dump_json())
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
async def ingest_raw_text(payload: RawEmailTextRequest):
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
        await redis_client.lpush(INGESTION_QUEUE, event.model_dump_json())
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
