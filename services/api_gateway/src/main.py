"""Netra API Gateway & Persistence Service - Layers 7 & 9
FastAPI management service running a background consumer on Redis final_persistence_queue,
persisting finalized CorrelatedEmail records into PostgreSQL, and exposing REST endpoints.
"""

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, status, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as aioredis

from netra_common.config import settings
from netra_common.models.email import CorrelatedEmail
from src.database import init_db, get_db_session, async_session_maker, EmailReport

logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("netra.api_gateway")

FINAL_PERSISTENCE_QUEUE = "final_persistence_queue"

# Global consumer task handle
consumer_task: Optional[asyncio.Task] = None
redis_client: Optional[aioredis.Redis] = None


async def persistence_worker_loop():
    """Background async worker pulling finalized emails from Redis and persisting to PostgreSQL."""
    logger.info(f"Starting PostgreSQL persistence consumer on queue '{FINAL_PERSISTENCE_QUEUE}'...")

    while True:
        try:
            if not redis_client:
                await asyncio.sleep(2)
                continue

            # Blocking pop from final_persistence_queue
            result = await redis_client.brpop(FINAL_PERSISTENCE_QUEUE, timeout=2)
            if not result:
                continue

            _, raw_payload = result

            try:
                data = json.loads(raw_payload)
                correlated = CorrelatedEmail(**data)
            except Exception as e:
                logger.error(f"Malformed payload in {FINAL_PERSISTENCE_QUEUE}: {e}")
                continue

            # Extract report properties
            email_id = correlated.email_id
            parsed_headers = correlated.enriched_email.classified_email.analyzed_email.parsed_email.headers
            assessment = correlated.enriched_email.classified_email.threat_assessment
            correlation = correlated.correlation

            subject = parsed_headers.subject or "No Subject"
            sender = parsed_headers.from_address or "Unknown"
            verdict = assessment.classification.value
            risk_score = assessment.risk_score
            campaign_id = correlation.campaign_id

            # Persist to PostgreSQL
            async with async_session_maker() as session:
                async with session.begin():
                    # Check if already exists (upsert)
                    existing = await session.get(EmailReport, email_id)
                    if existing:
                        existing.subject = subject
                        existing.sender = sender
                        existing.classification = verdict
                        existing.risk_score = risk_score
                        existing.campaign_id = campaign_id
                        existing.full_report = data
                    else:
                        report_record = EmailReport(
                            email_id=email_id,
                            subject=subject,
                            sender=sender,
                            classification=verdict,
                            risk_score=risk_score,
                            campaign_id=campaign_id,
                            full_report=data,
                        )
                        session.add(report_record)

            logger.info(
                f"Successfully persisted report for {email_id} to PostgreSQL: "
                f"Verdict={verdict}, Score={risk_score}, Campaign={campaign_id or 'None'}"
            )

        except asyncio.CancelledError:
            logger.info("Persistence consumer task cancelled.")
            break
        except Exception as e:
            logger.error(f"Error in persistence worker loop: {e}")
            await asyncio.sleep(2)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database tables, Redis connection, and background persistence worker."""
    global redis_client, consumer_task
    logger.info("Starting Netra API Gateway...")

    # Initialize PostgreSQL schema
    try:
        await init_db()
        logger.info("PostgreSQL database initialized.")
    except Exception as e:
        logger.error(f"Failed to initialize PostgreSQL: {e}")

    # Initialize Redis connection
    redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)

    # Launch background persistence consumer
    consumer_task = asyncio.create_task(persistence_worker_loop())

    yield

    # Clean shutdown
    if consumer_task:
        consumer_task.cancel()
        try:
            await consumer_task
        except asyncio.CancelledError:
            pass

    if redis_client:
        await redis_client.close()
    logger.info("API Gateway cleanly stopped.")


app = FastAPI(
    title="Netra Threat Intelligence API Gateway",
    version="1.0.0",
    description="Layers 7 & 9: Reports retrieval, analytics query service, and audit persistence.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ReportSummary(BaseModel):
    """Summary item of an email threat report."""
    email_id: str
    subject: Optional[str]
    sender: Optional[str]
    classification: str
    risk_score: int
    campaign_id: Optional[str]
    created_at: Any


@app.get("/health", tags=["Health"])
async def health_check():
    """Healthcheck endpoint for PostgreSQL and Redis connectivity."""
    db_ok = False
    try:
        async with async_session_maker() as session:
            await session.execute(select(1))
            db_ok = True
    except Exception as e:
        logger.error(f"DB healthcheck failed: {e}")

    redis_ok = False
    try:
        if redis_client:
            redis_ok = await redis_client.ping()
    except Exception as e:
        logger.error(f"Redis healthcheck failed: {e}")

    healthy = db_ok and redis_ok
    status_code = status.HTTP_200_OK if healthy else status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "healthy" if healthy else "degraded",
        "database_connected": db_ok,
        "redis_connected": redis_ok,
    }


@app.get("/api/v1/reports", response_model=List[ReportSummary], tags=["Reports"])
async def list_reports(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    classification: Optional[str] = Query(None),
    session: AsyncSession = Depends(get_db_session),
):
    """Retrieve paginated list of recent finalized email threat reports."""
    query = select(EmailReport).order_by(desc(EmailReport.created_at)).limit(limit).offset(offset)
    if classification:
        query = query.where(EmailReport.classification == classification.upper())

    result = await session.execute(query)
    records = result.scalars().all()

    return [
        ReportSummary(
            email_id=rec.email_id,
            subject=rec.subject,
            sender=rec.sender,
            classification=rec.classification,
            risk_score=rec.risk_score,
            campaign_id=rec.campaign_id,
            created_at=rec.created_at,
        )
        for rec in records
    ]


@app.get("/api/v1/reports/{email_id}", tags=["Reports"])
async def get_report_by_id(
    email_id: str,
    session: AsyncSession = Depends(get_db_session),
):
    """Retrieve full, finalized threat report for an email."""
    record = await session.get(EmailReport, email_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Threat report for email {email_id} not found.")

    return record.full_report
