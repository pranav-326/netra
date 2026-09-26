"""Netra API Gateway & Persistence Service - Layers 7 & 9
FastAPI management service running a background consumer on Redis final_persistence_queue,
persisting finalized CorrelatedEmail records into PostgreSQL, and exposing REST endpoints.
"""

import asyncio
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, status, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as aioredis

from netra_common.config import settings
from netra_common.events import (
    AsyncPipelineEventPublisher,
    PipelineStage,
    STAGE_SEQUENCE,
    TERMINAL_STAGE,
    TOTAL_STAGES,
    channel_for,
    read_event_log,
)
from netra_common.fastapi_auth import require_role
from netra_common.models.email import CorrelatedEmail
from netra_common.security import ROLE_ADMIN, ROLE_ANALYST, Principal, require_secret
from src.auth import (
    audit_consumer_loop,
    audit_event,
    bootstrap_accounts,
    principal_for_stream,
    record,
    router as auth_router,
)
from src.database import init_db, get_db_session, async_session_maker, EmailReport
from src.graph_reader import GraphUnavailable, Neo4jGraphReader

logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("netra.api_gateway")

FINAL_PERSISTENCE_QUEUE = "final_persistence_queue"

# Upper bound on how long a browser may hold an SSE stream open waiting for a
# pipeline to finish. A healthy run completes in well under a second, so this is
# sized for fast, visible feedback when a worker is down rather than for patience.
SSE_TIMEOUT_SECONDS = int(os.getenv("NETRA_SSE_TIMEOUT_SECONDS", "45"))
SSE_HEARTBEAT_SECONDS = 15

# Global consumer task handle
consumer_task: Optional[asyncio.Task] = None
redis_client: Optional[aioredis.Redis] = None
event_publisher: Optional[AsyncPipelineEventPublisher] = None
graph_reader: Optional[Neo4jGraphReader] = None


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
            stage_started = time.perf_counter()

            try:
                data = json.loads(raw_payload)
                correlated = CorrelatedEmail(**data)
            except Exception as e:
                logger.error(f"Malformed payload in {FINAL_PERSISTENCE_QUEUE}: {e}")
                continue

            # Extract report properties
            email_id = correlated.email_id
            owner_username = await redis_client.get(f"email_owner:{email_id}") if redis_client else None
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
                        existing.owner_username = owner_username
                        existing.subject = subject
                        existing.sender = sender
                        existing.classification = verdict
                        existing.risk_score = risk_score
                        existing.campaign_id = campaign_id
                        existing.full_report = data
                    else:
                        report_record = EmailReport(
                            email_id=email_id,
                            owner_username=owner_username,
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

            if event_publisher:
                await event_publisher.emit(
                    email_id,
                    PipelineStage.PERSISTED,
                    latency_ms=(time.perf_counter() - stage_started) * 1000.0,
                    detail=f"Report committed to PostgreSQL: {verdict} at {risk_score}/100",
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
    global redis_client, consumer_task, event_publisher, graph_reader
    logger.info("Starting Netra API Gateway...")

    # Refuse to serve evidence without a signing key.
    require_secret(settings.NETRA_AUTH_SECRET)

    # Initialize PostgreSQL schema
    try:
        await init_db()
        logger.info("PostgreSQL database initialized.")
        await bootstrap_accounts()
    except Exception as e:
        logger.error(f"Failed to initialize PostgreSQL: {e}")

    # Initialize Redis connection
    redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
    app.state.redis = redis_client
    event_publisher = AsyncPipelineEventPublisher(redis_client)
    audit_task = asyncio.create_task(audit_consumer_loop(redis_client))

    # Neo4j read-side for campaign subgraphs
    graph_reader = Neo4jGraphReader()
    await graph_reader.connect()

    # Launch background persistence consumer
    consumer_task = asyncio.create_task(persistence_worker_loop())

    yield

    # Clean shutdown
    for task in (consumer_task, audit_task):
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    if graph_reader:
        await graph_reader.close()

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

app.include_router(auth_router)

# Every route that returns evidence needs a signed-in analyst (admins included).
analyst = require_role(ROLE_ANALYST)


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
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    classification: Optional[str] = Query(None),
    session: AsyncSession = Depends(get_db_session),
    principal: Principal = Depends(analyst),
):
    """Retrieve paginated list of recent finalized email threat reports."""
    query = select(EmailReport).order_by(desc(EmailReport.created_at)).limit(limit).offset(offset)
    if principal.role != ROLE_ADMIN:
        query = query.where(EmailReport.owner_username == principal.username)
    if classification:
        query = query.where(EmailReport.classification == classification.upper())

    result = await session.execute(query)
    records = result.scalars().all()
    await record(audit_event(request, principal, "report.list", count=len(records)))

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
    request: Request,
    session: AsyncSession = Depends(get_db_session),
    principal: Principal = Depends(analyst),
):
    """Retrieve full, finalized threat report for an email."""
    report = await session.get(EmailReport, email_id)
    if report and principal.role != ROLE_ADMIN and report.owner_username != principal.username:
        report = None
    await record(audit_event(request, principal, "report.view", email_id, success=report is not None))
    if not report:
        raise HTTPException(status_code=404, detail=f"Threat report for email {email_id} not found.")

    return report.full_report


@app.get("/api/v1/pipeline/stages", tags=["Pipeline"])
async def get_pipeline_stages():
    """Return the canonical stage sequence so the UI renders labels from one source of truth."""
    return {"total_stages": TOTAL_STAGES, "stages": STAGE_SEQUENCE}


async def _pipeline_event_stream(email_id: str, request: Request):
    """Yield SSE frames for one email: replayed history, then live stage transitions.

    Replay comes first because the early stages routinely finish before the
    browser opens its stream — without it the UI would miss stage 1 and 2.
    """
    if not redis_client:
        yield _sse_frame("error", {"message": "Event bus unavailable"})
        return

    seen_stages = set()

    # 1. Replay everything already recorded for this email.
    for event in await read_event_log(redis_client, email_id):
        seen_stages.add(event.get("stage"))
        yield _sse_frame("stage", event)
        if event.get("stage") == TERMINAL_STAGE or event.get("status") == "failed":
            yield _sse_frame("done", {"email_id": email_id, "reason": "replayed_terminal"})
            return

    # 2. Follow live transitions.
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(channel_for(email_id))
    started = asyncio.get_event_loop().time()
    last_heartbeat = started

    try:
        while True:
            if await request.is_disconnected():
                return

            now = asyncio.get_event_loop().time()
            if now - started > SSE_TIMEOUT_SECONDS:
                yield _sse_frame("timeout", {
                    "email_id": email_id,
                    "message": f"No terminal stage within {SSE_TIMEOUT_SECONDS}s",
                    "stages_seen": sorted(seen_stages),
                })
                return

            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)

            if message is None:
                # Keep proxies from closing an idle connection.
                if now - last_heartbeat >= SSE_HEARTBEAT_SECONDS:
                    last_heartbeat = now
                    yield ": heartbeat\n\n"
                continue

            try:
                event = json.loads(message["data"])
            except (json.JSONDecodeError, KeyError, TypeError):
                continue

            # Redis pub/sub can overlap with the replay above; don't double-render.
            if event.get("stage") in seen_stages:
                continue
            seen_stages.add(event.get("stage"))

            yield _sse_frame("stage", event)

            if event.get("stage") == TERMINAL_STAGE or event.get("status") == "failed":
                yield _sse_frame("done", {"email_id": email_id, "reason": "terminal_stage"})
                return
    finally:
        try:
            await pubsub.unsubscribe(channel_for(email_id))
            await pubsub.aclose()
        except Exception as exc:
            logger.debug(f"Error closing pubsub for {email_id}: {exc}")


def _sse_frame(event_name: str, data: Dict[str, Any]) -> str:
    """Format one Server-Sent Events frame."""
    return f"event: {event_name}\ndata: {json.dumps(data, default=str)}\n\n"


@app.get("/api/v1/pipeline/events/{email_id}", tags=["Pipeline"])
async def stream_pipeline_events(email_id: str, request: Request, ticket: Optional[str] = Query(None)):
    """Stream real pipeline stage transitions for an email over Server-Sent Events.

    Each `stage` frame is emitted by the service that actually did the work, and
    carries that service's measured latency. The stream terminates on the
    persistence stage, on a stage failure, or after SSE_TIMEOUT_SECONDS.

    Authenticate with a bearer token, or (browsers) a single-use `ticket` from
    POST /api/v1/pipeline/events/{email_id}/ticket.
    """
    principal = await principal_for_stream(request, email_id, ticket)
    await record(audit_event(request, principal, "pipeline.stream", email_id))
    return StreamingResponse(
        _pipeline_event_stream(email_id, request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/v1/pipeline/events/{email_id}/history", tags=["Pipeline"])
async def get_pipeline_event_history(email_id: str, principal: Principal = Depends(analyst)):
    """Non-streaming fallback returning the recorded stage events for an email."""
    if not redis_client:
        raise HTTPException(status_code=503, detail="Event bus unavailable.")

    events = await read_event_log(redis_client, email_id)
    return {
        "email_id": email_id,
        "total_stages": TOTAL_STAGES,
        "stages_completed": len([e for e in events if e.get("status") == "complete"]),
        "events": events,
    }


@app.get("/api/v1/graph/{email_id}", tags=["Graph"])
async def get_email_subgraph(email_id: str, request: Request, principal: Principal = Depends(analyst)):
    """Return the Neo4j attack-infrastructure subgraph centred on one email.

    Nodes are the email itself, the IOCs it touches, other emails reaching those same
    IOCs, and the campaign cluster. This is what backs the "shares infrastructure with
    N other emails" claim in the forensic report.
    """
    await record(audit_event(request, principal, "graph.view", email_id))
    if not graph_reader:
        raise HTTPException(status_code=503, detail="Graph reader not initialized.")

    try:
        return await graph_reader.fetch_email_subgraph(email_id)
    except GraphUnavailable as exc:
        raise HTTPException(status_code=503, detail=f"Neo4j unavailable: {exc}")
    except Exception as exc:
        logger.error(f"Graph query failed for {email_id}: {exc}")
        raise HTTPException(status_code=500, detail="Graph query failed.")
