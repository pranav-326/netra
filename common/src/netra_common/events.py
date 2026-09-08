"""Pipeline telemetry events (cross-layer).

Every worker in the Netra pipeline emits a `stage_complete` (or `stage_failed`)
event as it hands an email to the next queue. The API Gateway replays these over
Server-Sent Events so the UI can render true pipeline progress and per-stage
latency instead of a client-side animation.

Two transports are used together:

* A per-email Redis pub/sub channel (`pipeline_events:{email_id}`) for live push.
* A capped, TTL'd replay list (`pipeline_events_log:{email_id}`) so a subscriber
  that attaches after a stage already fired still sees it. Without this, the
  first stages routinely complete before the browser opens its stream.
"""

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("netra.events")

# Replay window: long enough for a browser reconnect, short enough to stay cheap.
EVENT_LOG_TTL_SECONDS = 900
EVENT_LOG_MAX_ENTRIES = 64


def channel_for(email_id: str) -> str:
    """Redis pub/sub channel carrying live stage events for one email."""
    return f"pipeline_events:{email_id}"


def log_key_for(email_id: str) -> str:
    """Redis list key holding the replayable event history for one email."""
    return f"pipeline_events_log:{email_id}"


class PipelineStage:
    """Canonical stage keys. One per service that touches the email."""

    INGESTED = "ingested"
    PARSED = "parsed"
    ANALYZED = "analyzed"
    SCORED = "scored"
    ENRICHED = "enriched"
    CORRELATED = "correlated"
    PERSISTED = "persisted"


# Ordered stage descriptors. `index` drives the UI progress bar; `layer` and
# `service` keep the display honest about which container actually did the work.
STAGE_SEQUENCE: List[Dict[str, Any]] = [
    {"key": PipelineStage.INGESTED, "index": 1, "label": "Ingestion", "layer": 1, "service": "ingestion"},
    {"key": PipelineStage.PARSED, "index": 2, "label": "MIME Parsing", "layer": 2, "service": "parser"},
    {"key": PipelineStage.ANALYZED, "index": 3, "label": "Analysis Engines", "layer": 3, "service": "analyzer"},
    {"key": PipelineStage.SCORED, "index": 4, "label": "Threat Scoring", "layer": 4, "service": "threat_engine"},
    {"key": PipelineStage.ENRICHED, "index": 5, "label": "Threat Intel", "layer": 5, "service": "threat_intel"},
    {"key": PipelineStage.CORRELATED, "index": 6, "label": "Graph Correlation", "layer": 6, "service": "correlation"},
    {"key": PipelineStage.PERSISTED, "index": 7, "label": "Report Persistence", "layer": 7, "service": "api_gateway"},
]

STAGE_INDEX: Dict[str, Dict[str, Any]] = {stage["key"]: stage for stage in STAGE_SEQUENCE}
TOTAL_STAGES = len(STAGE_SEQUENCE)
TERMINAL_STAGE = PipelineStage.PERSISTED


class PipelineEvent(BaseModel):
    """A single stage transition observed in the pipeline."""

    email_id: str = Field(..., description="Email the event belongs to")
    stage: str = Field(..., description="Stage key from PipelineStage")
    stage_index: int = Field(..., description="1-based position in STAGE_SEQUENCE")
    total_stages: int = Field(default=TOTAL_STAGES, description="Total stages in the pipeline")
    label: str = Field(..., description="Human-readable stage name")
    layer: int = Field(..., description="Architecture layer number")
    service: str = Field(..., description="Service/container that emitted the event")
    status: str = Field(default="complete", description="'complete' or 'failed'")
    latency_ms: Optional[float] = Field(None, description="Wall-clock time this stage spent on the email")
    detail: Optional[str] = Field(None, description="Short human-readable summary of what the stage found")
    error: Optional[str] = Field(None, description="Failure reason when status is 'failed'")
    emitted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


def build_event(
    email_id: str,
    stage: str,
    status: str = "complete",
    latency_ms: Optional[float] = None,
    detail: Optional[str] = None,
    error: Optional[str] = None,
) -> PipelineEvent:
    """Construct a PipelineEvent, resolving stage metadata from STAGE_INDEX."""
    meta = STAGE_INDEX.get(stage)
    if meta is None:
        raise ValueError(f"Unknown pipeline stage '{stage}'")

    return PipelineEvent(
        email_id=email_id,
        stage=stage,
        stage_index=meta["index"],
        label=meta["label"],
        layer=meta["layer"],
        service=meta["service"],
        status=status,
        latency_ms=round(latency_ms, 2) if latency_ms is not None else None,
        detail=detail,
        error=error,
    )


class StageTimer:
    """Context manager measuring wall-clock latency for one stage.

    Usage::

        with StageTimer() as timer:
            do_work()
        publisher.emit(email_id, PipelineStage.PARSED, latency_ms=timer.elapsed_ms)
    """

    def __init__(self) -> None:
        self._start = time.perf_counter()
        self._end: Optional[float] = None

    def __enter__(self) -> "StageTimer":
        self._start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self._end = time.perf_counter()
        return False

    @property
    def elapsed_ms(self) -> float:
        end = self._end if self._end is not None else time.perf_counter()
        return (end - self._start) * 1000.0


class PipelineEventPublisher:
    """Synchronous publisher for the blocking worker services.

    Telemetry must never break the pipeline: every method swallows Redis errors
    and logs them, so a publish failure degrades the UI rather than dropping the
    email being analyzed.
    """

    def __init__(self, redis_client: Any) -> None:
        self.redis = redis_client

    def emit(
        self,
        email_id: str,
        stage: str,
        status: str = "complete",
        latency_ms: Optional[float] = None,
        detail: Optional[str] = None,
        error: Optional[str] = None,
    ) -> None:
        try:
            event = build_event(email_id, stage, status, latency_ms, detail, error)
        except ValueError as exc:
            logger.error(f"Refusing to emit malformed pipeline event: {exc}")
            return

        payload = event.model_dump_json()
        try:
            pipe = self.redis.pipeline()
            pipe.rpush(log_key_for(email_id), payload)
            pipe.ltrim(log_key_for(email_id), -EVENT_LOG_MAX_ENTRIES, -1)
            pipe.expire(log_key_for(email_id), EVENT_LOG_TTL_SECONDS)
            pipe.publish(channel_for(email_id), payload)
            pipe.execute()
        except Exception as exc:
            logger.warning(f"Failed to publish pipeline event {stage} for {email_id}: {exc}")


class AsyncPipelineEventPublisher:
    """Async counterpart for the FastAPI services (ingestion, api_gateway)."""

    def __init__(self, redis_client: Any) -> None:
        self.redis = redis_client

    async def emit(
        self,
        email_id: str,
        stage: str,
        status: str = "complete",
        latency_ms: Optional[float] = None,
        detail: Optional[str] = None,
        error: Optional[str] = None,
    ) -> None:
        try:
            event = build_event(email_id, stage, status, latency_ms, detail, error)
        except ValueError as exc:
            logger.error(f"Refusing to emit malformed pipeline event: {exc}")
            return

        payload = event.model_dump_json()
        try:
            pipe = self.redis.pipeline()
            pipe.rpush(log_key_for(email_id), payload)
            pipe.ltrim(log_key_for(email_id), -EVENT_LOG_MAX_ENTRIES, -1)
            pipe.expire(log_key_for(email_id), EVENT_LOG_TTL_SECONDS)
            pipe.publish(channel_for(email_id), payload)
            await pipe.execute()
        except Exception as exc:
            logger.warning(f"Failed to publish pipeline event {stage} for {email_id}: {exc}")


async def read_event_log(redis_client: Any, email_id: str) -> List[Dict[str, Any]]:
    """Return the replayable event history for an email, oldest first."""
    try:
        raw_events = await redis_client.lrange(log_key_for(email_id), 0, -1)
    except Exception as exc:
        logger.warning(f"Failed to read event log for {email_id}: {exc}")
        return []

    events: List[Dict[str, Any]] = []
    for raw in raw_events:
        try:
            events.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return events
