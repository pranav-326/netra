"""Unit tests for the cross-layer pipeline telemetry event bus."""

import json

import pytest

from netra_common.events import (
    EVENT_LOG_MAX_ENTRIES,
    EVENT_LOG_TTL_SECONDS,
    STAGE_INDEX,
    STAGE_SEQUENCE,
    TERMINAL_STAGE,
    TOTAL_STAGES,
    PipelineEventPublisher,
    PipelineStage,
    StageTimer,
    build_event,
    channel_for,
    log_key_for,
)


class FakePipeline:
    """Records the commands a publisher queues, mimicking redis-py's pipeline API."""

    def __init__(self, recorder):
        self.recorder = recorder

    def rpush(self, key, value):
        self.recorder.append(("rpush", key, value))

    def ltrim(self, key, start, end):
        self.recorder.append(("ltrim", key, start, end))

    def expire(self, key, ttl):
        self.recorder.append(("expire", key, ttl))

    def publish(self, channel, value):
        self.recorder.append(("publish", channel, value))

    def execute(self):
        self.recorder.append(("execute",))


class FakeRedis:
    def __init__(self, fail=False):
        self.commands = []
        self.fail = fail

    def pipeline(self):
        if self.fail:
            raise ConnectionError("redis is down")
        return FakePipeline(self.commands)


def test_stage_sequence_is_contiguous_and_ordered():
    """Stage indices must be 1..N with no gaps; the UI renders progress from them."""
    indices = [stage["index"] for stage in STAGE_SEQUENCE]
    assert indices == list(range(1, TOTAL_STAGES + 1))
    assert len(STAGE_INDEX) == TOTAL_STAGES
    assert STAGE_SEQUENCE[-1]["key"] == TERMINAL_STAGE


def test_every_stage_names_the_service_that_emits_it():
    """Each stage must attribute itself to a real service, so the UI cannot invent one."""
    expected = {
        "ingested": "ingestion",
        "parsed": "parser",
        "analyzed": "analyzer",
        "scored": "threat_engine",
        "enriched": "threat_intel",
        "correlated": "correlation",
        "persisted": "api_gateway",
    }
    assert {s["key"]: s["service"] for s in STAGE_SEQUENCE} == expected


def test_build_event_resolves_stage_metadata():
    event = build_event("abc-123", PipelineStage.SCORED, latency_ms=12.3456, detail="MALICIOUS at 80/100")

    assert event.email_id == "abc-123"
    assert event.stage_index == 4
    assert event.label == "Threat Scoring"
    assert event.service == "threat_engine"
    assert event.status == "complete"
    assert event.latency_ms == 12.35  # rounded to 2dp for display
    assert event.total_stages == TOTAL_STAGES


def test_build_event_rejects_unknown_stage():
    with pytest.raises(ValueError):
        build_event("abc-123", "teleportation")


def test_publisher_writes_replay_log_and_publishes_live():
    """Both transports must fire: the replay list and the pub/sub channel."""
    redis = FakeRedis()
    PipelineEventPublisher(redis).emit("e-1", PipelineStage.PARSED, latency_ms=5.0, detail="2 URLs")

    kinds = [cmd[0] for cmd in redis.commands]
    assert kinds == ["rpush", "ltrim", "expire", "publish", "execute"]

    rpush, ltrim, expire, publish, _ = redis.commands
    assert rpush[1] == log_key_for("e-1")
    assert ltrim[2:] == (-EVENT_LOG_MAX_ENTRIES, -1)
    assert expire[2] == EVENT_LOG_TTL_SECONDS
    assert publish[1] == channel_for("e-1")

    # The replayed payload and the live payload must be identical.
    assert rpush[2] == publish[2]
    payload = json.loads(publish[2])
    assert payload["stage"] == "parsed"
    assert payload["service"] == "parser"
    assert payload["latency_ms"] == 5.0


def test_publisher_emits_failure_events_with_reason():
    redis = FakeRedis()
    PipelineEventPublisher(redis).emit(
        "e-2", PipelineStage.ANALYZED, status="failed", latency_ms=1.0, error="engine exploded"
    )

    payload = json.loads(redis.commands[0][2])
    assert payload["status"] == "failed"
    assert payload["error"] == "engine exploded"


def test_publisher_never_raises_when_redis_is_down():
    """Telemetry must degrade the UI, never drop the email being analyzed."""
    redis = FakeRedis(fail=True)
    PipelineEventPublisher(redis).emit("e-3", PipelineStage.INGESTED)  # must not raise


def test_publisher_ignores_unknown_stage_without_raising():
    redis = FakeRedis()
    PipelineEventPublisher(redis).emit("e-4", "not-a-stage")
    assert redis.commands == []


def test_stage_timer_measures_elapsed_time():
    with StageTimer() as timer:
        sum(range(100000))
    elapsed = timer.elapsed_ms
    assert elapsed > 0
    # The timer freezes on exit, so repeated reads are stable.
    assert timer.elapsed_ms == elapsed
