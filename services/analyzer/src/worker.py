"""Netra Analyzer Worker Service - Layer 3 (Analysis Engines)
Continuously polls parsed emails from Redis, applies multi-perspective security engines
(Headers/Auth, URLs/Typosquatting, Content/BEC heuristics, Attachments), constructs
canonical AnalyzedEmail schemas, and dispatches them to the threat_engine_queue.
"""

import json
import logging
import signal
import time
from datetime import datetime

import redis
from pydantic import ValidationError

from netra_common.config import settings
from netra_common.events import PipelineEventPublisher, PipelineStage, StageTimer
from netra_common.models.email import (
    ParsedEmail,
    AnalyzedEmail,
    AnalysisResults,
)
from src.engines import (
    analyze_headers,
    analyze_urls,
    analyze_content,
    analyze_attachments,
    analyze_origin,
)

logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("netra.analyzer")

PARSED_EMAIL_QUEUE = "parsed_email_queue"
THREAT_ENGINE_QUEUE = "threat_engine_queue"


class EmailAnalyzerWorker:
    """Worker listening to parsed emails, executing analysis engines, and pushing to Threat Engine."""

    def __init__(self):
        self.running = True
        logger.info("Initializing Netra Analyzer Worker...")

        self.redis_client = redis.Redis.from_url(
            settings.redis_url,
            decode_responses=True,
        )
        self.events = PipelineEventPublisher(self.redis_client)

        # Setup graceful shutdown handlers
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

    def _handle_shutdown(self, signum, frame):
        logger.info("Shutdown signal received. Gracefully stopping analyzer worker...")
        self.running = False

    def analyze_email(self, parsed_email: ParsedEmail) -> AnalyzedEmail:
        """Run all Layer 3 security analysis engines on the parsed email."""
        # 1. Header and Protocol Analysis
        header_result = analyze_headers(parsed_email.headers)

        # 2. URL and Domain Typosquatting Analysis
        url_result = analyze_urls(parsed_email.extracted_urls)

        # 3. Content and BEC Heuristic Analysis
        content_result = analyze_content(
            body_plain=parsed_email.body_plain,
            body_html=parsed_email.body_html,
            subject=parsed_email.headers.subject,
        )

        # 4. Attachment Security Analysis
        attachment_result = analyze_attachments(parsed_email.attachments)

        # 5. Origin clues other than IP (location evidence; adds no risk points)
        origin_result = analyze_origin(
            subject=parsed_email.headers.subject,
            body_plain=parsed_email.body_plain,
            body_html=parsed_email.body_html,
            date_header=parsed_email.headers.date,
            from_header=parsed_email.headers.from_address,
        )

        # Combine into unified AnalysisResults
        analysis_results = AnalysisResults(
            header_analysis=header_result,
            url_analysis=url_result,
            content_analysis=content_result,
            attachment_analysis=attachment_result,
            origin_analysis=origin_result,
        )

        return AnalyzedEmail(
            email_id=parsed_email.email_id,
            parsed_email=parsed_email,
            analysis=analysis_results,
            analyzed_at=datetime.utcnow(),
        )

    def process_message(self, raw_message: str) -> None:
        """Deserialize parsed email, run security engines, and forward to Threat Engine."""
        try:
            data = json.loads(raw_message)
            parsed_email = ParsedEmail(**data)
        except Exception as e:
            logger.error(f"Failed to parse message from {PARSED_EMAIL_QUEUE}: {e}")
            return

        logger.info(f"Running Layer 3 security analysis on email {parsed_email.email_id}...")

        timer = StageTimer()

        try:
            analyzed = self.analyze_email(parsed_email)
        except Exception as e:
            logger.exception(f"Error during analysis of email {parsed_email.email_id}: {e}")
            self.events.emit(parsed_email.email_id, PipelineStage.ANALYZED, status="failed",
                             latency_ms=timer.elapsed_ms, error=f"Analysis engines failed: {e}")
            return

        # Push to threat_engine_queue
        try:
            payload = analyzed.model_dump_json()
            self.redis_client.lpush(THREAT_ENGINE_QUEUE, payload)
            logger.info(
                f"Completed analysis for email {analyzed.email_id}: "
                f"SPF={analyzed.analysis.header_analysis.spf_verdict}, "
                f"Typosquats={len(analyzed.analysis.url_analysis.typosquat_detections)}, "
                f"ContentScore={analyzed.analysis.content_analysis.heuristic_content_score}, "
                f"ExecAttachments={analyzed.analysis.attachment_analysis.has_executable_attachment}. "
                f"Dispatched to '{THREAT_ENGINE_QUEUE}'."
            )
            self.events.emit(
                analyzed.email_id,
                PipelineStage.ANALYZED,
                latency_ms=timer.elapsed_ms,
                detail=f"SPF={analyzed.analysis.header_analysis.spf_verdict}, "
                       f"DMARC={analyzed.analysis.header_analysis.dmarc_verdict}, "
                       f"{len(analyzed.analysis.url_analysis.typosquat_detections)} typosquat hits",
            )
        except Exception as e:
            logger.error(f"Failed to push analyzed email {analyzed.email_id} to Redis: {e}")
            self.events.emit(analyzed.email_id, PipelineStage.ANALYZED, status="failed",
                             latency_ms=timer.elapsed_ms, error=f"Queue dispatch failed: {e}")

    def run(self):
        """Worker main loop polling Redis with blocking pop."""
        logger.info(f"Analyzer worker started. Listening on queue '{PARSED_EMAIL_QUEUE}'...")

        while self.running:
            try:
                result = self.redis_client.brpop(PARSED_EMAIL_QUEUE, timeout=2)
                if result:
                    _, raw_message = result
                    self.process_message(raw_message)
            except redis.ConnectionError as e:
                logger.warning(f"Redis connection error: {e}. Retrying in 3 seconds...")
                time.sleep(3)
            except Exception as e:
                logger.error(f"Unexpected error in analyzer loop: {e}")
                time.sleep(1)

        logger.info("Analyzer worker shutdown complete.")


if __name__ == "__main__":
    worker = EmailAnalyzerWorker()
    worker.run()
