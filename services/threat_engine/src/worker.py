"""Netra Threat Engine Worker Service - Layer 4 (Threat Engine)
Continuously polls analyzed emails from Redis threat_engine_queue, fuses signals into
a 0-100 risk score, classifies threats (BENIGN, SUSPICIOUS, MALICIOUS), aggregates IOCs,
and dispatches ClassifiedEmail payloads to threat_intel_queue for Layer 5 enrichment.
"""

import json
import logging
import signal
import time
from datetime import datetime

import redis
from pydantic import ValidationError

from netra_common.config import settings
from netra_common.models.email import (
    AnalyzedEmail,
    ClassifiedEmail,
    ThreatIntelligence,
)
from src.scorer import evaluate_threat_score
from src.ioc_extractor import extract_consolidated_iocs

logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("netra.threat_engine")

THREAT_ENGINE_QUEUE = "threat_engine_queue"
THREAT_INTEL_QUEUE = "threat_intel_queue"


class ThreatEngineWorker:
    """Worker evaluating threat scores, classification verdicts, and extracting IOCs."""

    def __init__(self):
        self.running = True
        logger.info("Initializing Netra Threat Engine Worker...")

        self.redis_client = redis.Redis.from_url(
            settings.redis_url,
            decode_responses=True,
        )

        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

    def _handle_shutdown(self, signum, frame):
        logger.info("Shutdown signal received. Gracefully stopping threat engine worker...")
        self.running = False

    def classify_email(self, analyzed_email: AnalyzedEmail) -> ClassifiedEmail:
        """Run rule scoring algorithm and aggregate IOCs."""
        # 1. Evaluate Rule-Based Threat Score & Classification
        risk_score, verdict, matched_rules = evaluate_threat_score(analyzed_email.analysis)

        # 2. Extract and Deduplicate IOCs
        iocs = extract_consolidated_iocs(analyzed_email.parsed_email, analyzed_email.analysis)

        threat_assessment = ThreatIntelligence(
            risk_score=risk_score,
            classification=verdict,
            matched_rules=matched_rules,
            iocs=iocs,
            classified_at=datetime.utcnow(),
        )

        return ClassifiedEmail(
            email_id=analyzed_email.email_id,
            analyzed_email=analyzed_email,
            threat_assessment=threat_assessment,
        )

    def process_message(self, raw_message: str) -> None:
        """Deserialize AnalyzedEmail, run Threat Engine, and forward to Layer 5."""
        try:
            data = json.loads(raw_message)
            analyzed_email = AnalyzedEmail(**data)
        except Exception as e:
            logger.error(f"Failed to parse message from {THREAT_ENGINE_QUEUE}: {e}")
            return

        logger.info(f"Classifying threat for email {analyzed_email.email_id}...")

        try:
            classified = self.classify_email(analyzed_email)
        except Exception as e:
            logger.exception(f"Error classifying email {analyzed_email.email_id}: {e}")
            return

        # Push to threat_intel_queue
        try:
            payload = classified.model_dump_json()
            self.redis_client.lpush(THREAT_INTEL_QUEUE, payload)
            assessment = classified.threat_assessment
            logger.info(
                f"Classified email {classified.email_id}: "
                f"Verdict={assessment.classification.value}, "
                f"RiskScore={assessment.risk_score}/100, "
                f"IOCs={len(assessment.iocs)}, "
                f"RulesTriggered={len(assessment.matched_rules)}. "
                f"Dispatched to '{THREAT_INTEL_QUEUE}'."
            )
        except Exception as e:
            logger.error(f"Failed to push classified email {classified.email_id} to Redis: {e}")

    def run(self):
        """Worker main loop polling Redis with blocking pop."""
        logger.info(f"Threat Engine worker started. Listening on queue '{THREAT_ENGINE_QUEUE}'...")

        while self.running:
            try:
                result = self.redis_client.brpop(THREAT_ENGINE_QUEUE, timeout=2)
                if result:
                    _, raw_message = result
                    self.process_message(raw_message)
            except redis.ConnectionError as e:
                logger.warning(f"Redis connection error: {e}. Retrying in 3 seconds...")
                time.sleep(3)
            except Exception as e:
                logger.error(f"Unexpected error in threat engine loop: {e}")
                time.sleep(1)

        logger.info("Threat Engine worker shutdown complete.")


if __name__ == "__main__":
    worker = ThreatEngineWorker()
    worker.run()
