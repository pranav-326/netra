"""Netra Threat Intelligence Worker Service - Layer 5 (Threat Intel)
Continuously polls classified emails from Redis threat_intel_queue, executes external
enrichment on extracted IOCs via MockIntelProvider, constructs canonical EnrichedEmail
schemas, and dispatches them to correlation_queue for Layer 6 graph analysis.
"""

import json
import logging
import signal
import time

import redis
from pydantic import ValidationError

from netra_common.config import settings
from netra_common.models.email import (
    ClassifiedEmail,
    EnrichedEmail,
)
from src.provider import MockIntelProvider

logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("netra.threat_intel")

THREAT_INTEL_QUEUE = "threat_intel_queue"
CORRELATION_QUEUE = "correlation_queue"


class ThreatIntelWorker:
    """Worker enriching IOCs with external threat intelligence."""

    def __init__(self):
        self.running = True
        logger.info("Initializing Netra Threat Intel Worker...")

        self.redis_client = redis.Redis.from_url(
            settings.redis_url,
            decode_responses=True,
        )
        self.provider = MockIntelProvider()

        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

    def _handle_shutdown(self, signum, frame):
        logger.info("Shutdown signal received. Gracefully stopping threat intel worker...")
        self.running = False

    def process_message(self, raw_message: str) -> None:
        """Deserialize ClassifiedEmail, enrich IOCs, and forward to Layer 6."""
        try:
            data = json.loads(raw_message)
            classified_email = ClassifiedEmail(**data)
        except Exception as e:
            logger.error(f"Failed to parse message from {THREAT_INTEL_QUEUE}: {e}")
            return

        email_id = classified_email.email_id
        logger.info(f"Enriching IOCs for email {email_id}...")

        try:
            enrichment_data = self.provider.enrich_iocs(classified_email.threat_assessment.iocs)
            enriched_email = EnrichedEmail(
                email_id=email_id,
                classified_email=classified_email,
                enrichment=enrichment_data,
            )
        except Exception as e:
            logger.exception(f"Error enriching email {email_id}: {e}")
            return

        # Push to correlation_queue
        try:
            payload = enriched_email.model_dump_json()
            self.redis_client.lpush(CORRELATION_QUEUE, payload)
            logger.info(
                f"Enriched email {email_id}: "
                f"MaliciousIOCs={enrichment_data.malicious_iocs_found}/{enrichment_data.total_iocs_checked}, "
                f"ThreatActors={enrichment_data.threat_actors}. "
                f"Dispatched to '{CORRELATION_QUEUE}'."
            )
        except Exception as e:
            logger.error(f"Failed to push enriched email {email_id} to Redis: {e}")

    def run(self):
        """Worker main loop polling Redis via blocking pop."""
        logger.info(f"Threat Intel worker started. Listening on queue '{THREAT_INTEL_QUEUE}'...")

        while self.running:
            try:
                result = self.redis_client.brpop(THREAT_INTEL_QUEUE, timeout=2)
                if result:
                    _, raw_message = result
                    self.process_message(raw_message)
            except redis.ConnectionError as e:
                logger.warning(f"Redis connection error: {e}. Retrying in 3 seconds...")
                time.sleep(3)
            except Exception as e:
                logger.error(f"Unexpected error in threat intel loop: {e}")
                time.sleep(1)

        logger.info("Threat Intel worker shutdown complete.")


if __name__ == "__main__":
    worker = ThreatIntelWorker()
    worker.run()
