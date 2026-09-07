"""Netra Graph Correlation Worker Service - Layer 6 (Correlation)
Continuously polls enriched emails from Redis correlation_queue, persists nodes & edges
into Neo4j, detects campaign clusters sharing infrastructure, constructs canonical
CorrelatedEmail schemas, and pushes to final_persistence_queue for Layer 7 persistence.
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
    EnrichedEmail,
    CorrelatedEmail,
)
from src.graph import Neo4jCorrelator

logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("netra.correlation")

CORRELATION_QUEUE = "correlation_queue"
FINAL_PERSISTENCE_QUEUE = "final_persistence_queue"


class CorrelationWorker:
    """Worker integrating email data with Neo4j and detecting phishing campaigns."""

    def __init__(self):
        self.running = True
        logger.info("Initializing Netra Graph Correlation Worker...")

        self.redis_client = redis.Redis.from_url(
            settings.redis_url,
            decode_responses=True,
        )
        self.correlator = Neo4jCorrelator()

        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

    def _handle_shutdown(self, signum, frame):
        logger.info("Shutdown signal received. Gracefully stopping correlation worker...")
        self.running = False
        self.correlator.close()

    def process_message(self, raw_message: str) -> None:
        """Deserialize EnrichedEmail, run Neo4j correlation, and forward to Layer 7."""
        try:
            data = json.loads(raw_message)
            enriched_email = EnrichedEmail(**data)
        except Exception as e:
            logger.error(f"Failed to parse message from {CORRELATION_QUEUE}: {e}")
            return

        email_id = enriched_email.email_id
        logger.info(f"Correlating email {email_id} in Neo4j graph...")

        try:
            correlation_data = self.correlator.correlate_email(enriched_email)
            correlated_email = CorrelatedEmail(
                email_id=email_id,
                enriched_email=enriched_email,
                correlation=correlation_data,
                finalized_at=datetime.utcnow(),
            )
        except Exception as e:
            logger.exception(f"Error during graph correlation for email {email_id}: {e}")
            return

        # Push to final_persistence_queue
        try:
            payload = correlated_email.model_dump_json()
            self.redis_client.lpush(FINAL_PERSISTENCE_QUEUE, payload)
            logger.info(
                f"Correlated email {email_id}: "
                f"Campaign={correlation_data.campaign_id or 'None'}, "
                f"RelatedEmails={len(correlation_data.related_email_ids)}. "
                f"Dispatched to '{FINAL_PERSISTENCE_QUEUE}'."
            )
        except Exception as e:
            logger.error(f"Failed to push correlated email {email_id} to Redis: {e}")

    def run(self):
        """Worker main loop polling Redis with blocking pop."""
        logger.info(f"Correlation worker started. Listening on queue '{CORRELATION_QUEUE}'...")

        while self.running:
            try:
                result = self.redis_client.brpop(CORRELATION_QUEUE, timeout=2)
                if result:
                    _, raw_message = result
                    self.process_message(raw_message)
            except redis.ConnectionError as e:
                logger.warning(f"Redis connection error: {e}. Retrying in 3 seconds...")
                time.sleep(3)
            except Exception as e:
                logger.error(f"Unexpected error in correlation loop: {e}")
                time.sleep(1)

        logger.info("Correlation worker shutdown complete.")


if __name__ == "__main__":
    worker = CorrelationWorker()
    worker.run()
