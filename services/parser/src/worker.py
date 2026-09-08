"""Netra Parser Worker Service - Layer 2 (Preprocessing & Parsing)
Pulls raw email events from Redis, parses RFC 5322 structure, extracts headers,
bodies, URLs, and attachments (saving attachments to MinIO), and pushes
normalized ParsedEmail models to the parsed_email_queue.
"""

import email
from email import policy
from email.message import EmailMessage
import hashlib
import json
import logging
import re
import signal
import sys
import time
from typing import List, Tuple, Optional, Dict, Any

import redis
from pydantic import ValidationError

from netra_common.config import settings
from netra_common.events import PipelineEventPublisher, PipelineStage, StageTimer
from netra_common.models.email import (
    IngestionEvent,
    ParsedEmail,
    EmailHeaders,
    AttachmentMetadata,
)
from netra_common.storage.minio_client import MinioStorageClient

logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("netra.parser")

INGESTION_QUEUE = "email_ingestion_queue"
PARSED_QUEUE = "parsed_email_queue"

# Comprehensive regex to extract HTTP, HTTPS, FTP, and defanged URLs (hxxp, [.] etc.)
URL_REGEX = re.compile(
    r"""(?i)\b(?:https?|hxxps?|ftp)://[^\s<>"'{}|\\^`]+|\bwww\.[^\s<>"'{}|\\^`]+""",
    re.IGNORECASE,
)


class EmailParserWorker:
    """Worker listening to Redis ingestion events and parsing emails into canonical models."""

    def __init__(self, connect: bool = True):
        """Create a parser worker.

        `connect=False` builds an offline instance with no Redis, MinIO, or signal
        handlers — used by the ML training pipeline so that corpus emails are parsed
        by exactly the same code that parses production traffic. Any divergence here
        would be train/serve skew, and would silently poison the model.
        """
        self.running = True
        self.redis_client = None
        self.minio_client = None
        self.events = None

        if not connect:
            logger.info("Parser worker constructed in offline mode (no Redis/MinIO).")
            return

        logger.info("Initializing Netra Parser Worker...")

        # Redis synchronous client for reliable BRPOP
        self.redis_client = redis.Redis.from_url(
            settings.redis_url,
            decode_responses=True,
        )
        self.events = PipelineEventPublisher(self.redis_client)

        # MinIO client
        self.minio_client = MinioStorageClient(
            endpoint=settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ROOT_USER,
            secret_key=settings.MINIO_ROOT_PASSWORD,
            secure=settings.MINIO_SECURE,
        )
        self.minio_client.ensure_bucket(settings.ATTACHMENTS_BUCKET)

        # Setup graceful shutdown handlers
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

    def _handle_shutdown(self, signum, frame):
        logger.info("Shutdown signal received. Gracefully stopping parser worker...")
        self.running = False

    def extract_urls(self, text: str) -> List[str]:
        """Extract unique URLs from given text content."""
        if not text:
            return []
        matches = URL_REGEX.findall(text)
        cleaned = []
        for url in matches:
            # Strip trailing punctuation commonly captured by regex
            url = re.sub(r"[.,;:?!)>\]]+$", "", url)
            if url and url not in cleaned:
                cleaned.append(url)
        return cleaned

    def process_attachments(
        self, msg: EmailMessage, email_id: str
    ) -> List[AttachmentMetadata]:
        """Extract attachments from MIME parts, hash them, and store in MinIO."""
        attachments_meta: List[AttachmentMetadata] = []

        for part in msg.iter_attachments():
            filename = part.get_filename() or "unnamed_attachment"
            content_type = part.get_content_type()
            payload = part.get_payload(decode=True)

            if not payload:
                continue

            # Compute cryptographic hashes
            sha256 = hashlib.sha256(payload).hexdigest()
            md5 = hashlib.md5(payload).hexdigest()
            size_bytes = len(payload)

            # Sanitize filename for object key
            safe_filename = re.sub(r"[^\w\-.]", "_", filename)
            object_key = f"{email_id}/{sha256}_{safe_filename}"

            # Save attachment bytes into MinIO. In offline mode there is no object
            # store, but the metadata (name, hashes, size, MIME) is still produced —
            # that is what the attachment engine and the ML features actually read.
            if self.minio_client is not None:
                try:
                    self.minio_client.put_bytes(
                        bucket_name=settings.ATTACHMENTS_BUCKET,
                        object_name=object_key,
                        data=payload,
                        content_type=content_type,
                    )
                    logger.info(
                        f"Stored attachment: {filename} (SHA256: {sha256[:12]}..., {size_bytes} bytes) -> {object_key}"
                    )
                except Exception as e:
                    logger.error(f"Failed to store attachment {filename} for email {email_id}: {e}")
                    continue

            attachments_meta.append(
                AttachmentMetadata(
                    filename=filename,
                    content_type=content_type,
                    size_bytes=size_bytes,
                    sha256=sha256,
                    md5=md5,
                    bucket=settings.ATTACHMENTS_BUCKET,
                    object_key=object_key,
                )
            )

        return attachments_meta

    def parse_rfc5322(self, raw_bytes: bytes, email_id: str, bucket: str, object_key: str) -> ParsedEmail:
        """Parse raw RFC 5322 email bytes into structured ParsedEmail schema."""
        msg: EmailMessage = email.message_from_bytes(raw_bytes, policy=policy.default)

        # 1. Headers
        received_chain = msg.get_all("Received", [])
        to_list = [addr.strip() for addr in msg.get("To", "").split(",") if addr.strip()]
        cc_list = [addr.strip() for addr in msg.get("Cc", "").split(",") if addr.strip()]
        bcc_list = [addr.strip() for addr in msg.get("Bcc", "").split(",") if addr.strip()]

        raw_headers_dict: Dict[str, Any] = {}
        for header_key, header_val in msg.items():
            if header_key in raw_headers_dict:
                if isinstance(raw_headers_dict[header_key], list):
                    raw_headers_dict[header_key].append(str(header_val))
                else:
                    raw_headers_dict[header_key] = [raw_headers_dict[header_key], str(header_val)]
            else:
                raw_headers_dict[header_key] = str(header_val)

        headers = EmailHeaders(
            from_address=str(msg.get("From")) if msg.get("From") else None,
            to=to_list,
            cc=cc_list,
            bcc=bcc_list,
            reply_to=str(msg.get("Reply-To")) if msg.get("Reply-To") else None,
            subject=str(msg.get("Subject")) if msg.get("Subject") else None,
            date=str(msg.get("Date")) if msg.get("Date") else None,
            message_id=str(msg.get("Message-ID")) if msg.get("Message-ID") else None,
            received_chain=received_chain,
            raw_headers=raw_headers_dict,
        )

        # 2. Extract bodies (Plaintext & HTML)
        body_plain: Optional[str] = None
        body_html: Optional[str] = None

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                disposition = str(part.get_content_disposition())

                if "attachment" in disposition:
                    continue

                if content_type == "text/plain" and body_plain is None:
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or "utf-8"
                        body_plain = payload.decode(charset, errors="replace")
                    except Exception as e:
                        logger.warning(f"Error decoding text/plain part: {e}")
                elif content_type == "text/html" and body_html is None:
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or "utf-8"
                        body_html = payload.decode(charset, errors="replace")
                    except Exception as e:
                        logger.warning(f"Error decoding text/html part: {e}")
        else:
            # Single-part email
            content_type = msg.get_content_type()
            try:
                payload = msg.get_payload(decode=True)
                charset = msg.get_content_charset() or "utf-8"
                decoded_str = payload.decode(charset, errors="replace")
                if content_type == "text/html":
                    body_html = decoded_str
                else:
                    body_plain = decoded_str
            except Exception as e:
                logger.warning(f"Error decoding single part email: {e}")

        # 3. URL Extraction
        urls_set = set()
        if body_plain:
            urls_set.update(self.extract_urls(body_plain))
        if body_html:
            urls_set.update(self.extract_urls(body_html))

        # 4. Attachments Extraction
        attachments = self.process_attachments(msg, email_id)

        return ParsedEmail(
            email_id=email_id,
            raw_s3_bucket=bucket,
            raw_s3_key=object_key,
            headers=headers,
            body_plain=body_plain,
            body_html=body_html,
            extracted_urls=sorted(list(urls_set)),
            attachments=attachments,
        )

    def process_event(self, raw_event_str: str) -> None:
        """Parse raw event payload and process the email."""
        try:
            event_data = json.loads(raw_event_str)
            event = IngestionEvent(**event_data)
        except Exception as e:
            logger.error(f"Malformed ingestion event rejected: {e}, payload: {raw_event_str}")
            return

        logger.info(f"Processing email: id={event.email_id}, key={event.object_key}")

        timer = StageTimer()

        # Fetch raw email bytes from MinIO
        try:
            raw_bytes = self.minio_client.get_bytes(
                bucket_name=event.bucket,
                object_name=event.object_key,
            )
        except Exception as e:
            logger.error(f"Failed to fetch {event.object_key} from MinIO bucket {event.bucket}: {e}")
            self.events.emit(event.email_id, PipelineStage.PARSED, status="failed",
                             latency_ms=timer.elapsed_ms, error=f"Object storage fetch failed: {e}")
            return

        # Parse email
        try:
            parsed = self.parse_rfc5322(
                raw_bytes=raw_bytes,
                email_id=event.email_id,
                bucket=event.bucket,
                object_key=event.object_key,
            )
        except Exception as e:
            logger.exception(f"Unexpected error while parsing email {event.email_id}: {e}")
            self.events.emit(event.email_id, PipelineStage.PARSED, status="failed",
                             latency_ms=timer.elapsed_ms, error=f"MIME parse failed: {e}")
            return

        # Push normalized ParsedEmail to Layer 3 queue
        try:
            parsed_json = parsed.model_dump_json()
            self.redis_client.lpush(PARSED_QUEUE, parsed_json)
            logger.info(
                f"Successfully parsed email {event.email_id}: "
                f"subject='{parsed.headers.subject}', "
                f"urls={len(parsed.extracted_urls)}, "
                f"attachments={len(parsed.attachments)}. Pushed to {PARSED_QUEUE}."
            )
            self.events.emit(
                event.email_id,
                PipelineStage.PARSED,
                latency_ms=timer.elapsed_ms,
                detail=f"{len(parsed.extracted_urls)} URLs, {len(parsed.attachments)} attachments, "
                       f"{len(parsed.headers.received_chain or [])} relay hops extracted",
            )
        except Exception as e:
            logger.error(f"Failed pushing parsed email {event.email_id} to Redis: {e}")
            self.events.emit(event.email_id, PipelineStage.PARSED, status="failed",
                             latency_ms=timer.elapsed_ms, error=f"Queue dispatch failed: {e}")

    def run(self):
        """Worker main loop polling Redis via blocking pop (BRPOP)."""
        logger.info(f"Parser worker started. Listening on queue '{INGESTION_QUEUE}'...")

        while self.running:
            try:
                # BRPOP returns tuple (queue_name, item) or None if timeout reached
                result = self.redis_client.brpop(INGESTION_QUEUE, timeout=2)
                if result:
                    _, raw_event = result
                    self.process_event(raw_event)
            except redis.ConnectionError as e:
                logger.warning(f"Redis connection error: {e}. Retrying in 3 seconds...")
                time.sleep(3)
            except Exception as e:
                logger.error(f"Unexpected error in parser worker loop: {e}")
                time.sleep(1)

        logger.info("Parser worker shutdown complete.")


if __name__ == "__main__":
    worker = EmailParserWorker()
    worker.run()
