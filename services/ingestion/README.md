# Service: Ingestion (Layer 1)

## Purpose
Responsible for high-throughput email ingestion across multiple channels:
- Direct `.eml` raw file uploads via multipart HTTP.
- Raw text / RFC 5322 string paste endpoints.
- Periodic / Event-driven IMAP and SMTP polling listeners.
- Webhook endpoints for email delivery providers (SendGrid, Mailgun, Postmark, AWS SES).

## Storage Interactions
- Writes raw payload to MinIO `raw-emails` bucket.
- Publishes `email.ingested` event to Redis Pub/Sub / Celery queue with generated `message_id` and metadata.
