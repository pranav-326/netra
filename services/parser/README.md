# Service: Preprocessing & Parsing (Layer 2)

## Purpose
Responsible for deep RFC 5322 and MIME structure analysis:
- Extracts transport headers (Received chain, Return-Path, Message-ID, Date, Subject, From, To, CC, Reply-To).
- Resolves character sets and normalizes plaintext & HTML bodies (stripping obfuscations, homoglyphs, zero-width spaces).
- Extracts and defangs URLs/hyperlinks from HTML and plaintext bodies.
- Decodes MIME multipart attachments, computes cryptographic hashes (MD5, SHA1, SHA256, SSDEEP), and uploads to MinIO `attachments` bucket.
- Stores normalized email metadata into PostgreSQL `ingestion.emails`.
- Emits `email.parsed` event for Layer 3 analyzers.
