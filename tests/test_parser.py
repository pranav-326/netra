"""Unit test for EmailParserWorker RFC 5322 parsing logic."""

import email
from email import policy
from email.message import EmailMessage
from unittest.mock import MagicMock

from netra_common.models.email import ParsedEmail
from netra_common.storage.minio_client import MinioStorageClient
from services.parser.src.worker import EmailParserWorker, URL_REGEX


def test_url_regex():
    sample_text = (
        "Check this link: http://malicious-domain.com/login.php and "
        "hxxps://phishing-portal[.]org/fake-bank. "
        "Also www.google.com/test?a=1&b=2."
    )
    worker = EmailParserWorker.__new__(EmailParserWorker)
    worker.minio_client = MagicMock()
    worker.redis_client = MagicMock()
    worker.running = False

    urls = worker.extract_urls(sample_text)
    assert any("malicious-domain.com" in u for u in urls), f"Missing domain in {urls}"
    assert any("phishing-portal" in u for u in urls), f"Missing defanged URL in {urls}"
    assert any("www.google.com" in u for u in urls), f"Missing www URL in {urls}"


def test_parse_rfc5322():
    # Build synthetic multipart RFC 5322 email
    msg = EmailMessage()
    msg["From"] = "Attacker <attacker@evil-domain.com>"
    msg["To"] = "victim@corporate.org, second_victim@corporate.org"
    msg["Subject"] = "URGENT: Verify Your Corporate Password Immediately"
    msg["Date"] = "Mon, 7 Sep 2026 10:00:00 +0000"
    msg["Message-ID"] = "<20260907100000.12345@evil-domain.com>"
    msg["Received"] = "from mail.evil-domain.com ([198.51.100.25]) by mx.corporate.org with ESMTP"

    msg.set_content(
        "Dear employee,\nPlease verify your account at https://evil-login.com/login?id=42.\nRegards,\nIT Team"
    )
    msg.add_alternative(
        "<html><body>Dear employee,<br>Please verify your account at "
        "<a href='https://evil-login.com/login?id=42'>Here</a>.<br>Regards,<br>IT Team</body></html>",
        subtype="html"
    )

    # Add mock attachment
    fake_attachment_bytes = b"%PDF-1.4 mock malware attachment content"
    msg.add_attachment(
        fake_attachment_bytes,
        maintype="application",
        subtype="pdf",
        filename="invoice_urgent.pdf"
    )

    raw_bytes = msg.as_bytes()

    # Mock worker
    worker = EmailParserWorker.__new__(EmailParserWorker)
    worker.minio_client = MagicMock()
    worker.redis_client = MagicMock()
    worker.running = False

    parsed: ParsedEmail = worker.parse_rfc5322(
        raw_bytes=raw_bytes,
        email_id="test-uuid-1234",
        bucket="raw-emails",
        object_key="test-uuid-1234.eml",
    )

    assert parsed.email_id == "test-uuid-1234"
    assert parsed.headers.from_address == "Attacker <attacker@evil-domain.com>"
    assert "victim@corporate.org" in parsed.headers.to_addresses
    assert parsed.headers.subject == "URGENT: Verify Your Corporate Password Immediately"
    assert len(parsed.headers.received_chain) == 1
    assert "https://evil-login.com/login?id=42" in parsed.extracted_urls
    assert len(parsed.attachments) == 1
    assert parsed.attachments[0].filename == "invoice_urgent.pdf"
    assert len(parsed.attachments[0].sha256) == 64

    # Verify MinIO put_bytes was called for the attachment
    assert worker.minio_client.put_bytes.called

    print("\n[SUCCESS] All parser tests passed successfully!")


if __name__ == "__main__":
    test_url_regex()
    test_parse_rfc5322()
