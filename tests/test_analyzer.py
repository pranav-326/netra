"""Unit tests for Layer 3 Analysis Engines."""

from services.analyzer.src.engines.header_engine import analyze_headers
from services.analyzer.src.engines.url_engine import analyze_urls, levenshtein_distance
from services.analyzer.src.engines.content_engine import analyze_content
from services.analyzer.src.engines.attachment_engine import analyze_attachments
from netra_common.models.email import EmailHeaders, AttachmentMetadata


def test_header_engine():
    # Case 1: Failing SPF and missing DKIM/DMARC
    headers = EmailHeaders(
        from_address="spoofed@bank.com",
        to=["victim@corp.com"],
        raw_headers={
            "Authentication-Results": "mx.corp.com; spf=fail (sender IP not authorized) smtp.mailfrom=bank.com; dkim=none; dmarc=fail",
            "From": "spoofed@bank.com",
            "Subject": "Urgent verification",
        }
    )
    result = analyze_headers(headers)
    assert result.spf_verdict == "fail", f"Expected spf fail, got {result.spf_verdict}"
    assert result.dkim_verdict == "none", f"Expected dkim none, got {result.dkim_verdict}"
    assert result.dmarc_verdict == "fail", f"Expected dmarc fail, got {result.dmarc_verdict}"
    assert len(result.auth_anomalies) > 0

    # Case 2: All passing
    headers_pass = EmailHeaders(
        from_address="legit@google.com",
        to=["user@corp.com"],
        message_id="<msg01@google.com>",
        raw_headers={
            "Authentication-Results": "mx.corp.com; spf=pass; dkim=pass header.i=@google.com; dmarc=pass",
        }
    )
    result_pass = analyze_headers(headers_pass)
    assert result_pass.spf_verdict == "pass"
    assert result_pass.dkim_verdict == "pass"
    assert result_pass.dmarc_verdict == "pass"
    print("[PASS] Header Engine test passed.")


def test_url_engine():
    # Levenshtein distance check
    assert levenshtein_distance("micros0ft.com", "microsoft.com") == 1
    assert levenshtein_distance("paypa1.com", "paypal.com") == 1

    urls = [
        "https://micros0ft.com/login",
        "http://paypal.account-verify.net/auth",
        "http://192.168.1.50/malware.sh",
        "hxxps://phishing-portal[.]org",
    ]
    result = analyze_urls(urls)
    assert result.total_urls_inspected == 4
    assert len(result.ip_host_urls) == 1
    assert len(result.defanged_urls) == 1
    assert len(result.typosquat_detections) >= 1
    targets = [d.target_brand for d in result.typosquat_detections]
    assert any("microsoft.com" in t or "paypal.com" in t for t in targets)
    print("[PASS] URL Engine test passed.")


def test_content_engine():
    body_plain = (
        "URGENT: Immediate action required! Your account has been suspended due to suspicious activity. "
        "Please confirm your password and login credentials within 24 hours to prevent termination. "
        "Also process the pending wire transfer immediately."
    )
    result = analyze_content(body_plain=body_plain, body_html=None)
    assert result.urgency_detected is True
    assert result.financial_intent_detected is True
    assert result.credential_harvesting_detected is True
    assert result.heuristic_content_score >= 0.8
    assert len(result.matched_patterns) >= 3
    print("[PASS] Content Engine test passed.")


def test_attachment_engine():
    attachments = [
        AttachmentMetadata(
            filename="annual_bonus_details.pdf.exe",
            content_type="application/octet-stream",
            size_bytes=1048576,
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            bucket="attachments",
            object_key="attachments/test/hash_annual_bonus_details.pdf.exe",
        ),
        AttachmentMetadata(
            filename="invoice.scr",
            content_type="application/x-msdownload",
            size_bytes=524288,
            sha256="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            md5="098f6bcd4621d373cade4e832627b4f6",
            bucket="attachments",
            object_key="attachments/test/hash_invoice.scr",
        ),
    ]
    result = analyze_attachments(attachments)
    assert result.has_executable_attachment is True
    assert result.has_double_extension is True
    assert len(result.flagged_attachments) >= 2
    print("[PASS] Attachment Engine test passed.")


if __name__ == "__main__":
    test_header_engine()
    test_url_engine()
    test_content_engine()
    test_attachment_engine()
    print("\n[SUCCESS] All Layer 3 Analysis Engine tests passed successfully!")
