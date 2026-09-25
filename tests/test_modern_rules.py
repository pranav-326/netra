"""Tests for the modern brand and lure rules, including the false positives they avoid."""

import pytest

from netra_common.models.email import (
    AnalysisResults,
    AttachmentAnalysisResult,
    AttachmentMetadata,
    ContentAnalysisResult,
    HeaderAnalysisResult,
    UrlAnalysisResult,
)
from services.analyzer.src.engines.attachment_engine import analyze_attachments
from services.analyzer.src.engines.brands import brand_in_display_name
from services.analyzer.src.engines.content_engine import analyze_content, find_lures
from services.analyzer.src.engines.header_engine import sender_brand_impersonation
from services.analyzer.src.engines.url_engine import analyze_urls
from services.threat_engine.src.scorer import evaluate_threat_score


def targets(urls):
    return sorted({d.target_brand for d in analyze_urls(urls, resolver=None).typosquat_detections})


# --- Display-name brand impersonation ---------------------------------------------

@pytest.mark.parametrize("from_header,brand", [
    ("DocuSign <billing@cefilni.com>", "docusign"),
    ("DocuSign via DocuSign <dse@docusign.net>", None),
    ("Geek^^Squad <support@johnmarshallank.info>", "geeksquad"),
    ("Microsoft 365 Admin <no-reply@evil.example>", "microsoft"),
    ("Google Drive <drive-shares-noreply@google.com>", None),
    ("Chase Miller <chase.miller@gmail.com>", None),
    ("Chase Bank Alerts <alerts@secure-chase-verify.com>", "chase"),
    ("Economic Outlook Weekly <news@econ.example>", None),
    ("Priya Raman <priya@acme-corp.example>", None),
])
def test_sender_brand_impersonation(from_header, brand):
    assert sender_brand_impersonation(from_header)[0] == brand


def test_display_name_obfuscation_is_normalised():
    assert brand_in_display_name("D.o.c.u.S.i.g.n") == "docusign"


# --- Typosquatting with whole-word matching -----------------------------------------

def test_brand_word_embedded_in_hostname_is_flagged():
    assert targets(["https://paypal-login.net/auth"]) == ["paypal.com"]
    assert targets(["https://docusign.secure-view.com/doc"]) == ["docusign.com"]


def test_lookalike_brand_word_is_flagged():
    assert "microsoft.com" in targets(["https://micros0ft-portal.com/login"])


def test_brand_inside_an_ordinary_word_is_not_flagged():
    assert targets(["https://purchase.example.com/cart"]) == []
    assert targets(["https://pineapple-farm.com/"]) == []


def test_domains_a_brand_owns_are_not_flagged():
    assert targets([
        "https://na4.docusign.net/Signing",
        "https://lh3.googleusercontent.com/img",
        "https://m.media-amazon.com/images/x.jpg",
        "https://login.microsoftonline.com/common",
    ]) == []


def test_classic_edit_distance_typosquat_still_flagged():
    assert targets(["https://paypa1.com/signin"]) == ["paypal.com"]


# --- Abused hosting ---------------------------------------------------------------

def test_ipfs_and_throwaway_hosting_are_flagged():
    result = analyze_urls([
        "https://ipfs.io/ipfs/bafybeigdyrzt5/login.html",
        "https://gateway.example.net/ipfs/QmXyz/index.html",
        "https://secure-login.pages.dev/",
        "https://www.example.org/about",
    ], resolver=None)
    assert result.abused_hosting_urls == [
        "https://ipfs.io/ipfs/bafybeigdyrzt5/login.html",
        "https://gateway.example.net/ipfs/QmXyz/index.html",
        "https://secure-login.pages.dev/",
    ]


# --- HTML attachments -------------------------------------------------------------

def attachment(filename, content_type):
    return AttachmentMetadata(filename=filename, content_type=content_type, size_bytes=10,
                              sha256="a" * 64, md5="b" * 32, object_key=f"test/{filename}")


def test_html_and_svg_attachments_are_recorded():
    result = analyze_attachments([
        attachment("Remittance.html", "text/html"),
        attachment("logo.svg", "image/svg+xml"),
        attachment("report.pdf", "application/pdf"),
    ])
    assert result.html_attachments == ["Remittance.html", "logo.svg"]
    assert result.flagged_attachments == []


# --- Content lures ----------------------------------------------------------------

@pytest.mark.parametrize("text,lure", [
    ('Item shared with you: "Account Locked.pdf"', "document_share"),
    ("Complete with DocuSign: Contract Agreement.pdf", "document_share"),
    ("Signature Required: Doc Via-Sign #8", "document_share"),
    ("You received some files via WeTransfer", "document_share"),
    ("Your account jose@example.org password expire today", "mailbox_admin"),
    ("You have [7] Pending Mails", "mailbox_admin"),
    ("You Have Received (5) incoming messages", "mailbox_admin"),
    ("(2) massage inbox failed email deliveries", "mailbox_admin"),
    ("Your mailbox is almost full", "mailbox_admin"),
    ("Sorry we missed you! Schedule your next delivery date.", "parcel_delivery"),
    ("Your Prime membership is renewing on April 3", "subscription_renewal"),
    ("You've received a B T C coin on your e-mail", "crypto"),
])
def test_lure_patterns(text, lure):
    assert lure in find_lures(text)


@pytest.mark.parametrize("text", [
    "Configure the incoming mail server in your client settings.",
    "SquirrelMail is a webmail package written in PHP.",
    "Microsoft announced record revenue; press office 425-882-8080 for orders.",
    "Here are the meeting notes from Tuesday.",
])
def test_ordinary_mail_triggers_no_lure(text):
    assert find_lures(text) == {}


def test_callback_scam_needs_brand_phone_and_money():
    full = "Payment Received [PP190208843783] Geek^^Squad +1-813-776-1410 renewal of your plan"
    assert "callback_scam" in find_lures(full)
    assert "callback_scam" not in find_lures("Geek Squad renewal of your plan")
    assert "callback_scam" not in find_lures("Call Geek Squad at +1-813-776-1410")
    assert "callback_scam" not in find_lures("Order #1234567890 payment received")


def test_lures_do_not_change_learned_model_inputs():
    result = analyze_content("Item shared with you", None, "You have [7] Pending Mails")
    assert result.lure_matches
    assert result.matched_patterns == []
    assert result.heuristic_content_score == 0.0


# --- Scoring ----------------------------------------------------------------------

def score(**parts):
    analysis = AnalysisResults(
        header_analysis=parts.get("header", HeaderAnalysisResult(
            spf_verdict="pass", dkim_verdict="pass", dmarc_verdict="pass", has_authentication_results=True)),
        url_analysis=parts.get("url", UrlAnalysisResult()),
        content_analysis=parts.get("content", ContentAnalysisResult()),
        attachment_analysis=parts.get("attachment", AttachmentAnalysisResult()),
    )
    final, _, _, contributions, raw = evaluate_threat_score(analysis)
    return {c.rule_id: c for c in contributions}, raw


def test_brand_spoof_fires_even_when_authentication_passes():
    rules, raw = score(header=HeaderAnalysisResult(
        spf_verdict="pass", dkim_verdict="pass", dmarc_verdict="pass", has_authentication_results=True,
        impersonated_brand="docusign", sender_domain="cefilni.com"))
    assert rules["HDR-BRAND-SPOOF"].points == 25
    assert "docusign" in rules["HDR-BRAND-SPOOF"].evidence and "cefilni.com" in rules["HDR-BRAND-SPOOF"].evidence
    assert raw == 25


def test_each_lure_is_its_own_rule_and_sums_exactly():
    rules, raw = score(content=ContentAnalysisResult(
        lure_matches={"document_share": "Item shared with you", "mailbox_admin": "password expire"}))
    assert rules["CNT-LURE-DOCUMENT"].points == 15
    assert rules["CNT-LURE-MAILBOX"].points == 20
    assert raw == 35


def test_html_attachment_and_abused_host_rules():
    rules, raw = score(
        attachment=AttachmentAnalysisResult(html_attachments=["Invoice.html"]),
        url=UrlAnalysisResult(abused_hosting_urls=["https://ipfs.io/ipfs/x"]),
    )
    assert rules["ATT-HTML"].points == 25 and "Invoice.html" in rules["ATT-HTML"].evidence
    assert rules["URL-ABUSED-HOST"].points == 15
    assert raw == 40
