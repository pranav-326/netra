"""Content & NLP Heuristic Engine (Layer 3)
Fast regex and keyword-based heuristic analyzer scanning plaintext and HTML email bodies
for Business Email Compromise (BEC), urgency coercion, credential harvesting, and financial fraud.
"""

import re
from typing import Optional, List, Dict, Set, Tuple
from netra_common.models.email import ContentAnalysisResult

# Pre-compiled heuristic patterns for high-speed scanning
URGENCY_PATTERNS = [
    (re.compile(r"\b(?:urgent|immediately|immediate|time-sensitive|critical|expedite)\b", re.I), "Urgent / Critical Pressure"),
    (re.compile(r"\b(?:action|attention|response)\s+(?:required|needed|requested)\b", re.I), "Urgent Action Required"),
    (re.compile(r"\baccount\s+(?:suspended|terminated|locked|disabled|interrupted|expire[ds]?)\b", re.I), "Account Suspension Threat"),
    (re.compile(r"\bwithin\s+(?:\d+|twenty[-\s]four|forty[-\s]eight)\s+hours\b", re.I), "Time-Limited Pressure (24-48h)"),
    (re.compile(r"\b(?:processed|paid|settled)\s+today\b", re.I), "Same-Day Settlement Pressure"),
    (re.compile(r"\b(?:unauthorized|suspicious)\s+(?:activity|login|sign-in|access)\b", re.I), "Unauthorized Activity Alert"),
    (re.compile(r"\bfailure\s+to\s+(?:respond|verify|comply|settle)\b", re.I), "Coercion / Penalty Warning"),
    (re.compile(r"\bsecurity\s+(?:alert|warning|breach|notice)\b", re.I), "Generic Security Warning"),
]

FINANCIAL_BEC_PATTERNS = [
    (re.compile(r"\b(?:wire\s+transfer|electronic\s+transfer|remittance|bank\s+transfer)\b", re.I), "Wire Transfer Request"),
    (re.compile(r"\b(?:payroll|direct\s+deposit)\b", re.I), "Payroll / Direct Deposit Modification"),
    (re.compile(r"\b(?:gift\s+cards?|itunes\s+card|steam\s+card|apple\s+gift)\b", re.I), "Gift Card Solicitations"),
    (re.compile(r"\b(?:invoice|payment|settlement|balance)\s+(?:overdue|unpaid|outstanding|due)\b", re.I), "Overdue Invoice Bait"),
    (re.compile(r"\b(?:overdue|unpaid|outstanding)\s+(?:invoice|payment|settlement|balance)\b", re.I), "Overdue Invoice Bait"),
    (re.compile(r"\b(?:new\s+bank|updated\s+banking|banking?\s+details?|bank\s+account)\b", re.I), "Bank Account Update Request"),
    (re.compile(r"\b(?:account|banking?|payment)\s+details\s+(?:have\s+been\s+)?updated\b", re.I), "Updated Bank Account Details"),
    (re.compile(r"\b(?:swift|iban|routing\s+number|beneficiary(?:\s+account)?)\b", re.I), "Bank Routing / Wire Information"),
    (re.compile(r"\bremittance\s+(?:advice|payment)\b", re.I), "Remittance Bait"),
    (re.compile(r"\bvendor\s+(?:payment|invoice)\b", re.I), "Vendor Payment Fraud"),
    (re.compile(r"\bconfidential\s+wire\b", re.I), "Confidential Wire Transfer"),
]

CREDENTIAL_HARVESTING_PATTERNS = [
    (re.compile(r"\b(?:login|account|corporate)\s+credentials\b", re.I), "Credential Reference"),
    (re.compile(r"\bverify\s+(?:your\s+)?(?:account|identity|details|email|credentials)\b", re.I), "Account Verification Prompt"),
    (re.compile(r"\b(?:reset|confirm|update|change)\s+(?:your\s+)?password\b", re.I), "Password Reset Bait"),
    (re.compile(r"\bpassword\s+(?:has\s+)?expired\b", re.I), "Password Expiration Alert"),
    (re.compile(r"\bclick\s+(?:here|the\s+link)\s+to\s+(?:log\s*in|verify|unlock|review)\b", re.I), "Click to Login Link Trap"),
    (re.compile(r"\bupdate\s+(?:your\s+)?billing\s+(?:information|details)\b", re.I), "Billing Update Harvesting"),
    (re.compile(r"\b(?:sso\s+login|office\s*365|microsoft\s*365)\b", re.I), "Branded SSO Lure"),
]


def strip_html_tags(html_content: str) -> str:
    """Basic HTML tag cleaner to extract readable text tokens."""
    if not html_content:
        return ""
    # Remove script and style tags completely
    clean = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html_content, flags=re.DOTALL | re.I)
    # Remove all HTML tags
    clean = re.sub(r"<[^>]+>", " ", clean)
    # Normalize whitespaces
    return " ".join(clean.split())


def analyze_content(
    body_plain: Optional[str],
    body_html: Optional[str],
    subject: Optional[str] = None
) -> ContentAnalysisResult:
    """Execute heuristic content analysis on email bodies and subject."""
    # Combine subject, normalized plaintext and stripped HTML body
    text_corpus = []
    if subject:
        text_corpus.append(subject)
    if body_plain:
        text_corpus.append(body_plain)
    if body_html:
        text_corpus.append(strip_html_tags(body_html))

    full_text = " ".join(text_corpus)
    if not full_text.strip():
        return ContentAnalysisResult()

    matched_patterns: Set[str] = set()
    matched_keywords: Set[str] = set()

    # 1. Check Urgency Patterns
    urgency_detected = False
    for pattern, label in URGENCY_PATTERNS:
        match = pattern.search(full_text)
        if match:
            urgency_detected = True
            matched_patterns.add(f"URGENCY: {label}")
            matched_keywords.add(match.group(0))

    # 2. Check Financial / BEC Patterns
    financial_detected = False
    for pattern, label in FINANCIAL_BEC_PATTERNS:
        match = pattern.search(full_text)
        if match:
            financial_detected = True
            matched_patterns.add(f"BEC_FINANCIAL: {label}")
            matched_keywords.add(match.group(0))

    # 3. Check Credential Harvesting Patterns
    credential_detected = False
    for pattern, label in CREDENTIAL_HARVESTING_PATTERNS:
        match = pattern.search(full_text)
        if match:
            credential_detected = True
            matched_patterns.add(f"CREDENTIAL: {label}")
            matched_keywords.add(match.group(0))

    # Compute heuristic threat score (0.0 to 1.0)
    score = 0.0
    if urgency_detected:
        score += 0.3
    if financial_detected:
        score += 0.4
    if credential_detected:
        score += 0.4

    # Compound multi-category indicator penalty (e.g. urgency + credential = classic phishing)
    if urgency_detected and (financial_detected or credential_detected):
        score += 0.2

    # Cap score at 1.0
    final_score = min(round(score, 2), 1.0)

    return ContentAnalysisResult(
        urgency_detected=urgency_detected,
        financial_intent_detected=financial_detected,
        credential_harvesting_detected=credential_detected,
        matched_patterns=sorted(list(matched_patterns)),
        matched_keywords=sorted(list(matched_keywords)),
        heuristic_content_score=final_score,
    )
