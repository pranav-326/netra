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


# Modern lures, found by reading 2024 phishing (Nazario corpus). Recorded separately from
# the patterns above so the learned model's inputs do not shift. Each lure type is one
# scoring rule; points are set in scorer.py by how often legitimate mail says the same.
LURE_PATTERNS: Dict[str, List[re.Pattern]] = {
    # "Item shared with you: Invoice.pdf", "Complete with DocuSign", "Signature Required"
    "document_share": [
        re.compile(r"\b(?:item|file|folder|document|pdf)s?\s+(?:has\s+been\s+|have\s+been\s+|was\s+)?shared\s+with\s+you\b", re.I),
        re.compile(r"\bshared\s+(?:a|an|the|some)?\s*(?:internal\s+)?(?:file|folder|document|item|pdf|spreadsheet)s?\s+with\s+you\b", re.I),
        re.compile(r"\b(?:e-?)?signature\s+(?:is\s+)?(?:required|requested|needed|pending)\b", re.I),
        re.compile(r"\b(?:review\s+and\s+sign|complete\s+with\s+docu\s*sign|please\s+docu\s*sign)\b", re.I),
        re.compile(r"\b(?:document|doc|docs|file)s?\s+via[\s\-]+(?:docu[\s\-]*sign|e[\s\-]*sign|sign|wetransfer|onedrive|sharepoint|dropbox)\b", re.I),
        re.compile(r"\byou\s+(?:have\s+)?received\s+(?:a\s+|an\s+|some\s+|new\s+)*(?:secure\s+)?(?:files?|documents?|e-?fax|fax|e-?file|voice\s*mail|voice\s+message)\b", re.I),
        re.compile(r"\bscanned\s+(?:docu\w*|document|file|copy|invoice)\b", re.I),
    ],
    # "password expire today", "You have [7] Pending Mails", "mailbox is full"
    "mailbox_admin": [
        re.compile(r"\bpassword\s+(?:will\s+|is\s+about\s+to\s+|is\s+going\s+to\s+)?expir(?:e|es|ed|ing|ation)\b", re.I),
        re.compile(r"\b(?:keep|retain|maintain)\s+(?:your\s+|the\s+)?(?:same|current|old|existing)\s+password\b", re.I),
        re.compile(r"\b(?:retain|re-?validate|validate)\s+(?:your\s+)?(?:e-?mail\s+)?credentials\b", re.I),
        re.compile(r"\b(?:mailbox|mail\s*box|e-?mail\s+(?:account|box)|inbox)\s+(?:is\s+|has\s+|will\s+be\s+)?(?:almost\s+|nearly\s+)?(?:full|over\s*(?:quota|limit)|quota|storage\s+(?:full|limit)|deactivat\w*|suspend\w*|terminat\w*|disabled|requires?\s+(?:an?\s+)?(?:update|upgrade|verification))\b", re.I),
        re.compile(r"\b(?:pending|blocked|held|queued|suspended)\s+(?:e-?mails?|mails?|messages?|massages?)\b", re.I),
        # "Incoming mail" alone is ordinary mail-server talk; the lure counts or blocks it.
        re.compile(r"(?:\(\d+\)|\[\d+\]|\b\d+)\s+(?:new\s+)?incoming\s+(?:e-?mails?|mails?|messages?|massages?)\b"
                   r"|\bincoming\s+(?:e-?mails?|mails?|messages?|massages?)\s+(?:failed|blocked|pending|on\s+hold|held|suspended|could\s+not)\b", re.I),
        re.compile(r"\bfailed\s+(?:e-?mail\s+)?deliveries\b|\be-?mail\s+delivery\s+(?:report|failure\s+notification)\b", re.I),
        # Naming the webmail software alone is ordinary; the lure speaks as its administrator.
        re.compile(r"\b(?:cpanel|webmail|roundcube|zimbra|squirrelmail|outlook\s+web\s+(?:app|access))\s+"
                   r"(?:admin\w*|account|team|support|upgrade|update|quota|user|notification|security)\b", re.I),
        re.compile(r"\b(?:e-?mail|account)\s+(?:account\s+)?(?:requires?|needs?)\s+(?:an?\s+)?(?:update|upgrade|verification|validation)\b", re.I),
    ],
    # "Sorry we missed you! Schedule your next delivery", "customs fee"
    "parcel_delivery": [
        re.compile(r"\b(?:sorry\s+we\s+missed\s+you|missed\s+(?:your\s+)?delivery|delivery\s+attempt|unable\s+to\s+deliver"
                   r"|could\s*n[o']?t\s+(?:be\s+)?deliver(?:ed)?|redeliver\w*|schedule\s+(?:your\s+)?(?:next\s+|a\s+new\s+)?delivery"
                   r"|shipment\s+(?:is\s+)?(?:on\s+hold|suspended|notification)|customs\s+(?:fee|duty|charges?|clearance)"
                   r"|(?:package|parcel)\s+(?:is\s+)?(?:on\s+hold|pending|waiting|held))\b", re.I),
    ],
    # "Your Prime membership is renewing", "Extend your SiriusXM membership"
    "subscription_renewal": [
        re.compile(r"\b(?:membership|subscription)\s+(?:(?:is|has|was|will\s+be)\s+)?(?:auto-?renew\w*|renew\w*|expir\w*|cancel\w*|suspend\w*|ended|statement|extension)\b", re.I),
        re.compile(r"\b(?:renew|extend)\s+your\s+(?:\w+\s+){0,3}(?:membership|subscription)\b", re.I),
    ],
    # "You've received a B T C coin", "wallet validation", "recovery phrase"
    "crypto": [
        re.compile(r"\b(?:bitcoin|b\s?t\s?c|usdt|ethereum|cryptocurrency|seed\s+phrase|recovery\s+phrase|secret\s+phrase"
                   r"|wallet\s+(?:verification|validation|suspended|synchroni[sz]ation|connect\w*))\b", re.I),
    ],
}

# Callback ("telephone-oriented") scams: a fake invoice or renewal from a known brand,
# with a phone number to call instead of a link. All three together form the lure.
CALLBACK_BRAND = re.compile(
    r"\b(?:geek\W{0,3}squad|norton|mcafee|paypal|best\s*buy|amazon|coinbase|windows\s+defender|avast|pc\s*matic)\b", re.I)
PHONE_NUMBER = re.compile(r"(?<![\w])(?:\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]\d{3}[\s\-.]\d{4}(?![\w])")
MONEY_WORDS = re.compile(
    r"\b(?:payment|paid|charged|charge|renew\w*|subscription|order|invoice|refund|cancel\w*|debited|transaction|purchase)\b", re.I)


def find_lures(text: str) -> Dict[str, str]:
    """Lure type -> the first text that matched it."""
    found: Dict[str, str] = {}
    for lure, patterns in LURE_PATTERNS.items():
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                found[lure] = match.group(0)
                break
    brand, phone = CALLBACK_BRAND.search(text), PHONE_NUMBER.search(text)
    if brand and phone and MONEY_WORDS.search(text):
        found["callback_scam"] = f"{brand.group(0)} … call {phone.group(0).strip()}"
    return found


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
        lure_matches=find_lures(full_text),
    )
