"""Header & Protocol Analysis Engine (Layer 3)
Evaluates Authentication-Results, Received-SPF, and related headers to extract
and validate SPF, DKIM, and DMARC verdicts, identifying anomalies or spoofing indicators.
"""

import re
import logging
from typing import List, Dict, Any, Tuple
from netra_common.models.email import EmailHeaders, HeaderAnalysisResult

logger = logging.getLogger("netra.analyzer.header")

# RFC 8601 Authentication-Results regex patterns
SPF_PATTERN = re.compile(r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.IGNORECASE)
DKIM_PATTERN = re.compile(r"\bdkim=(pass|fail|neutral|none|temperror|permerror)\b", re.IGNORECASE)
DMARC_PATTERN = re.compile(r"\bdmarc=(pass|fail|none|temperror|permerror|bestguesspass)\b", re.IGNORECASE)
RECEIVED_SPF_PATTERN = re.compile(r"^(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.IGNORECASE)


def parse_auth_results(auth_headers: List[str]) -> Tuple[str, str, str]:
    """Extract SPF, DKIM, and DMARC verdicts from Authentication-Results headers."""
    spf_verdict = "missing"
    dkim_verdict = "missing"
    dmarc_verdict = "missing"

    for header in auth_headers:
        if not isinstance(header, str):
            continue

        spf_match = SPF_PATTERN.search(header)
        if spf_match and spf_verdict == "missing":
            spf_verdict = spf_match.group(1).lower()

        dkim_match = DKIM_PATTERN.search(header)
        if dkim_match and dkim_verdict == "missing":
            dkim_verdict = dkim_match.group(1).lower()

        dmarc_match = DMARC_PATTERN.search(header)
        if dmarc_match and dmarc_verdict == "missing":
            dmarc_verdict = dmarc_match.group(1).lower()

    return spf_verdict, dkim_verdict, dmarc_verdict


def analyze_headers(headers: EmailHeaders) -> HeaderAnalysisResult:
    """Analyze email authentication and protocol headers."""
    raw_headers = headers.raw_headers or {}

    # Gather Authentication-Results headers (case-insensitive search)
    auth_results_raw = []
    received_spf_raw = []

    for key, val in raw_headers.items():
        key_lower = key.lower()
        if key_lower in ("authentication-results", "arc-authentication-results"):
            if isinstance(val, list):
                auth_results_raw.extend(val)
            else:
                auth_results_raw.append(str(val))
        elif key_lower == "received-spf":
            if isinstance(val, list):
                received_spf_raw.extend(val)
            else:
                received_spf_raw.append(str(val))

    has_auth_results = len(auth_results_raw) > 0
    spf_verdict, dkim_verdict, dmarc_verdict = parse_auth_results(auth_results_raw)

    # Fallback to Received-SPF if not found in Authentication-Results
    if spf_verdict == "missing" and received_spf_raw:
        for rspf in received_spf_raw:
            match = RECEIVED_SPF_PATTERN.search(rspf.strip())
            if match:
                spf_verdict = match.group(1).lower()
                break

    # Identify anomalies
    anomalies: List[str] = []

    if not has_auth_results and not received_spf_raw:
        anomalies.append("No Authentication-Results or Received-SPF headers present; email may be spoofed or unauthenticated")

    if spf_verdict == "fail":
        anomalies.append("SPF check failed: Sender IP is not authorized by sending domain policy")
    elif spf_verdict == "softfail":
        anomalies.append("SPF softfail: Sender IP is discouraged by sending domain policy")
    elif spf_verdict in ("none", "missing"):
        anomalies.append("SPF record is missing or not evaluated")

    if dkim_verdict == "fail":
        anomalies.append("DKIM check failed: Cryptographic email signature verification failed or was tampered")
    elif dkim_verdict in ("none", "missing"):
        anomalies.append("DKIM signature is missing or not evaluated")

    if dmarc_verdict == "fail":
        anomalies.append("DMARC alignment check failed: Domain policy rejected sender alignment")
    elif dmarc_verdict in ("none", "missing"):
        anomalies.append("DMARC policy record is missing or not evaluated")

    # Flag missing message-id or date anomalies
    if not headers.message_id:
        anomalies.append("Missing standard RFC 5322 Message-ID header")
    if not headers.from_address:
        anomalies.append("Missing standard RFC 5322 From address header")

    return HeaderAnalysisResult(
        spf_verdict=spf_verdict,
        dkim_verdict=dkim_verdict,
        dmarc_verdict=dmarc_verdict,
        has_authentication_results=has_auth_results,
        auth_anomalies=anomalies,
    )
