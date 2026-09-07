"""Direct algorithmic tests for Layer 3 security heuristic logic without external dependencies."""

import os
import re

# 1. Levenshtein Distance & Domain Normalization
def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def normalize_defanged_url(url: str) -> str:
    norm = re.sub(r"^hxxps?", lambda m: "https" if "s" in m.group(0).lower() else "http", url, flags=re.IGNORECASE)
    norm = norm.replace("[.]", ".").replace("(:)", ":").replace("[/]", "/")
    if not norm.startswith(("http://", "https://", "ftp://")):
        norm = "http://" + norm
    return norm

def extract_root_domain(hostname: str) -> str:
    if not hostname:
        return ""
    parts = hostname.lower().strip().split(".")
    if len(parts) >= 2:
        two_part_tlds = {"co.uk", "gov.uk", "ac.uk", "com.au", "net.au", "co.in", "net.in", "org.in", "co.nz"}
        if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in two_part_tlds:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return hostname.lower()

# 2. Header parsing regex
SPF_PATTERN = re.compile(r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.IGNORECASE)
DKIM_PATTERN = re.compile(r"\bdkim=(pass|fail|neutral|none|temperror|permerror)\b", re.IGNORECASE)
DMARC_PATTERN = re.compile(r"\bdmarc=(pass|fail|none|temperror|permerror|bestguesspass)\b", re.IGNORECASE)

# 3. Content Heuristics
URGENCY_PATTERN = re.compile(r"\b(?:urgent|immediate)\s+(?:action|attention|response)\s+(?:required|needed)\b", re.I)
WIRE_PATTERN = re.compile(r"\bwire\s+transfer\b", re.I)
CREDENTIAL_PATTERN = re.compile(r"\b(?:login|account)\s+credentials\b", re.I)

# 4. Attachment Security
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".js", ".bat", ".cmd", ".ps1", ".iso", ".hta", ".wsf", ".jar", ".msi", ".docm", ".xlsm"
}
DOUBLE_EXTENSION_PATTERN = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|zip|tar|gz)\.(?:exe|scr|vbs|js|bat|cmd|ps1|hta|iso|jar|msi|cpl)$",
    re.IGNORECASE
)


def run_all_tests():
    # URL / Typosquatting verification
    assert levenshtein_distance("micros0ft.com", "microsoft.com") == 1
    assert levenshtein_distance("paypa1.com", "paypal.com") == 1
    assert levenshtein_distance("google.com", "g00gle.com") == 2
    assert normalize_defanged_url("hxxps://evil-phish[.]com/login") == "https://evil-phish.com/login"
    assert extract_root_domain("login.account.microsoft.com") == "microsoft.com"
    assert extract_root_domain("secure.banking.co.uk") == "banking.co.uk"
    print("[PASS] URL & Typosquatting heuristics passed.")

    # Header parsing verification
    auth_sample = "mx.google.com; dkim=pass; spf=fail (domain does not authorize IP); dmarc=fail"
    spf_match = SPF_PATTERN.search(auth_sample)
    dkim_match = DKIM_PATTERN.search(auth_sample)
    dmarc_match = DMARC_PATTERN.search(auth_sample)
    assert spf_match and spf_match.group(1).lower() == "fail"
    assert dkim_match and dkim_match.group(1).lower() == "pass"
    assert dmarc_match and dmarc_match.group(1).lower() == "fail"
    print("[PASS] Header RFC 8601 regex parsing passed.")

    # Content heuristic verification
    text = "URGENT: Immediate action required! A wire transfer has been requested. Verify your login credentials."
    assert URGENCY_PATTERN.search(text) is not None
    assert WIRE_PATTERN.search(text) is not None
    assert CREDENTIAL_PATTERN.search(text) is not None
    print("[PASS] BEC and phishing content heuristics passed.")

    # Attachment verification
    assert ".exe" in DANGEROUS_EXTENSIONS
    assert ".scr" in DANGEROUS_EXTENSIONS
    assert DOUBLE_EXTENSION_PATTERN.search("bonus_report.pdf.exe") is not None
    assert DOUBLE_EXTENSION_PATTERN.search("clean_invoice.pdf") is None
    print("[PASS] Attachment extension security heuristics passed.")

    print("\n>>> ALL LAYER 3 ALGORITHMIC HEURISTICS VERIFIED CLEANLY <<<")


if __name__ == "__main__":
    run_all_tests()
