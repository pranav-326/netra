"""URL & Domain Analysis Engine (Layer 3)
Extracts root domains, computes Levenshtein distance against high-value target brands
to flag typosquatting, and identifies suspicious URL structures (IP hosts, defanged, punycode).
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import List, Set, Optional, Tuple

from netra_common.models.email import UrlAnalysisResult, DetectedTyposquat

# Hardcoded high-value target brand domains frequently targeted in phishing
HIGH_VALUE_TARGETS = [
    "microsoft.com",
    "google.com",
    "paypal.com",
    "apple.com",
    "amazon.com",
    "netflix.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "dropbox.com",
    "office.com",
    "adobe.com",
    "dhl.com",
    "fedex.com",
    "facebook.com",
    "instagram.com",
]

IP_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute classic Levenshtein distance between two strings."""
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
    """Normalize defanged URL characters (hxxp -> http, [.] -> .)."""
    norm = re.sub(r"^hxxps?", lambda m: "https" if "s" in m.group(0).lower() else "http", url, flags=re.IGNORECASE)
    norm = norm.replace("[.]", ".").replace("(:)", ":").replace("[/]", "/")
    if not norm.startswith(("http://", "https://", "ftp://")):
        norm = "http://" + norm
    return norm


def extract_root_domain(hostname: str) -> str:
    """Extract root domain (e.g., login.sub.example.com -> example.com)."""
    if not hostname:
        return ""
    parts = hostname.lower().strip().split(".")
    if len(parts) >= 2:
        # Check two-part TLDs (e.g. .co.uk, .com.au)
        two_part_tlds = {"co.uk", "gov.uk", "ac.uk", "com.au", "net.au", "co.in", "net.in", "org.in", "co.nz"}
        if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in two_part_tlds:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return hostname.lower()


def analyze_urls(urls: List[str]) -> UrlAnalysisResult:
    """Analyze extracted URLs for typosquatting, bare IP addresses, and evasion tactics."""
    if not urls:
        return UrlAnalysisResult()

    root_domains: Set[str] = set()
    typosquats: List[DetectedTyposquat] = []
    ip_host_urls: List[str] = []
    defanged_urls: List[str] = []
    suspicious_flags: List[str] = []

    seen_typosquat_keys = set()

    for raw_url in urls:
        # Check if originally defanged
        if "hxxp" in raw_url.lower() or "[.]" in raw_url:
            defanged_urls.append(raw_url)

        normalized_url = normalize_defanged_url(raw_url)

        try:
            parsed = urlparse(normalized_url)
            hostname = parsed.hostname or ""
        except Exception:
            hostname = ""

        if not hostname:
            continue

        # 1. Bare IP address check
        if IP_PATTERN.match(hostname):
            ip_host_urls.append(raw_url)
            suspicious_flags.append(f"URL uses bare IP host instead of domain: {raw_url}")
            continue

        # 2. Punycode check (homograph attack)
        if "xn--" in hostname.lower():
            suspicious_flags.append(f"Punycode / IDN homograph domain detected: {hostname}")

        root_domain = extract_root_domain(hostname)
        if root_domain:
            root_domains.add(root_domain)

        # 3. Typosquatting / Brand Impersonation Checks
        for target in HIGH_VALUE_TARGETS:
            target_brand_name = target.split(".")[0]

            # Direct match - legit domain, skip typosquat check
            if root_domain == target:
                continue

            # Subdomain spoofing (e.g. paypal.com.evil-portal.net or paypal-login.net)
            if target_brand_name in hostname.lower() and root_domain != target:
                key = (root_domain, target)
                if key not in seen_typosquat_keys:
                    seen_typosquat_keys.add(key)
                    suspicious_flags.append(
                        f"Brand name '{target_brand_name}' embedded in suspicious domain '{hostname}'"
                    )
                    typosquats.append(
                        DetectedTyposquat(
                            extracted_domain=root_domain,
                            target_brand=target,
                            distance=1,
                            similarity_ratio=0.9,
                        )
                    )
                continue

            # Levenshtein distance check on root domain (e.g., paypa1.com vs paypal.com)
            # Only compare if domain lengths are reasonably close
            if abs(len(root_domain) - len(target)) <= 3:
                dist = levenshtein_distance(root_domain, target)
                max_len = max(len(root_domain), len(target))
                ratio = 1.0 - (dist / max_len)

                # Flag if edit distance is 1 or 2 with high similarity
                if 1 <= dist <= 2 and ratio >= 0.75:
                    key = (root_domain, target)
                    if key not in seen_typosquat_keys:
                        seen_typosquat_keys.add(key)
                        typosquats.append(
                            DetectedTyposquat(
                                extracted_domain=root_domain,
                                target_brand=target,
                                distance=dist,
                                similarity_ratio=round(ratio, 3),
                            )
                        )
                        suspicious_flags.append(
                            f"Typosquatting detected: '{root_domain}' mimics high-value target '{target}' (edit distance: {dist})"
                        )

        # 4. Excessive subdomains check (e.g. a.b.c.d.e.example.com)
        subdomains = hostname.split(".")
        if len(subdomains) > 4:
            suspicious_flags.append(f"Excessive subdomain depth ({len(subdomains)} levels) in: {hostname}")

    return UrlAnalysisResult(
        total_urls_inspected=len(urls),
        root_domains=sorted(list(root_domains)),
        typosquat_detections=typosquats,
        ip_host_urls=ip_host_urls,
        defanged_urls=defanged_urls,
        suspicious_url_flags=suspicious_flags,
    )
