"""URL & Domain Analysis Engine (Layer 3)
Extracts root domains, computes Levenshtein distance against high-value target brands
to flag typosquatting, and identifies suspicious URL structures (IP hosts, defanged, punycode).
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import List, Set, Optional, Tuple

from netra_common.models.email import UrlAnalysisResult, DetectedTyposquat, ShortenedUrl

from .brands import (
    ALL_LEGITIMATE_DOMAINS,
    FUZZY_BRAND_TOKENS,
    HOSTNAME_BRAND_TOKENS,
    TYPOSQUAT_TARGETS,
    hostname_tokens,
)
from .shortener import DEFAULT_RESOLVER, ShortenerResolver, is_shortener

# Free, anonymous hosting where phishing pages are routinely published: IPFS gateways
# and throwaway app-hosting domains. Legitimate business mail rarely links to these.
ABUSED_HOSTING_SUFFIXES = (
    "ipfs.io", "cloudflare-ipfs.com", "dweb.link", "w3s.link", "nftstorage.link", "pinata.cloud",
    "r2.dev", "workers.dev", "pages.dev", "web.app", "firebaseapp.com", "glitch.me",
    "ngrok.io", "ngrok-free.app", "trycloudflare.com",
)

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


def analyze_urls(
    urls: List[str], resolver: Optional[ShortenerResolver] = DEFAULT_RESOLVER
) -> UrlAnalysisResult:
    """Analyze extracted URLs for typosquatting, bare IP addresses, and evasion tactics.

    Short links are resolved through `resolver` and their destinations are analysed
    like any other link. Pass `resolver=None` to skip network resolution entirely.
    """
    if not urls:
        return UrlAnalysisResult()

    root_domains: Set[str] = set()
    typosquats: List[DetectedTyposquat] = []
    ip_host_urls: List[str] = []
    defanged_urls: List[str] = []
    suspicious_flags: List[str] = []
    shortened: List[ShortenedUrl] = []
    abused_hosting: List[str] = []

    seen_typosquat_keys = set()

    # Resolved destinations are appended while iterating, so they run through the
    # same checks below as the links that were in the email.
    work_list = list(urls)
    for raw_url in work_list:
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

        # 0. Link shortener: find the real destination and queue it for analysis.
        if resolver is not None and is_shortener(hostname):
            root_domains.add(extract_root_domain(hostname))
            resolution = resolver.resolve(normalized_url)
            resolution.original_url = raw_url
            shortened.append(resolution)
            if resolution.final_url:
                work_list.append(resolution.final_url)
            continue

        # Phishing pages hosted where anyone can publish anonymously for free.
        if _is_abused_hosting(hostname, normalized_url):
            abused_hosting.append(raw_url)

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

        # 3. Typosquatting / brand impersonation. A domain a brand legitimately owns is
        #    never flagged as imitating any brand.
        if root_domain and root_domain not in ALL_LEGITIMATE_DOMAINS:
            for target, dist, ratio, flag in _brand_impersonations(hostname, root_domain):
                key = (root_domain, target)
                if key in seen_typosquat_keys:
                    continue
                seen_typosquat_keys.add(key)
                suspicious_flags.append(flag)
                typosquats.append(
                    DetectedTyposquat(
                        extracted_domain=root_domain,
                        target_brand=target,
                        distance=dist,
                        similarity_ratio=round(ratio, 3),
                    )
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
        shortened_urls=shortened,
        abused_hosting_urls=abused_hosting,
    )


def _brand_impersonations(hostname: str, root_domain: str) -> List[Tuple[str, int, float, str]]:
    """(target domain, edit distance, similarity, flag text) for every brand imitated."""
    hits = []
    for token in hostname_tokens(hostname):
        # Brand word as its own label or hyphenated part: paypal-login.net, docusign.secure.net
        target = HOSTNAME_BRAND_TOKENS.get(token)
        if target:
            hits.append((target, 1, 0.9, f"Brand name '{token}' embedded in suspicious domain '{hostname}'"))
            continue
        # One character off a long brand word: micros0ft-portal.com, dropb0x-share.net
        for brand_token, brand_target in FUZZY_BRAND_TOKENS.items():
            if abs(len(token) - len(brand_token)) <= 1 and levenshtein_distance(token, brand_token) == 1:
                hits.append((brand_target, 1, 1 - 1 / len(brand_token),
                             f"Lookalike of brand '{brand_token}' ('{token}') in domain '{hostname}'"))

    # Whole-domain edit distance: paypa1.com vs paypal.com
    for _, target in TYPOSQUAT_TARGETS:
        if abs(len(root_domain) - len(target)) > 3:
            continue
        dist = levenshtein_distance(root_domain, target)
        ratio = 1.0 - dist / max(len(root_domain), len(target))
        if 1 <= dist <= 2 and ratio >= 0.75:
            hits.append((target, dist, ratio,
                         f"Typosquatting detected: '{root_domain}' mimics high-value target '{target}' (edit distance: {dist})"))
    return hits


def _is_abused_hosting(hostname: str, url: str) -> bool:
    host = hostname.lower()
    if any(host == s or host.endswith("." + s) for s in ABUSED_HOSTING_SUFFIXES):
        return True
    # IPFS content served through any gateway: https://gateway.example/ipfs/<cid>
    return "/ipfs/" in url.lower() or ".ipfs." in host
