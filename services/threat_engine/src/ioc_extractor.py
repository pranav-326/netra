"""IOC Extraction Engine (Layer 4)
Consolidates Indicators of Compromise (IOCs) from parsed email headers, bodies,
URLs, Received hop chains, and attachment cryptographic hashes for Layer 5 threat intelligence.
"""

import re
import ipaddress
from typing import List, Set, Tuple
from netra_common.models.email import ParsedEmail, AnalysisResults, IOCItem

IPV4_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


def extract_ips_from_received_chain(received_chain: List[str]) -> List[str]:
    """Extract public/routable IP addresses from Received header hops."""
    found_ips: Set[str] = set()
    for hop in received_chain:
        matches = IPV4_PATTERN.findall(hop)
        for ip_str in matches:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                # Ignore loopback and standard private non-routable IPs (127.0.0.1, 0.0.0.0)
                if not ip_obj.is_loopback and not ip_obj.is_unspecified:
                    found_ips.add(ip_str)
            except ValueError:
                continue
    return sorted(list(found_ips))


def extract_consolidated_iocs(parsed_email: ParsedEmail, analysis: AnalysisResults) -> List[IOCItem]:
    """Aggregate all IOCs across email headers, URLs, attachments, and routing chains."""
    iocs: List[IOCItem] = []
    seen: Set[Tuple[str, str]] = set()

    def add_ioc(ioc_type: str, value: str, context: str):
        val = value.strip()
        if not val:
            return
        key = (ioc_type.lower(), val.lower())
        if key not in seen:
            seen.add(key)
            iocs.append(IOCItem(type=ioc_type, value=val, context=context))

    # 1. Sender Email & Domain
    from_addr = parsed_email.headers.from_address
    if from_addr:
        # Extract bare email if in 'Name <email@domain.com>' format
        email_match = re.search(r"[\w\.-]+@[\w\.-]+", from_addr)
        if email_match:
            sender_email = email_match.group(0)
            add_ioc("email_address", sender_email, "Sender RFC 5322 From Address")
            if "@" in sender_email:
                sender_domain = sender_email.split("@")[1]
                add_ioc("domain", sender_domain, "Sender Domain")

    # 2. URLs & Root Domains
    for url in parsed_email.extracted_urls:
        add_ioc("url", url, "Extracted link from email body")

    for root_domain in analysis.url_analysis.root_domains:
        add_ioc("domain", root_domain, "Extracted link root domain")

    # 3. Hop IP Addresses from Received Chain & URL bare IPs
    chain_ips = extract_ips_from_received_chain(parsed_email.headers.received_chain)
    for ip in chain_ips:
        add_ioc("ip", ip, "Hop IP extracted from Received transport header chain")

    for ip_url in analysis.url_analysis.ip_host_urls:
        ip_match = IPV4_PATTERN.search(ip_url)
        if ip_match:
            add_ioc("ip", ip_match.group(0), "Bare IP address used as URL host")

    # 4. Attachment Hashes
    for att in parsed_email.attachments:
        if att.sha256:
            add_ioc("sha256", att.sha256, f"Attachment SHA-256 hash: {att.filename}")
        if att.md5:
            add_ioc("md5", att.md5, f"Attachment MD5 hash: {att.filename}")

    return iocs
