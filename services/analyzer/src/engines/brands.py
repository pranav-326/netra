"""Brands phishing impersonates, and the domains each brand legitimately uses (Layer 3).

One registry shared by the URL engine (typosquatting) and the header engine
(display-name impersonation), so "which domains really belong to DocuSign" is answered
in exactly one place. A domain listed here is never flagged as impersonating its own
brand: DocuSign's real notifications come from docusign.net, Google's from google.com.
"""

import re
from typing import Dict, FrozenSet, List, Optional, Tuple

# brand key -> (display-name phrases, legitimate root domains, typosquat targets)
#
# Typosquat targets must be long enough that an edit distance of 1–2 does not land on
# an unrelated real company: "ups.com" is one edit from "ubs.com", so short domains
# appear only as legitimate domains, never as targets.
_REGISTRY: Dict[str, Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]] = {
    # "Outlook" alone is also an ordinary newsletter word, so it is not a display phrase.
    "microsoft": (("microsoft", "office 365", "office365", "microsoft 365", "microsoft outlook", "onedrive",
                   "sharepoint"),
                  ("microsoft.com", "office.com", "office365.com", "outlook.com", "live.com", "microsoftonline.com",
                   "sharepoint.com", "onedrive.com", "hotmail.com", "azure.com"),
                  ("microsoft.com", "office.com", "outlook.com", "sharepoint.com")),
    "google": (("google", "gmail", "google drive", "google docs"),
               ("google.com", "gmail.com", "googlemail.com", "youtube.com", "google-analytics.com",
                "googleusercontent.com", "googleapis.com", "gstatic.com", "googletagmanager.com"),
               ("google.com",)),
    "docusign": (("docusign", "docu sign"), ("docusign.com", "docusign.net"), ("docusign.com", "docusign.net")),
    "wetransfer": (("wetransfer",), ("wetransfer.com",), ("wetransfer.com",)),
    "dropbox": (("dropbox",), ("dropbox.com", "dropboxmail.com"), ("dropbox.com",)),
    "adobe": (("adobe", "adobe sign", "acrobat"), ("adobe.com", "adobesign.com", "echosign.com"), ("adobe.com",)),
    "paypal": (("paypal",), ("paypal.com",), ("paypal.com",)),
    "amazon": (("amazon",), ("amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonses.com",
                             "media-amazon.com", "ssl-images-amazon.com", "amazonaws.com"), ("amazon.com",)),
    "apple": (("apple", "icloud", "itunes"), ("apple.com", "icloud.com"), ("apple.com",)),
    "netflix": (("netflix",), ("netflix.com",), ("netflix.com",)),
    "linkedin": (("linkedin",), ("linkedin.com",), ("linkedin.com",)),
    "facebook": (("facebook", "meta", "instagram"), ("facebook.com", "facebookmail.com", "instagram.com", "meta.com"),
                 ("facebook.com", "instagram.com")),
    # "Chase" and "Norton" are also personal names: display names need brand context.
    "chase": (("chase bank", "chase online", "jpmorgan chase", "chase alert"), ("chase.com",), ("chase.com",)),
    "bankofamerica": (("bank of america",), ("bankofamerica.com", "bofa.com"), ("bankofamerica.com",)),
    "wellsfargo": (("wells fargo",), ("wellsfargo.com",), ("wellsfargo.com",)),
    "dhl": (("dhl",), ("dhl.com", "dhl.de"), ("dhl.com",)),
    "fedex": (("fedex",), ("fedex.com",), ("fedex.com",)),
    "ups": (("ups",), ("ups.com",), ()),
    "usps": (("usps", "postal service"), ("usps.com", "usps.gov"), ()),
    "geeksquad": (("geek squad", "geeksquad"), ("geeksquad.com", "bestbuy.com"), ("geeksquad.com",)),
    "norton": (("norton antivirus", "norton security", "norton 360", "nortonlifelock"),
               ("norton.com", "nortonlifelock.com", "gen.com"), ("norton.com",)),
    "mcafee": (("mcafee",), ("mcafee.com",), ("mcafee.com",)),
    "coinbase": (("coinbase",), ("coinbase.com",), ("coinbase.com",)),
    "trustwallet": (("trust wallet", "trustwallet"), ("trustwallet.com",), ("trustwallet.com",)),
    "metamask": (("metamask",), ("metamask.io",), ("metamask.io",)),
    "cpanel": (("cpanel",), ("cpanel.net", "cpanel.com"), ("cpanel.net",)),
}

LEGITIMATE_DOMAINS: Dict[str, FrozenSet[str]] = {k: frozenset(v[1]) for k, v in _REGISTRY.items()}
ALL_LEGITIMATE_DOMAINS: FrozenSet[str] = frozenset(d for domains in LEGITIMATE_DOMAINS.values() for d in domains)

# (brand key, target domain) pairs for edit-distance checks.
TYPOSQUAT_TARGETS: List[Tuple[str, str]] = [(k, t) for k, v in _REGISTRY.items() for t in v[2]]

# Brand words that may appear as a whole label or hyphen-separated part of a hostname
# (paypal-login.net, docusign.secure-view.com), mapped to the domain they imitate.
# Four letters or more, since "dhl" or "ups" collide with ordinary words, and never a
# generic word: "office" appears in plenty of unrelated hostnames.
_GENERIC_WORDS = {"office"}
HOSTNAME_BRAND_TOKENS: Dict[str, str] = {}
for _, _target in TYPOSQUAT_TARGETS:
    _word = _target.split(".")[0]
    if len(_word) >= 4 and _word not in _GENERIC_WORDS:
        HOSTNAME_BRAND_TOKENS.setdefault(_word, _target)  # first listed = the brand's primary domain

# Brand words long enough that a one-character change (micros0ft, dropb0x) is still
# unmistakably that brand. Shorter words have too many innocent near neighbours
# (norton / morton, google / goggle).
FUZZY_BRAND_TOKENS: Dict[str, str] = {t: d for t, d in HOSTNAME_BRAND_TOKENS.items() if len(t) >= 7}

_DISPLAY_PATTERNS = [
    (brand, re.compile(r"(?<![a-z0-9])" + r"\W*".join(map(re.escape, phrase.split())) + r"(?![a-z0-9])", re.I))
    for brand, (phrases, _, _) in _REGISTRY.items()
    for phrase in phrases
]


def brand_in_display_name(display_name: str) -> Optional[str]:
    """The brand a sender's display name claims to be, if any."""
    if not display_name:
        return None
    # Collapse obfuscation such as "Geek^^Squad" or "D.o.c.u.S.i.g.n" before matching.
    normalised = re.sub(r"(?<=\w)[\W_]{1,3}(?=\w)", lambda m: " " if " " in m.group(0) else "", display_name)
    for brand, pattern in _DISPLAY_PATTERNS:
        if pattern.search(display_name) or pattern.search(normalised):
            return brand
    return None


def is_legitimate_for(brand: str, root_domain: str) -> bool:
    return root_domain in LEGITIMATE_DOMAINS.get(brand, frozenset())


def hostname_tokens(hostname: str) -> List[str]:
    return [t for t in re.split(r"[.\-]", hostname.lower()) if t]
