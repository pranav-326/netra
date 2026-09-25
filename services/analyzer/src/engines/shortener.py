"""Link-shortener resolution for the URL engine (Layer 3).

A shortened link hides its destination, which blinds every other URL check: the
typosquat detector sees `tinyurl.com`, not the lookalike domain behind it. This module
asks the shortener where a link points and hands the real destination back to the URL
engine, which then analyses it exactly as if it had appeared in the email.

Safety rules, all enforced here:

* Only hosts on `SHORTENER_DOMAINS` are ever contacted. A URL from an email can never
  make the analyzer connect to an arbitrary server.
* We read the redirect's `Location` header and stop. Redirects are never followed and
  response bodies are never read, so the attacker's destination is never contacted —
  visiting it could tip them off that the email was opened, or serve a payload.
* Failure is reported as "unresolved", never as "clean".
"""

import http.client
import logging
import time
from typing import Callable, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

from netra_common.models.email import ShortenedUrl

logger = logging.getLogger("netra.analyzer.shortener")

SHORTENER_DOMAINS = frozenset({
    "tinyurl.com",
    "bit.ly",
    "bitly.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "v.gd",
    "buff.ly",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "t.ly",
    "rebrand.ly",
    "tiny.cc",
    "s.id",
    "lnkd.in",
    "shorte.st",
    "adf.ly",
    "bl.ink",
})

# Attackers nest shorteners to hide the destination; past this depth we stop asking.
MAX_HOPS = 5
TIMEOUT_SECONDS = 3.0
CACHE_TTL_SECONDS = 6 * 3600
REDIRECT_STATUSES = {301, 302, 303, 307, 308}

# Given a short URL, return the redirect target, or None if the shortener did not
# redirect. Raises on network failure.
Fetcher = Callable[[str], Optional[str]]


def is_shortener(hostname: Optional[str]) -> bool:
    if not hostname:
        return False
    host = hostname.lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host in SHORTENER_DOMAINS


def fetch_redirect_target(url: str) -> Optional[str]:
    """Ask a shortener where `url` points, without following the redirect."""
    parsed = urlparse(url)
    host = parsed.hostname
    if not is_shortener(host):
        raise ValueError(f"refusing to contact non-shortener host: {host!r}")

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    # Always HTTPS on the default port: any port or credentials embedded in the URL
    # are attacker-controlled and deliberately ignored.
    conn = http.client.HTTPSConnection(host, timeout=TIMEOUT_SECONDS)
    headers = {"User-Agent": "Netra-LinkResolver/1.0"}
    try:
        conn.request("HEAD", path, headers=headers)
        response = conn.getresponse()
        response.read()
        if response.status == 405:
            # Some shorteners refuse HEAD. A GET still only reaches the shortener,
            # and the body is never read.
            conn.request("GET", path, headers=headers)
            response = conn.getresponse()
        status = response.status
        location = response.getheader("Location")
    finally:
        conn.close()

    if status in REDIRECT_STATUSES and location:
        return urljoin(url, location)
    return None


class ShortenerResolver:
    """Resolves short links hop by hop, caching results for the worker's lifetime."""

    def __init__(self, fetch: Fetcher = fetch_redirect_target):
        self._fetch = fetch
        self._cache: Dict[str, Tuple[float, ShortenedUrl]] = {}

    def resolve(self, url: str) -> ShortenedUrl:
        cached = self._cache.get(url)
        if cached and cached[0] > time.monotonic():
            return cached[1].model_copy(deep=True)

        result, cacheable = self._walk(url)
        if cacheable:
            self._cache[url] = (time.monotonic() + CACHE_TTL_SECONDS, result)
        return result.model_copy(deep=True)

    def _walk(self, url: str) -> Tuple[ShortenedUrl, bool]:
        chain = [url]
        current = url

        for _ in range(MAX_HOPS):
            try:
                target = self._fetch(current)
            except Exception as exc:
                # Transient network failures are not cached, so the next email retries.
                logger.warning(f"Shortener lookup failed for {current}: {exc}")
                return ShortenedUrl(
                    original_url=url,
                    chain=chain,
                    failure_reason=f"lookup failed ({type(exc).__name__})",
                ), False

            if not target:
                return ShortenedUrl(
                    original_url=url,
                    chain=chain,
                    failure_reason="shortener did not redirect (link expired or removed)",
                ), True

            chain.append(target)
            if not is_shortener(urlparse(target).hostname):
                return ShortenedUrl(
                    original_url=url, chain=chain, final_url=target, resolved=True
                ), True
            current = target

        return ShortenedUrl(
            original_url=url,
            chain=chain,
            failure_reason=f"more than {MAX_HOPS} nested shorteners",
        ), True


DEFAULT_RESOLVER = ShortenerResolver()
