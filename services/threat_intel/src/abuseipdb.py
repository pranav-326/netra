"""Live AbuseIPDB client for Layer 5 IP reputation enrichment.

Netra's free-tier budget is 1,000 checks/day, so this client is deliberately frugal:

* Private, loopback, link-local and reserved addresses are never sent upstream — they
  cannot have public abuse reports, and spending quota on them is pure waste.
* Verdicts are cached in Redis (shared across worker restarts and replicas), so a
  campaign of 50 emails from one relay costs one lookup, not fifty.
* Every failure mode — timeout, 429, 401, malformed body — returns None rather than
  raising, so the caller can fall back to the mock provider and the pipeline keeps
  moving. Threat intel is enrichment; it must never be able to drop an email.

The daily quota remaining is read from AbuseIPDB's own `X-RateLimit-Remaining` header
and logged, so quota exhaustion is visible rather than silent.
"""

import ipaddress
import json
import logging
from typing import Any, Dict, Optional

import requests

from netra_common.config import settings

logger = logging.getLogger("netra.threat_intel.abuseipdb")

API_URL = "https://api.abuseipdb.com/api/v2/check"
CACHE_PREFIX = "intel:abuseipdb:"

# A negative cache entry is stored for IPs AbuseIPDB reports as clean, so repeat
# benign senders do not consume quota either.
NEGATIVE_CACHE_TTL_SECONDS = 3600


def is_publicly_routable(ip: str) -> bool:
    """True only for addresses that can meaningfully have public abuse reports."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


class AbuseIPDBClient:
    """Queries AbuseIPDB for IP reputation, with a Redis-backed quota-saving cache."""

    def __init__(self, redis_client: Any = None) -> None:
        self.redis = redis_client
        self.api_key = settings.ABUSEIPDB_API_KEY.strip()
        self.enabled = settings.abuseipdb_active
        self.quota_remaining: Optional[int] = None
        # Set when the API answers 429 or 401; suppresses further calls this run so a
        # dead key does not add latency to every single email.
        self.suspended_reason: Optional[str] = None

        self._session = requests.Session()
        self._session.headers.update({"Key": self.api_key, "Accept": "application/json"})

        if self.enabled:
            logger.info(
                f"AbuseIPDB live enrichment ENABLED "
                f"(threshold={settings.ABUSEIPDB_MALICIOUS_THRESHOLD}, "
                f"cache_ttl={settings.ABUSEIPDB_CACHE_TTL_SECONDS}s)"
            )
        else:
            logger.info("AbuseIPDB live enrichment DISABLED (no API key or explicitly off).")

    @property
    def available(self) -> bool:
        return self.enabled and self.suspended_reason is None

    # ---------------------------------------------------------------- caching

    def _cache_get(self, ip: str) -> Optional[Dict[str, Any]]:
        if not self.redis:
            return None
        try:
            raw = self.redis.get(f"{CACHE_PREFIX}{ip}")
            return json.loads(raw) if raw else None
        except Exception as exc:
            logger.debug(f"AbuseIPDB cache read failed for {ip}: {exc}")
            return None

    def _cache_put(self, ip: str, payload: Dict[str, Any]) -> None:
        if not self.redis:
            return
        ttl = (
            settings.ABUSEIPDB_CACHE_TTL_SECONDS
            if payload.get("is_malicious")
            else NEGATIVE_CACHE_TTL_SECONDS
        )
        try:
            self.redis.setex(f"{CACHE_PREFIX}{ip}", ttl, json.dumps(payload))
        except Exception as exc:
            logger.debug(f"AbuseIPDB cache write failed for {ip}: {exc}")

    # ---------------------------------------------------------------- lookup

    def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Return a normalised verdict for `ip`, or None if no live answer is available.

        None means "no live data" — never "clean". The caller must distinguish those,
        otherwise an outage would silently exonerate malicious infrastructure.
        """
        ip = ip.strip()

        if not self.available:
            return None

        if not is_publicly_routable(ip):
            logger.debug(f"Skipping AbuseIPDB lookup for non-routable address {ip}.")
            return None

        cached = self._cache_get(ip)
        if cached is not None:
            cached["cached"] = True
            return cached

        try:
            response = self._session.get(
                API_URL,
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": settings.ABUSEIPDB_MAX_AGE_DAYS,
                    "verbose": "",
                },
                timeout=settings.ABUSEIPDB_TIMEOUT_SECONDS,
            )
        except requests.Timeout:
            logger.warning(f"AbuseIPDB timed out for {ip}; falling back to local intel.")
            return None
        except requests.RequestException as exc:
            logger.warning(f"AbuseIPDB request failed for {ip}: {exc}; falling back to local intel.")
            return None

        remaining = response.headers.get("X-RateLimit-Remaining")
        if remaining is not None:
            try:
                self.quota_remaining = int(remaining)
                if self.quota_remaining <= 25:
                    logger.warning(f"AbuseIPDB daily quota nearly exhausted: {self.quota_remaining} left.")
            except ValueError:
                pass

        if response.status_code == 429:
            self.suspended_reason = "daily quota exhausted (HTTP 429)"
            logger.warning("AbuseIPDB quota exhausted; using local intel for the rest of this run.")
            return None

        if response.status_code in (401, 403):
            self.suspended_reason = f"authentication rejected (HTTP {response.status_code})"
            logger.error("AbuseIPDB rejected the API key; live enrichment suspended.")
            return None

        if response.status_code != 200:
            logger.warning(f"AbuseIPDB returned HTTP {response.status_code} for {ip}.")
            return None

        try:
            data = response.json().get("data", {})
        except ValueError:
            logger.warning(f"AbuseIPDB returned a non-JSON body for {ip}.")
            return None

        verdict = self._normalise(ip, data)
        self._cache_put(ip, verdict)
        verdict["cached"] = False
        return verdict

    @staticmethod
    def _normalise(ip: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Map AbuseIPDB's response onto Netra's EnrichedIOC shape."""
        confidence = int(data.get("abuseConfidenceScore") or 0)
        total_reports = int(data.get("totalReports") or 0)
        usage_type = data.get("usageType") or "Unknown"
        is_tor = bool(data.get("isTor"))

        threat_names = []
        if confidence >= settings.ABUSEIPDB_MALICIOUS_THRESHOLD:
            threat_names.append(f"AbuseIPDB confidence {confidence}%")
        if is_tor:
            threat_names.append("Tor exit node")
        if usage_type and usage_type != "Unknown":
            threat_names.append(usage_type)

        return {
            "ip": ip,
            "is_malicious": confidence >= settings.ABUSEIPDB_MALICIOUS_THRESHOLD,
            "threat_score": max(0, min(confidence, 100)),
            "threat_names": threat_names,
            "details": {
                "source": "AbuseIPDB live API",
                "abuse_confidence_score": confidence,
                "total_reports": total_reports,
                "num_distinct_reporters": data.get("numDistinctUsers"),
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "usage_type": usage_type,
                "is_tor": is_tor,
                "is_whitelisted": bool(data.get("isWhitelisted")),
                "last_reported_at": data.get("lastReportedAt"),
            },
        }

    def close(self) -> None:
        try:
            self._session.close()
        except Exception:
            pass
