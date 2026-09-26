"""Access tokens, password hashing and roles (Layer 9), using only the standard library.

Tokens are HMAC-SHA256-signed JSON, verified by any service holding NETRA_AUTH_SECRET,
so the gateway and the ingestion service agree on who is calling without a shared
session store. They are stateless: logging out discards the token on the client, and a
stolen token stays valid until it expires (NETRA_TOKEN_TTL_SECONDS).
"""

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional, Tuple

ROLE_ANALYST = "analyst"
ROLE_ADMIN = "admin"
# An admin can do everything an analyst can.
ROLE_RANK = {ROLE_ANALYST: 1, ROLE_ADMIN: 2}

PASSWORD_ITERATIONS = 600_000  # OWASP 2023 guidance for PBKDF2-HMAC-SHA256
MIN_SECRET_LENGTH = 32
TOKEN_VERSION = 1


class TokenError(Exception):
    """A token is missing, malformed, forged or expired."""


@dataclass(frozen=True)
class Principal:
    username: str
    role: str
    expires_at: int


def require_secret(secret: str) -> None:
    if len(secret or "") < MIN_SECRET_LENGTH:
        raise RuntimeError(
            f"NETRA_AUTH_SECRET must be at least {MIN_SECRET_LENGTH} characters. Generate one with: "
            "python3 -c \"import secrets; print(secrets.token_urlsafe(48))\""
        )


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(body: str, secret: str) -> str:
    return _b64e(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())


def issue_token(username: str, role: str, secret: str, ttl_seconds: int,
                now: Optional[int] = None) -> Tuple[str, int]:
    """Return (token, expiry as a Unix timestamp)."""
    require_secret(secret)
    if role not in ROLE_RANK:
        raise ValueError(f"unknown role: {role}")
    issued = int(now if now is not None else time.time())
    payload = {"v": TOKEN_VERSION, "sub": username, "role": role, "iat": issued, "exp": issued + ttl_seconds}
    body = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    return f"{body}.{_sign(body, secret)}", payload["exp"]


def verify_token(token: str, secret: str, now: Optional[int] = None) -> Principal:
    require_secret(secret)
    try:
        body, signature = token.split(".")
    except (AttributeError, ValueError):
        raise TokenError("malformed token")
    if not hmac.compare_digest(signature, _sign(body, secret)):
        raise TokenError("bad signature")
    try:
        payload = json.loads(_b64d(body))
    except ValueError:
        raise TokenError("malformed payload")
    if payload.get("v") != TOKEN_VERSION or payload.get("role") not in ROLE_RANK or not payload.get("sub"):
        raise TokenError("unrecognised token contents")
    if int(payload.get("exp", 0)) <= int(now if now is not None else time.time()):
        raise TokenError("token expired")
    return Principal(username=payload["sub"], role=payload["role"], expires_at=int(payload["exp"]))


def has_role(role: str, required: str) -> bool:
    return ROLE_RANK.get(role, 0) >= ROLE_RANK[required]


def hash_password(password: str, iterations: int = PASSWORD_ITERATIONS) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${_b64e(salt)}${_b64e(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt, expected = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), _b64d(salt), int(iterations))
    except (AttributeError, ValueError):
        return False
    return hmac.compare_digest(_b64e(digest), expected)


@lru_cache(maxsize=1)
def dummy_password_hash() -> str:
    """Checked against when a username does not exist, so a failed login takes the same
    time whether or not the account is real."""
    return hash_password("netra-timing-equaliser")
