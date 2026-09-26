"""Sign-in, accounts, stream tickets and the audit trail for the API gateway (Layer 9)."""

import asyncio
import json
import logging
import re
import secrets
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netra_common.audit import AUDIT_QUEUE, AuditEvent
from netra_common.config import settings
from netra_common.fastapi_auth import client_ip, get_principal, principal_from_token, require_role
from netra_common.security import (
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_RANK,
    Principal,
    dummy_password_hash,
    hash_password,
    issue_token,
    verify_password,
)
from src.database import AuditRecord, User, async_session_maker, get_db_session

logger = logging.getLogger("netra.api_gateway.auth")

MAX_FAILED_LOGINS = 10
LOCKOUT_SECONDS = 15 * 60
TICKET_TTL_SECONDS = 60
USERNAME_PATTERN = re.compile(r"^[a-z0-9._-]{3,32}$")
MIN_PASSWORD_LENGTH = 12

router = APIRouter()


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------

def audit_event(request: Request, principal: Optional[Principal], action: str,
                resource: Optional[str] = None, success: bool = True, **detail: Any) -> AuditEvent:
    return AuditEvent(
        service="api_gateway",
        username=principal.username if principal else None,
        role=principal.role if principal else None,
        action=action,
        resource=resource,
        success=success,
        client_ip=client_ip(request),
        detail=detail,
    )


async def record(event: AuditEvent) -> None:
    try:
        async with async_session_maker() as session:
            session.add(AuditRecord(**event.model_dump()))
            await session.commit()
    except Exception as exc:
        logger.error(f"Failed to write audit record {event.action} for {event.username}: {exc}")


async def audit_consumer_loop(redis_client) -> None:
    """Persist audit records other services queued (the ingestion service has no database)."""
    logger.info(f"Starting audit consumer on '{AUDIT_QUEUE}'...")
    while True:
        try:
            item = await redis_client.brpop(AUDIT_QUEUE, timeout=2)
            if item:
                await record(AuditEvent.model_validate_json(item[1]))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error(f"Audit consumer error: {exc}")
            await asyncio.sleep(2)


# ---------------------------------------------------------------------------
# Bootstrap accounts
# ---------------------------------------------------------------------------

async def bootstrap_accounts() -> None:
    """Create the configured admin (and optional analyst) when no account exists yet."""
    async with async_session_maker() as session:
        if await session.scalar(select(func.count()).select_from(User)):
            return
        created = []
        for username, password, role in (
            (settings.NETRA_ADMIN_USERNAME, settings.NETRA_ADMIN_PASSWORD, ROLE_ADMIN),
            (settings.NETRA_ANALYST_USERNAME, settings.NETRA_ANALYST_PASSWORD, ROLE_ANALYST),
        ):
            if not password:
                continue
            if len(password) < MIN_PASSWORD_LENGTH:
                logger.error(f"Bootstrap password for '{username}' is shorter than {MIN_PASSWORD_LENGTH}; skipped.")
                continue
            session.add(User(username=username.lower(), role=role,
                             password_hash=await asyncio.to_thread(hash_password, password)))
            created.append(f"{username} ({role})")
        if not created:
            logger.error("No accounts exist and NETRA_ADMIN_PASSWORD is not set: nobody can sign in.")
            return
        await session.commit()
        logger.info(f"Created bootstrap accounts: {', '.join(created)}")


# ---------------------------------------------------------------------------
# Sign-in
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: int
    username: str
    role: str


@router.post("/api/v1/auth/login", response_model=LoginResponse, tags=["Auth"])
async def login(payload: LoginRequest, request: Request, session: AsyncSession = Depends(get_db_session)):
    username = payload.username.strip().lower()
    redis = getattr(request.app.state, "redis", None)
    fail_key = f"login_fail:{username}"

    if redis and int(await redis.get(fail_key) or 0) >= MAX_FAILED_LOGINS:
        await record(audit_event(request, None, "login", username, success=False, reason="locked out"))
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail="Too many failed sign-in attempts. Try again in 15 minutes.")

    user = await session.get(User, username)
    # Always run the hash, so a missing account takes as long to reject as a wrong password.
    matches = await asyncio.to_thread(
        verify_password, payload.password, user.password_hash if user else dummy_password_hash())

    if not (user and matches):
        if redis:
            if await redis.incr(fail_key) == 1:
                await redis.expire(fail_key, LOCKOUT_SECONDS)
        await record(audit_event(request, None, "login", username, success=False, reason="bad credentials"))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password.")

    if redis:
        await redis.delete(fail_key)
    token, expires_at = issue_token(user.username, user.role, settings.NETRA_AUTH_SECRET,
                                    settings.NETRA_TOKEN_TTL_SECONDS)
    principal = Principal(user.username, user.role, expires_at)
    await record(audit_event(request, principal, "login", user.username))
    return LoginResponse(access_token=token, expires_at=expires_at, username=user.username, role=user.role)


@router.get("/api/v1/auth/me", tags=["Auth"])
async def whoami(principal: Principal = Depends(get_principal)):
    return {"username": principal.username, "role": principal.role, "expires_at": principal.expires_at}


# ---------------------------------------------------------------------------
# Accounts (admin)
# ---------------------------------------------------------------------------

class CreateUserRequest(BaseModel):
    username: str
    password: str = Field(..., max_length=256)
    role: str = ROLE_ANALYST


@router.post("/api/v1/auth/users", status_code=status.HTTP_201_CREATED, tags=["Auth"])
async def create_user(payload: CreateUserRequest, request: Request,
                      admin: Principal = Depends(require_role(ROLE_ADMIN)),
                      session: AsyncSession = Depends(get_db_session)):
    username = payload.username.strip().lower()
    if not USERNAME_PATTERN.match(username):
        raise HTTPException(status_code=422, detail="Usernames are 3–32 characters: lowercase letters, digits, . _ -")
    if len(payload.password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(status_code=422, detail=f"Passwords must be at least {MIN_PASSWORD_LENGTH} characters.")
    if payload.role not in ROLE_RANK:
        raise HTTPException(status_code=422, detail=f"Role must be one of: {', '.join(ROLE_RANK)}.")
    if await session.get(User, username):
        raise HTTPException(status_code=409, detail=f"An account named '{username}' already exists.")

    session.add(User(username=username, role=payload.role,
                     password_hash=await asyncio.to_thread(hash_password, payload.password)))
    await session.commit()
    await record(audit_event(request, admin, "user.create", username, role_granted=payload.role))
    return {"username": username, "role": payload.role}


# ---------------------------------------------------------------------------
# Audit log (admin)
# ---------------------------------------------------------------------------

@router.get("/api/v1/audit", tags=["Audit"])
async def read_audit_log(request: Request,
                         limit: int = Query(100, ge=1, le=1000),
                         offset: int = Query(0, ge=0),
                         username: Optional[str] = None,
                         action: Optional[str] = None,
                         resource: Optional[str] = None,
                         admin: Principal = Depends(require_role(ROLE_ADMIN)),
                         session: AsyncSession = Depends(get_db_session)) -> List[Dict[str, Any]]:
    query = select(AuditRecord).order_by(desc(AuditRecord.at), desc(AuditRecord.id)).limit(limit).offset(offset)
    if username:
        query = query.where(AuditRecord.username == username.lower())
    if action:
        query = query.where(AuditRecord.action == action)
    if resource:
        query = query.where(AuditRecord.resource == resource)
    rows = (await session.execute(query)).scalars().all()
    await record(audit_event(request, admin, "audit.view", filters={"username": username, "action": action,
                                                                     "resource": resource}))
    return [
        {c: getattr(r, c) for c in ("id", "at", "service", "username", "role", "action", "resource",
                                    "success", "client_ip", "detail")}
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Live-stream tickets
# ---------------------------------------------------------------------------
# Browsers cannot put an Authorization header on an EventSource, and a token in a URL
# ends up in access logs. So the client trades its token for a single-use ticket that
# lives for a minute and opens one stream for one email.

@router.post("/api/v1/pipeline/events/{email_id}/ticket", tags=["Pipeline"])
async def issue_stream_ticket(email_id: str, request: Request,
                              principal: Principal = Depends(require_role(ROLE_ANALYST))):
    redis = getattr(request.app.state, "redis", None)
    if not redis:
        raise HTTPException(status_code=503, detail="Event bus unavailable.")
    ticket = secrets.token_urlsafe(32)
    await redis.set(f"sse_ticket:{ticket}", json.dumps({"username": principal.username, "role": principal.role,
                                                         "email_id": email_id}), ex=TICKET_TTL_SECONDS)
    return {"ticket": ticket, "expires_in": TICKET_TTL_SECONDS}


async def principal_for_stream(request: Request, email_id: str, ticket: Optional[str]) -> Principal:
    """A bearer token (curl, scripts) or a single-use ticket (browsers)."""
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return principal_from_token(header[7:].strip())

    redis = getattr(request.app.state, "redis", None)
    stored = await redis.getdel(f"sse_ticket:{ticket}") if (ticket and redis) else None
    data = json.loads(stored) if stored else None
    if not data or data.get("email_id") != email_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Stream ticket missing, expired or already used. Request a new one.")
    return Principal(username=data["username"], role=data["role"], expires_at=0)
