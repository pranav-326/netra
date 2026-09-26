"""FastAPI dependencies for bearer-token authentication and role checks.

Imported only by the HTTP services; the pipeline workers never import FastAPI.
"""

from typing import Callable, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import settings
from .security import Principal, TokenError, has_role, verify_token

_bearer = HTTPBearer(auto_error=False)


def _unauthorised(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def principal_from_token(token: Optional[str]) -> Principal:
    if not token:
        raise _unauthorised("Sign in to use this endpoint.")
    try:
        return verify_token(token, settings.NETRA_AUTH_SECRET)
    except TokenError:
        raise _unauthorised("Your session is invalid or has expired. Sign in again.")


def get_principal(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> Principal:
    principal = principal_from_token(credentials.credentials if credentials else None)
    request.state.principal = principal
    return principal


def require_role(role: str) -> Callable[..., Principal]:
    def dependency(principal: Principal = Depends(get_principal)) -> Principal:
        if not has_role(principal.role, role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action needs the {role} role; you are signed in as {principal.role}.",
            )
        return principal

    return dependency


def client_ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None
