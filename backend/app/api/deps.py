"""Shared API dependencies: authentication, RBAC and rate limiting."""

from __future__ import annotations

from typing import Annotated, Callable

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.permissions import Role, has_permission
from app.core.security import TokenError, api_limiter, decode_token
from app.db.session import get_db
from app.models.user import User

bearer_scheme = HTTPBearer(auto_error=False, description="VulScanner access token")

DbSession = Annotated[Session, Depends(get_db)]


def client_ip(request: Request) -> str:
    if request.client:
        return request.client.host
    return "unknown"


def rate_limit(request: Request) -> None:
    key = client_ip(request)
    if not api_limiter.check(key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Slow down and retry shortly.",
            headers={"Retry-After": str(api_limiter.retry_after(key))},
        )


def current_user(
    db: DbSession,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(bearer_scheme)
    ] = None,
) -> User:
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_token(credentials.credentials, expected_type="access")
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = db.get(User, int(payload.get("uid", 0)))
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is inactive or no longer exists.",
        )
    return user


CurrentUser = Annotated[User, Depends(current_user)]


def require(permission: str) -> Callable[[User], User]:
    """Dependency factory enforcing a capability from the permission matrix."""

    def dependency(user: CurrentUser) -> User:
        if not has_permission(user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Your role ({user.role}) does not permit '{permission}'."
                ),
            )
        return user

    return dependency


def require_role(role: Role) -> Callable[[User], User]:
    def dependency(user: CurrentUser) -> User:
        from app.core.permissions import role_satisfies

        if not role_satisfies(user.role, role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This operation requires the {role.value} role.",
            )
        return user

    return dependency


def pagination(limit: int = 50, offset: int = 0) -> tuple[int, int]:
    return max(1, min(limit, 500)), max(0, offset)
