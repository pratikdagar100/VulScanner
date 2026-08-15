"""Authentication and user management endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select

from app.api.deps import CurrentUser, DbSession, client_ip, require
from app.core.config import settings
from app.core.permissions import Role
from app.core.security import (
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    login_limiter,
    verify_password,
)
from app.models.audit import AuditAction
from app.models.user import Role as RoleModel, User
from app.schemas.auth import (
    LoginRequest,
    PasswordChangeRequest,
    RefreshRequest,
    TokenPair,
    UserCreate,
    UserOut,
    UserUpdate,
)
from app.services import audit_service

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenPair)
def login(payload: LoginRequest, request: Request, db: DbSession) -> TokenPair:
    """Exchange credentials for an access and refresh token pair."""
    source = client_ip(request)
    if not login_limiter.check(source):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again later.",
            headers={"Retry-After": str(login_limiter.retry_after(source))},
        )

    user = db.scalar(select(User).where(User.username == payload.username))
    # Always run a verification so a missing user and a wrong password take a
    # comparable amount of time.
    valid = verify_password(
        payload.password,
        user.password_hash if user else "$2b$12$" + "x" * 53,
    )

    if user is None or not valid or not user.is_active:
        if user is not None:
            user.failed_login_count += 1
        audit_service.record(
            db,
            AuditAction.LOGIN_FAILED,
            actor_name=payload.username,
            outcome="failure",
            source_ip=source,
            message="Authentication failed.",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    user.last_login_at = datetime.now(tz=timezone.utc)
    user.failed_login_count = 0
    audit_service.record(
        db,
        AuditAction.LOGIN,
        actor_id=user.id,
        actor_name=user.username,
        source_ip=source,
        message="Authentication succeeded.",
    )

    return TokenPair(
        access_token=create_access_token(user.username, user.role, user.id),
        refresh_token=create_refresh_token(user.username, user.id),
        expires_in=settings.access_token_minutes * 60,
        role=user.role,
        username=user.username,
        must_change_password=user.must_change_password,
    )


@router.post("/refresh", response_model=TokenPair)
def refresh(payload: RefreshRequest, db: DbSession) -> TokenPair:
    try:
        claims = decode_token(payload.refresh_token, expected_type="refresh")
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)
        ) from exc

    user = db.get(User, int(claims.get("uid", 0)))
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Account is inactive."
        )

    return TokenPair(
        access_token=create_access_token(user.username, user.role, user.id),
        refresh_token=create_refresh_token(user.username, user.id),
        expires_in=settings.access_token_minutes * 60,
        role=user.role,
        username=user.username,
        must_change_password=user.must_change_password,
    )


@router.post("/logout")
def logout(request: Request, db: DbSession, user: CurrentUser) -> dict:
    audit_service.record(
        db,
        AuditAction.LOGOUT,
        actor_id=user.id,
        actor_name=user.username,
        source_ip=client_ip(request),
        message="User logged out.",
    )
    return {"detail": "Logged out. Discard the stored tokens."}


@router.get("/me", response_model=UserOut)
def me(user: CurrentUser) -> User:
    return user


@router.post("/change-password")
def change_password(
    payload: PasswordChangeRequest, db: DbSession, user: CurrentUser
) -> dict:
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The current password is incorrect.",
        )
    user.password_hash = hash_password(payload.new_password)
    user.must_change_password = False
    audit_service.record(
        db,
        AuditAction.USER_UPDATED,
        actor_id=user.id,
        actor_name=user.username,
        entity_type="user",
        entity_id=user.id,
        message="Password changed.",
    )
    return {"detail": "Password updated."}


@router.get("/users", response_model=list[UserOut])
def list_users(
    db: DbSession, _: Annotated[User, Depends(require("user:manage"))]
) -> list[User]:
    return list(db.scalars(select(User).order_by(User.username)).all())


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    db: DbSession,
    actor: Annotated[User, Depends(require("user:manage"))],
) -> User:
    if db.scalar(select(User).where(User.username == payload.username)):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Username already exists."
        )

    role_row = db.scalar(select(RoleModel).where(RoleModel.name == payload.role.value))
    user = User(
        username=payload.username,
        email=payload.email,
        full_name=payload.full_name,
        role=payload.role.value,
        role_id=role_row.id if role_row else None,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    audit_service.record(
        db,
        AuditAction.USER_CREATED,
        actor_id=actor.id,
        actor_name=actor.username,
        entity_type="user",
        entity_id=user.id,
        message=f"Created user '{user.username}' with role {user.role}.",
    )
    return user


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    payload: UserUpdate,
    db: DbSession,
    actor: Annotated[User, Depends(require("user:manage"))],
) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")

    if payload.role is not None and user.id == actor.id and payload.role != Role.ADMINISTRATOR:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot remove your own administrator role.",
        )

    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(user, field, value.value if isinstance(value, Role) else value)
    db.commit()
    db.refresh(user)

    audit_service.record(
        db,
        AuditAction.USER_UPDATED,
        actor_id=actor.id,
        actor_name=actor.username,
        entity_type="user",
        entity_id=user.id,
        message=f"Updated user '{user.username}'.",
        details={"fields": sorted(changes)},
    )
    return user
