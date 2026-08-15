"""Authentication and user schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.permissions import Role
from app.core.security import password_problems


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    role: str
    username: str
    must_change_password: bool = False


class RefreshRequest(BaseModel):
    refresh_token: str


class UserBase(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    email: str | None = Field(default=None, max_length=255)
    full_name: str | None = Field(default=None, max_length=128)
    role: Role = Role.VIEWER


class UserCreate(UserBase):
    password: str = Field(min_length=12, max_length=72)

    @field_validator("password")
    @classmethod
    def _policy(cls, value: str) -> str:
        problems = password_problems(value)
        if problems:
            raise ValueError(" ".join(problems))
        return value


class UserUpdate(BaseModel):
    email: str | None = None
    full_name: str | None = None
    role: Role | None = None
    is_active: bool | None = None


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=72)

    @field_validator("new_password")
    @classmethod
    def _policy(cls, value: str) -> str:
        problems = password_problems(value)
        if problems:
            raise ValueError(" ".join(problems))
        return value


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str | None
    full_name: str | None
    role: str
    is_active: bool
    must_change_password: bool
    last_login_at: datetime | None
    created_at: datetime
