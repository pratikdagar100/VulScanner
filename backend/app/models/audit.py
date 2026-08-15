"""Append-only audit log.

Credentials, tokens and secret values must never be written here; callers pass
only descriptive metadata.
"""

from __future__ import annotations

from enum import Enum

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin
from app.db.types import JSONMap


class AuditAction(str, Enum):
    LOGIN = "login"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_CANCELLED = "scan_cancelled"
    SCAN_FAILED = "scan_failed"
    TARGET_ADDED = "target_added"
    TARGET_DELETED = "target_deleted"
    FINDING_CREATED = "finding_created"
    FINDING_RESOLVED = "finding_resolved"
    FINDING_REOPENED = "finding_reopened"
    RISK_ACCEPTED = "risk_accepted"
    REPORT_GENERATED = "report_generated"
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    AUTHORIZATION_DENIED = "authorization_denied"


class AuditLog(Base, TimestampMixin):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)

    action: Mapped[str] = mapped_column(String(32), index=True)
    outcome: Mapped[str] = mapped_column(String(16), default="success")

    actor_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    actor_name: Mapped[str] = mapped_column(String(64), default="system")
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)

    entity_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    entity_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    message: Mapped[str] = mapped_column(Text, default="")
    details: Mapped[dict] = mapped_column(JSONMap, default=dict)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AuditLog {self.action} by {self.actor_name}>"
