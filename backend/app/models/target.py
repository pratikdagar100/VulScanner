"""Authorized scan targets.

A ``Target`` row is an operator's explicit statement that a host or network may
be assessed. It extends the environment-level authorized scopes.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class Target(Base, TimestampMixin):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128))

    # local | ip | cidr | hostname
    target_type: Mapped[str] = mapped_column(String(16), index=True)
    value: Mapped[str] = mapped_column(String(255), index=True)

    description: Mapped[str] = mapped_column(Text, default="")

    # Attestation of authorization - recorded for the audit trail.
    authorized: Mapped[bool] = mapped_column(Boolean, default=False)
    authorization_note: Mapped[str] = mapped_column(Text, default="")
    authorized_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    authorized_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Feeds the risk engine's asset-importance input.
    criticality: Mapped[str] = mapped_column(String(16), default="normal")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Target {self.value} ({self.target_type})>"
