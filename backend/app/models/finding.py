"""Security findings (misconfigurations, exposures, weaknesses)."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from sqlalchemy import DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.db.types import JSONList, JSONMap


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingStatus(str, Enum):
    OPEN = "open"
    RESOLVED = "resolved"
    REOPENED = "reopened"
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"


class FindingCategory(str, Enum):
    PATCH = "patch"
    SOFTWARE = "software"
    FIREWALL = "firewall"
    DEFENDER = "defender"
    ANTIVIRUS = "antivirus"
    RDP = "rdp"
    ACCOUNTS = "accounts"
    POLICY = "policy"
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    EXPOSURE = "exposure"
    SHARES = "shares"
    AUTORUN = "autorun"
    CERTIFICATE = "certificate"
    BOOT_INTEGRITY = "boot_integrity"
    LOGGING = "logging"
    FILESYSTEM = "filesystem"
    SECRETS = "secrets"
    VULNERABILITY = "vulnerability"
    SYSTEM = "system"


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)

    # Deterministic, human-referenceable identifier, e.g. VS-FW-0001.
    finding_uid: Mapped[str] = mapped_column(String(48), index=True)
    # Stable rule key used to deduplicate the same issue across scans.
    rule_id: Mapped[str] = mapped_column(String(64), index=True)

    title: Mapped[str] = mapped_column(String(255))
    category: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    confidence: Mapped[str] = mapped_column(String(16), default=Confidence.HIGH.value)
    status: Mapped[str] = mapped_column(
        String(16), default=FindingStatus.OPEN.value, index=True
    )

    description: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict] = mapped_column(JSONMap, default=dict)
    evidence_summary: Mapped[str] = mapped_column(Text, default="")
    detection_method: Mapped[str] = mapped_column(String(128), default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    remediation_command: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[list] = mapped_column(JSONList, default=list)

    # Explains how the risk score was produced.
    risk_factors: Mapped[dict] = mapped_column(JSONMap, default=dict)

    scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=True
    )
    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), index=True, nullable=True
    )
    scan_result_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_results.id", ondelete="SET NULL"), nullable=True
    )
    vulnerability_id: Mapped[int | None] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="SET NULL"), nullable=True
    )

    first_detected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_detected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status_note: Mapped[str] = mapped_column(Text, default="")
    status_changed_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    scan: Mapped["Scan | None"] = relationship(back_populates="findings")  # noqa: F821
    asset: Mapped["Asset | None"] = relationship(back_populates="findings")  # noqa: F821

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Finding {self.finding_uid} {self.severity} {self.title[:40]}>"
