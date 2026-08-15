"""SQLAlchemy models. Importing this package registers every table."""

from app.db.base import Base
from app.models.asset import Asset
from app.models.audit import AuditAction, AuditLog
from app.models.finding import (
    Confidence,
    Finding,
    FindingCategory,
    FindingStatus,
    Severity,
)
from app.models.network import (
    NetworkConnection,
    NetworkEdge,
    NetworkHost,
    NetworkPort,
)
from app.models.report import Report
from app.models.scan import Scan, ScanProfile, ScanResult, ScanStatus, TERMINAL_STATUSES
from app.models.target import Target
from app.models.user import Role, User
from app.models.vulnerability import CVE, Patch, Vulnerability

__all__ = [
    "Base",
    "Asset",
    "AuditAction",
    "AuditLog",
    "CVE",
    "Confidence",
    "Finding",
    "FindingCategory",
    "FindingStatus",
    "NetworkConnection",
    "NetworkEdge",
    "NetworkHost",
    "NetworkPort",
    "Patch",
    "Report",
    "Role",
    "Scan",
    "ScanProfile",
    "ScanResult",
    "ScanStatus",
    "Severity",
    "TERMINAL_STATUSES",
    "Target",
    "User",
    "Vulnerability",
]
