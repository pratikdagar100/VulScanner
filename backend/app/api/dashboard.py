"""Dashboard aggregation and audit log endpoints.

Every number here is computed from stored scan evidence. Nothing is seeded,
sampled or hard-coded: an empty database produces an empty dashboard.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, func, select

from app.api.deps import DbSession, pagination, require
from app.models.asset import Asset
from app.models.audit import AuditLog
from app.models.finding import Finding, FindingStatus
from app.models.network import NetworkPort
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.models.vulnerability import Patch, Vulnerability
from app.schemas.security import AuditLogOut, DashboardSummary
from app.services.cve_service import cve_service
from app.services.risk_engine import security_score

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])
audit_router = APIRouter(prefix="/api/audit", tags=["Audit"])

SEVERITIES = ["critical", "high", "medium", "low", "informational"]

# Finding categories that represent configuration weaknesses rather than
# missing patches or software vulnerabilities.
MISCONFIGURATION_CATEGORIES = {
    "firewall", "defender", "antivirus", "rdp", "accounts", "policy",
    "authentication", "network", "exposure", "shares", "autorun",
    "boot_integrity", "logging", "filesystem", "secrets", "certificate",
}


@router.get("", response_model=DashboardSummary)
def dashboard(
    db: DbSession, _: Annotated[User, Depends(require("finding:read"))]
) -> dict:
    open_statuses = [FindingStatus.OPEN.value, FindingStatus.REOPENED.value]

    severity_counts = {
        severity: (
            db.scalar(
                select(func.count(Finding.id)).where(
                    Finding.severity == severity, Finding.status.in_(open_statuses)
                )
            )
            or 0
        )
        for severity in SEVERITIES
    }

    open_findings = sum(severity_counts.values())
    resolved_findings = (
        db.scalar(
            select(func.count(Finding.id)).where(
                Finding.status == FindingStatus.RESOLVED.value
            )
        )
        or 0
    )

    category_rows = db.execute(
        select(Finding.category, func.count(Finding.id))
        .where(Finding.status.in_(open_statuses))
        .group_by(Finding.category)
        .order_by(desc(func.count(Finding.id)))
    ).all()
    category_distribution = {row[0]: row[1] for row in category_rows}

    total_assets = db.scalar(select(func.count(Asset.id))) or 0
    scanned_assets = (
        db.scalar(select(func.count(Asset.id)).where(Asset.last_seen.is_not(None))) or 0
    )
    total_scans = db.scalar(select(func.count(Scan.id))) or 0
    running_scans = (
        db.scalar(
            select(func.count(Scan.id)).where(
                Scan.status.in_([ScanStatus.RUNNING.value, ScanStatus.QUEUED.value])
            )
        )
        or 0
    )

    vulnerability_count = db.scalar(select(func.count(Vulnerability.id))) or 0
    kev_count = (
        db.scalar(select(func.count(Vulnerability.id)).where(Vulnerability.kev.is_(True)))
        or 0
    )
    missing_updates = (
        db.scalar(select(func.count(Patch.id)).where(Patch.state == "missing")) or 0
    )
    installed_updates = (
        db.scalar(select(func.count(Patch.id)).where(Patch.state == "installed")) or 0
    )
    exposed_ports = (
        db.scalar(
            select(func.count(NetworkPort.id)).where(
                NetworkPort.exposure.in_(["all-interfaces", "private", "public"])
            )
        )
        or 0
    )
    misconfigurations = (
        db.scalar(
            select(func.count(Finding.id)).where(
                Finding.category.in_(MISCONFIGURATION_CATEGORIES),
                Finding.status.in_(open_statuses),
            )
        )
        or 0
    )

    top_assets = db.scalars(
        select(Asset).order_by(desc(Asset.risk_score)).limit(10)
    ).all()

    service_rows = db.execute(
        select(
            NetworkPort.port,
            NetworkPort.service,
            func.count(NetworkPort.id),
            func.max(NetworkPort.risk_score),
        )
        .where(NetworkPort.exposure.in_(["all-interfaces", "private", "public"]))
        .group_by(NetworkPort.port, NetworkPort.service)
        .order_by(desc(func.max(NetworkPort.risk_score)))
        .limit(12)
    ).all()

    trend_rows = db.scalars(
        select(Scan)
        .where(Scan.security_score.is_not(None))
        .order_by(desc(Scan.finished_at))
        .limit(20)
    ).all()
    risk_trend = [
        {
            "scan_id": scan.id,
            "target": scan.target,
            "finished_at": scan.finished_at,
            "security_score": scan.security_score,
            "critical": scan.critical_count,
            "high": scan.high_count,
            "medium": scan.medium_count,
            "low": scan.low_count,
        }
        for scan in reversed(trend_rows)
    ]

    last_scan = db.scalar(
        select(Scan).where(Scan.finished_at.is_not(None)).order_by(desc(Scan.finished_at))
    )

    return {
        "security_score": security_score(
            severity_counts["critical"], severity_counts["high"],
            severity_counts["medium"], severity_counts["low"],
        ),
        "total_assets": total_assets,
        "scanned_assets": scanned_assets,
        "total_scans": total_scans,
        "running_scans": running_scans,
        "severity_counts": severity_counts,
        "open_findings": open_findings,
        "resolved_findings": resolved_findings,
        "vulnerability_count": vulnerability_count,
        "kev_vulnerability_count": kev_count,
        "missing_updates": missing_updates,
        "exposed_ports": exposed_ports,
        "misconfigurations": misconfigurations,
        "category_distribution": category_distribution,
        "top_risky_assets": [
            {
                "id": asset.id,
                "hostname": asset.hostname,
                "ip_address": asset.ip_address,
                "os_name": asset.os_name,
                "risk_score": asset.risk_score,
                "severity": asset.severity,
                "critical_count": asset.critical_count,
                "high_count": asset.high_count,
                "finding_count": asset.finding_count,
            }
            for asset in top_assets
        ],
        "exposed_services": [
            {
                "port": row[0],
                "service": row[1] or "unknown",
                "count": row[2],
                "max_risk_score": row[3] or 0.0,
            }
            for row in service_rows
        ],
        "risk_trend": risk_trend,
        "patch_status": {
            "installed": installed_updates,
            "missing": missing_updates,
            "coverage_percent": round(
                100.0 * installed_updates / max(1, installed_updates + missing_updates), 1
            ),
        },
        "last_scan_at": last_scan.finished_at if last_scan else None,
        "intelligence": cve_service.status(),
    }


@audit_router.get("", response_model=list[AuditLogOut])
def list_audit_logs(
    db: DbSession,
    _: Annotated[User, Depends(require("audit:read"))],
    page: Annotated[tuple[int, int], Depends(pagination)],
    action: str | None = None,
    actor: str | None = None,
    outcome: str | None = Query(default=None, pattern="^(success|failure|denied)$"),
) -> list[AuditLog]:
    limit, offset = page
    query = select(AuditLog).order_by(desc(AuditLog.created_at))
    if action:
        query = query.where(AuditLog.action == action)
    if actor:
        query = query.where(AuditLog.actor_name.ilike(f"%{actor}%"))
    if outcome:
        query = query.where(AuditLog.outcome == outcome)
    return list(db.scalars(query.limit(limit).offset(offset)).all())
