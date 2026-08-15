"""Finding endpoints and the remediation centre."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, select

from app.api.deps import DbSession, pagination, require
from app.models.audit import AuditAction
from app.models.finding import Finding, FindingStatus
from app.models.user import User
from app.schemas.security import FindingOut, FindingUpdate, RemediationOut
from app.services import audit_service
from app.services.remediation_service import remediation_service
from app.services.report_service import report_service

router = APIRouter(prefix="/api/findings", tags=["Findings"])

SEVERITY_RANK = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4
}


@router.get("", response_model=list[FindingOut])
def list_findings(
    db: DbSession,
    _: Annotated[User, Depends(require("finding:read"))],
    page: Annotated[tuple[int, int], Depends(pagination)],
    scan_id: int | None = None,
    asset_id: int | None = None,
    severity: str | None = None,
    category: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    search: str | None = None,
    rule_id: str | None = None,
) -> list[Finding]:
    limit, offset = page
    query = select(Finding)
    if scan_id is not None:
        query = query.where(Finding.scan_id == scan_id)
    if asset_id is not None:
        query = query.where(Finding.asset_id == asset_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if category:
        query = query.where(Finding.category == category)
    if status_filter:
        query = query.where(Finding.status == status_filter)
    if rule_id:
        query = query.where(Finding.rule_id == rule_id)
    if search:
        pattern = f"%{search}%"
        query = query.where(
            Finding.title.ilike(pattern) | Finding.description.ilike(pattern)
        )

    findings = list(
        db.scalars(
            query.order_by(desc(Finding.risk_score)).limit(limit).offset(offset)
        ).all()
    )
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), -f.risk_score))
    return findings


@router.get("/summary")
def findings_summary(
    db: DbSession,
    _: Annotated[User, Depends(require("finding:read"))],
    scan_id: int | None = None,
) -> dict:
    query = select(Finding)
    if scan_id is not None:
        query = query.where(Finding.scan_id == scan_id)
    findings = list(db.scalars(query).all())

    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_category[finding.category] = by_category.get(finding.category, 0) + 1
        by_status[finding.status] = by_status.get(finding.status, 0) + 1

    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_category": dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
        "by_status": by_status,
        "highest_risk_score": max((f.risk_score for f in findings), default=0.0),
    }


@router.get("/remediation", response_model=RemediationOut)
def remediation_plan(
    db: DbSession,
    _: Annotated[User, Depends(require("finding:read"))],
    scan_id: int | None = None,
    asset_id: int | None = None,
) -> dict:
    """Ordered remediation guidance. VulScanner never executes these actions."""
    query = select(Finding).where(
        Finding.status.in_(
            [FindingStatus.OPEN.value, FindingStatus.REOPENED.value]
        )
    )
    if scan_id is not None:
        query = query.where(Finding.scan_id == scan_id)
    if asset_id is not None:
        query = query.where(Finding.asset_id == asset_id)

    findings = [report_service._finding_dict(f) for f in db.scalars(query).all()]
    items = remediation_service.build_plan(findings)
    return {
        "items": [item.to_dict() for item in items],
        "summary": remediation_service.summarize_plan(items),
    }


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(
    finding_id: int,
    db: DbSession,
    _: Annotated[User, Depends(require("finding:read"))],
) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return finding


@router.patch("/{finding_id}", response_model=FindingOut)
def update_finding(
    finding_id: int,
    payload: FindingUpdate,
    db: DbSession,
    user: Annotated[User, Depends(require("finding:update"))],
) -> Finding:
    """Triage a finding: resolve, reopen, accept the risk or mark a false positive."""
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")

    new_status = payload.status
    if new_status is FindingStatus.RISK_ACCEPTED:
        from app.core.permissions import has_permission

        if not has_permission(user.role, "finding:accept_risk"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Accepting risk requires the administrator role.",
            )
        if not payload.note.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A justification note is required when accepting risk.",
            )

    finding.status = new_status.value
    finding.status_note = payload.note
    finding.status_changed_by_id = user.id
    finding.resolved_at = (
        datetime.now(tz=timezone.utc)
        if new_status is FindingStatus.RESOLVED
        else None
    )
    db.commit()
    db.refresh(finding)

    action = {
        FindingStatus.RESOLVED: AuditAction.FINDING_RESOLVED,
        FindingStatus.REOPENED: AuditAction.FINDING_REOPENED,
        FindingStatus.RISK_ACCEPTED: AuditAction.RISK_ACCEPTED,
    }.get(new_status, AuditAction.FINDING_CREATED)

    audit_service.record(
        db,
        action,
        actor_id=user.id,
        actor_name=user.username,
        entity_type="finding",
        entity_id=finding.finding_uid,
        message=f"Finding {finding.finding_uid} set to {new_status.value}.",
        details={"note": payload.note, "title": finding.title},
    )
    return finding
