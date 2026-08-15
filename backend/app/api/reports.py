"""Report generation and download endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import desc, select

from app.api.deps import DbSession, pagination, require
from app.core.config import settings
from app.models.audit import AuditAction
from app.models.report import Report
from app.models.scan import Scan
from app.models.user import User
from app.schemas.security import ReportCreate, ReportOut
from app.services import audit_service
from app.services.report_service import report_service

router = APIRouter(prefix="/api/reports", tags=["Reports"])

MEDIA_TYPES = {
    "html": "text/html",
    "pdf": "application/pdf",
    "json": "application/json",
    "csv": "text/csv",
}


@router.post("", response_model=ReportOut, status_code=status.HTTP_201_CREATED)
def create_report(
    payload: ReportCreate,
    db: DbSession,
    user: Annotated[User, Depends(require("report:create"))],
) -> Report:
    """Generate a VulScanner Security Assessment Report for a completed scan."""
    scan = db.get(Scan, payload.scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if scan.status in ("queued", "running"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The scan is still running. Wait for it to finish.",
        )

    report = Report(
        title=payload.title,
        format=payload.format,
        status="generating",
        scan_id=scan.id,
        generated_by_id=user.id,
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    try:
        path, summary = report_service.generate(db, scan.id, payload.format)
    except Exception as exc:
        report.status = "failed"
        report.error_message = f"{type(exc).__name__}: {exc}"
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {exc}",
        ) from exc

    report.status = "ready"
    report.file_path = str(path)
    report.file_name = path.name
    report.size_bytes = path.stat().st_size
    report.generated_at = datetime.now(tz=timezone.utc)
    report.summary = summary
    db.commit()
    db.refresh(report)

    audit_service.record(
        db,
        AuditAction.REPORT_GENERATED,
        actor_id=user.id,
        actor_name=user.username,
        entity_type="report",
        entity_id=report.id,
        message=f"Generated a {payload.format.upper()} report for scan #{scan.id}.",
        details={"file_name": report.file_name, "size_bytes": report.size_bytes},
    )
    return report


@router.get("", response_model=list[ReportOut])
def list_reports(
    db: DbSession,
    _: Annotated[User, Depends(require("report:read"))],
    page: Annotated[tuple[int, int], Depends(pagination)],
    scan_id: int | None = None,
) -> list[Report]:
    limit, offset = page
    query = select(Report).order_by(desc(Report.created_at))
    if scan_id is not None:
        query = query.where(Report.scan_id == scan_id)
    return list(db.scalars(query.limit(limit).offset(offset)).all())


@router.get("/{report_id}", response_model=ReportOut)
def get_report(
    report_id: int, db: DbSession, _: Annotated[User, Depends(require("report:read"))]
) -> Report:
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    return report


@router.get("/{report_id}/download")
def download_report(
    report_id: int, db: DbSession, _: Annotated[User, Depends(require("report:read"))]
) -> FileResponse:
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    if report.status != "ready" or not report.file_path:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Report is not available (status: {report.status}).",
        )

    path = Path(report.file_path).resolve()
    output_root = Path(settings.report_dir).resolve()
    # Reports are only ever served from the configured output directory.
    if output_root not in path.parents or not path.exists():
        raise HTTPException(
            status_code=404, detail="The report file is no longer available."
        )

    return FileResponse(
        path,
        media_type=MEDIA_TYPES.get(report.format, "application/octet-stream"),
        filename=report.file_name,
    )


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def delete_report(
    report_id: int,
    db: DbSession,
    user: Annotated[User, Depends(require("report:create"))],
) -> None:
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found.")

    if report.file_path:
        path = Path(report.file_path).resolve()
        output_root = Path(settings.report_dir).resolve()
        if output_root in path.parents and path.exists():
            path.unlink()

    db.delete(report)
    db.commit()
    audit_service.record(
        db,
        "report_deleted",
        actor_id=user.id,
        actor_name=user.username,
        entity_type="report",
        entity_id=report_id,
        message=f"Report #{report_id} deleted.",
    )
