"""Vulnerability and patch endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, select

from app.api.deps import DbSession, pagination, require
from app.models.user import User
from app.models.vulnerability import CVE, Patch, Vulnerability
from app.schemas.security import VulnerabilityOut
from app.services.cve_service import cve_service

router = APIRouter(prefix="/api/vulnerabilities", tags=["Vulnerabilities"])
patches_router = APIRouter(prefix="/api/patches", tags=["Patches"])


@router.get("", response_model=list[VulnerabilityOut])
def list_vulnerabilities(
    db: DbSession,
    _: Annotated[User, Depends(require("vulnerability:read"))],
    page: Annotated[tuple[int, int], Depends(pagination)],
    scan_id: int | None = None,
    asset_id: int | None = None,
    severity: str | None = None,
    kev: bool | None = Query(default=None, description="Only CISA KEV entries."),
    product: str | None = None,
    cve_id: str | None = None,
) -> list[Vulnerability]:
    limit, offset = page
    query = select(Vulnerability)
    if scan_id is not None:
        query = query.where(Vulnerability.scan_id == scan_id)
    if asset_id is not None:
        query = query.where(Vulnerability.asset_id == asset_id)
    if severity:
        query = query.where(Vulnerability.severity == severity)
    if kev is not None:
        query = query.where(Vulnerability.kev.is_(kev))
    if product:
        query = query.where(Vulnerability.product.ilike(f"%{product}%"))
    if cve_id:
        query = query.where(Vulnerability.cve_id == cve_id.upper())

    return list(
        db.scalars(
            query.order_by(desc(Vulnerability.risk_score)).limit(limit).offset(offset)
        ).all()
    )


@router.get("/intelligence")
def intelligence_status(
    _: Annotated[User, Depends(require("vulnerability:read"))]
) -> dict:
    """Availability of the vulnerability intelligence sources."""
    return cve_service.status()


@router.get("/cve/{cve_id}")
def get_cve(
    cve_id: str,
    db: DbSession,
    _: Annotated[User, Depends(require("vulnerability:read"))],
) -> dict:
    """Cached CVE intelligence, fetched from NVD on a cache miss."""
    record = db.scalar(select(CVE).where(CVE.cve_id == cve_id.upper()))
    if record is None:
        fetched = cve_service.get_cve(cve_id.upper())
        if fetched is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    "CVE not found in the local cache and the NVD lookup did not "
                    "return a record."
                ),
            )
        return fetched.to_dict()

    return {
        "cve_id": record.cve_id,
        "description": record.description,
        "cvss_v3_score": record.cvss_v3_score,
        "cvss_v3_vector": record.cvss_v3_vector,
        "cvss_severity": record.cvss_severity,
        "attack_vector": record.attack_vector,
        "exploitability_score": record.exploitability_score,
        "impact_score": record.impact_score,
        "cwe_ids": record.cwe_ids,
        "references": record.references,
        "kev": record.kev,
        "kev_date_added": record.kev_date_added,
        "kev_due_date": record.kev_due_date,
        "kev_ransomware": record.kev_ransomware,
        "published_at": record.published_at,
        "modified_at": record.modified_at,
        "fetched_at": record.fetched_at,
        "source": record.source,
    }


@router.get("/{vulnerability_id}", response_model=VulnerabilityOut)
def get_vulnerability(
    vulnerability_id: int,
    db: DbSession,
    _: Annotated[User, Depends(require("vulnerability:read"))],
) -> Vulnerability:
    vulnerability = db.get(Vulnerability, vulnerability_id)
    if vulnerability is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found.")
    return vulnerability


@patches_router.get("")
def list_patches(
    db: DbSession,
    _: Annotated[User, Depends(require("vulnerability:read"))],
    page: Annotated[tuple[int, int], Depends(pagination)],
    scan_id: int | None = None,
    asset_id: int | None = None,
    state: str | None = Query(default=None, pattern="^(installed|missing|unknown)$"),
) -> list[dict]:
    limit, offset = page
    query = select(Patch)
    if scan_id is not None:
        query = query.where(Patch.scan_id == scan_id)
    if asset_id is not None:
        query = query.where(Patch.asset_id == asset_id)
    if state:
        query = query.where(Patch.state == state)

    patches = db.scalars(
        query.order_by(desc(Patch.installed_on)).limit(limit).offset(offset)
    ).all()
    return [
        {
            "id": patch.id,
            "kb_id": patch.kb_id,
            "title": patch.title,
            "classification": patch.classification,
            "state": patch.state,
            "installed_on": patch.installed_on,
            "installed_by": patch.installed_by,
            "severity": patch.severity,
            "confidence": patch.confidence,
            "evidence": patch.evidence,
            "asset_id": patch.asset_id,
            "scan_id": patch.scan_id,
        }
        for patch in patches
    ]
