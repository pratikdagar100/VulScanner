"""Asset inventory endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, or_, select

from app.api.deps import DbSession, pagination, require
from app.models.asset import Asset
from app.models.audit import AuditAction
from app.models.finding import Finding
from app.models.network import NetworkPort
from app.models.target import Target
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.schemas.security import AssetOut, FindingOut, NetworkPortOut, TargetCreate, TargetOut
from app.services import audit_service

router = APIRouter(prefix="/api/assets", tags=["Assets"])
targets_router = APIRouter(prefix="/api/targets", tags=["Targets"])


@router.get("", response_model=list[AssetOut])
def list_assets(
    db: DbSession,
    _: Annotated[User, Depends(require("asset:read"))],
    page: Annotated[tuple[int, int], Depends(pagination)],
    search: str | None = Query(
        default=None,
        description="Matches hostname, IP, MAC or vendor.",
    ),
    severity: str | None = None,
    os_name: str | None = None,
    port: int | None = Query(default=None, description="Only assets exposing this port."),
    cve: str | None = Query(default=None, description="Only assets affected by this CVE."),
    finding_rule: str | None = Query(
        default=None, description="Only assets with this finding rule id."
    ),
) -> list[Asset]:
    limit, offset = page
    query = select(Asset)

    if search:
        pattern = f"%{search}%"
        query = query.where(
            or_(
                Asset.hostname.ilike(pattern),
                Asset.ip_address.ilike(pattern),
                Asset.mac_address.ilike(pattern),
                Asset.vendor.ilike(pattern),
            )
        )
    if severity:
        query = query.where(Asset.severity == severity)
    if os_name:
        query = query.where(Asset.os_name.ilike(f"%{os_name}%"))
    if port is not None:
        query = query.where(
            Asset.id.in_(select(NetworkPort.asset_id).where(NetworkPort.port == port))
        )
    if cve:
        query = query.where(
            Asset.id.in_(
                select(Vulnerability.asset_id).where(Vulnerability.cve_id == cve.upper())
            )
        )
    if finding_rule:
        query = query.where(
            Asset.id.in_(select(Finding.asset_id).where(Finding.rule_id == finding_rule))
        )

    return list(
        db.scalars(
            query.order_by(desc(Asset.risk_score)).limit(limit).offset(offset)
        ).all()
    )


@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(
    asset_id: int, db: DbSession, _: Annotated[User, Depends(require("asset:read"))]
) -> Asset:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found.")
    return asset


@router.get("/{asset_id}/findings", response_model=list[FindingOut])
def asset_findings(
    asset_id: int, db: DbSession, _: Annotated[User, Depends(require("asset:read"))]
) -> list[Finding]:
    return list(
        db.scalars(
            select(Finding)
            .where(Finding.asset_id == asset_id)
            .order_by(desc(Finding.risk_score))
        ).all()
    )


@router.get("/{asset_id}/ports", response_model=list[NetworkPortOut])
def asset_ports(
    asset_id: int, db: DbSession, _: Annotated[User, Depends(require("asset:read"))]
) -> list[NetworkPort]:
    return list(
        db.scalars(
            select(NetworkPort)
            .where(NetworkPort.asset_id == asset_id)
            .order_by(NetworkPort.port)
        ).all()
    )


@router.patch("/{asset_id}/criticality", response_model=AssetOut)
def set_criticality(
    asset_id: int,
    criticality: str,
    db: DbSession,
    user: Annotated[User, Depends(require("target:create"))],
) -> Asset:
    """Asset importance feeds directly into the VulScanner risk score."""
    if criticality not in ("critical", "high", "normal", "low"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Criticality must be one of: critical, high, normal, low.",
        )
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found.")
    asset.criticality = criticality
    db.commit()
    db.refresh(asset)
    audit_service.record(
        db,
        AuditAction.USER_UPDATED,
        actor_id=user.id,
        actor_name=user.username,
        entity_type="asset",
        entity_id=asset.asset_uid,
        message=f"Asset criticality set to {criticality}.",
    )
    return asset


# ---------------------------------------------------------------------------
# Authorized targets
# ---------------------------------------------------------------------------
@targets_router.get("", response_model=list[TargetOut])
def list_targets(
    db: DbSession, _: Annotated[User, Depends(require("target:read"))]
) -> list[Target]:
    return list(db.scalars(select(Target).order_by(Target.name)).all())


@targets_router.post("", response_model=TargetOut, status_code=status.HTTP_201_CREATED)
def create_target(
    payload: TargetCreate,
    db: DbSession,
    user: Annotated[User, Depends(require("target:create"))],
) -> Target:
    """Register a target and attest that assessing it is authorized."""
    from datetime import datetime, timezone

    from app.core.permissions import classify_target

    if db.scalar(select(Target).where(Target.value == payload.value)):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A target with that value already exists.",
        )
    if payload.authorized and not payload.authorization_note.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "An authorization note is required when marking a target as "
                "authorized. Record who granted permission and when."
            ),
        )

    target = Target(
        name=payload.name or payload.value,
        target_type=classify_target(payload.value),
        value=payload.value,
        description=payload.description,
        authorized=payload.authorized,
        authorization_note=payload.authorization_note,
        authorized_by_id=user.id if payload.authorized else None,
        authorized_at=datetime.now(tz=timezone.utc) if payload.authorized else None,
        criticality=payload.criticality,
    )
    db.add(target)
    db.commit()
    db.refresh(target)

    audit_service.record(
        db,
        AuditAction.TARGET_ADDED,
        actor_id=user.id,
        actor_name=user.username,
        entity_type="target",
        entity_id=target.id,
        message=(
            f"Target {target.value} registered"
            + (" and attested as authorized." if target.authorized else ".")
        ),
        details={
            "authorization_note": target.authorization_note,
            "criticality": target.criticality,
        },
    )
    return target


@targets_router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def delete_target(
    target_id: int,
    db: DbSession,
    user: Annotated[User, Depends(require("target:delete"))],
) -> None:
    target = db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found.")
    value = target.value
    db.delete(target)
    db.commit()
    audit_service.record(
        db,
        AuditAction.TARGET_DELETED,
        actor_id=user.id,
        actor_name=user.username,
        entity_type="target",
        entity_id=target_id,
        message=f"Target {value} removed.",
    )
