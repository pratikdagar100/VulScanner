"""Scan endpoints, including live progress over SSE and WebSocket."""

from __future__ import annotations

import asyncio
import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import StreamingResponse
from sqlalchemy import desc, func, select

from app.api.deps import CurrentUser, DbSession, client_ip, pagination, require
from app.core.permissions import AuthorizationError
from app.core.security import scan_limiter
from app.models.audit import AuditAction
from app.models.scan import Scan, ScanResult, ScanStatus, TERMINAL_STATUSES
from app.models.user import User
from app.scanner.registry import PROFILE_DESCRIPTIONS, collectors_for_profile, describe_collectors
from app.scanner.runner import RemoteCredential
from app.schemas.common import CollectorInfo, ScanProfileInfo
from app.schemas.scan import ScanCreate, ScanDetail, ScanOut
from app.services import audit_service
from app.services.scan_service import progress_broker, scan_service

router = APIRouter(prefix="/api/scans", tags=["Scans"])


@router.get("/profiles", response_model=list[ScanProfileInfo])
def list_profiles() -> list[ScanProfileInfo]:
    """Available scan profiles and the collectors each one runs."""
    return [
        ScanProfileInfo(
            name=name,
            description=description,
            collectors=[c.name for c in collectors_for_profile(name)],
        )
        for name, description in PROFILE_DESCRIPTIONS.items()
    ]


@router.get("/collectors", response_model=list[CollectorInfo])
def list_collectors() -> list[dict]:
    return describe_collectors()


@router.post("", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
def create_scan(
    payload: ScanCreate,
    request: Request,
    db: DbSession,
    user: Annotated[User, Depends(require("scan:create"))],
) -> Scan:
    """Queue a scan against an authorized target."""
    source = client_ip(request)
    if not scan_limiter.check(source):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many scans requested. Wait before starting another.",
        )

    options = payload.options.model_dump()
    try:
        scan = scan_service.create_scan(
            db,
            name=payload.name,
            target=payload.target,
            profile=payload.profile.value,
            options=options,
            user_id=user.id,
            actor_name=user.username,
        )
    except AuthorizationError as exc:
        # Refusing an unauthorized target is a product boundary, not an error.
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    credential = None
    if payload.credential:
        credential = RemoteCredential(
            username=payload.credential.username,
            password=payload.credential.password,
            auth=payload.credential.auth,
            port=payload.credential.port,
            use_ssl=payload.credential.use_ssl,
        )

    scan_service.submit(scan.id, credential)
    return scan


@router.get("", response_model=list[ScanOut])
def list_scans(
    db: DbSession,
    _: Annotated[User, Depends(require("scan:read"))],
    page: Annotated[tuple[int, int], Depends(pagination)],
    status_filter: str | None = Query(default=None, alias="status"),
    target: str | None = None,
) -> list[Scan]:
    limit, offset = page
    query = select(Scan).order_by(desc(Scan.created_at))
    if status_filter:
        query = query.where(Scan.status == status_filter)
    if target:
        query = query.where(Scan.target.contains(target))
    return list(db.scalars(query.limit(limit).offset(offset)).all())


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(
    scan_id: int, db: DbSession, _: Annotated[User, Depends(require("scan:read"))]
) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


@router.get("/{scan_id}/results")
def get_scan_results(
    scan_id: int,
    db: DbSession,
    _: Annotated[User, Depends(require("scan:read"))],
    collector: str | None = None,
) -> list[dict]:
    """Raw normalized collector output - the evidence behind every finding."""
    query = select(ScanResult).where(ScanResult.scan_id == scan_id)
    if collector:
        query = query.where(ScanResult.collector == collector)
    results = db.scalars(query).all()
    if not results and db.get(Scan, scan_id) is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return [
        {
            "collector": r.collector,
            "category": r.category,
            "status": r.status,
            "collection_method": r.collection_method,
            "collected_at": r.collected_at,
            "duration_seconds": r.duration_seconds,
            "warnings": r.warnings,
            "errors": r.errors,
            "data": r.data,
        }
        for r in results
    ]


@router.post("/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(
    scan_id: int,
    db: DbSession,
    user: Annotated[User, Depends(require("scan:cancel"))],
) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if scan.status in {s.value for s in TERMINAL_STATUSES}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan is already {scan.status}.",
        )

    cancelled = scan_service.cancel(scan_id)
    if not cancelled and scan.status == ScanStatus.QUEUED.value:
        scan.status = ScanStatus.CANCELLED.value
        db.commit()

    audit_service.record(
        db,
        AuditAction.SCAN_CANCELLED,
        actor_id=user.id,
        actor_name=user.username,
        entity_type="scan",
        entity_id=scan_id,
        message="Scan cancellation requested.",
    )
    db.refresh(scan)
    return scan


@router.get("/{scan_id}/progress")
def scan_progress(
    scan_id: int, db: DbSession, _: Annotated[User, Depends(require("scan:read"))]
) -> dict:
    """Latest progress snapshot (polling fallback for SSE/WebSocket)."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    latest = progress_broker.latest(scan_id) or {}
    return {
        "scan_id": scan_id,
        "status": scan.status,
        "progress": scan.progress,
        "stage": scan.current_stage,
        "stages": scan.stages,
        "message": latest.get("message", ""),
        "timestamp": latest.get("timestamp"),
    }


@router.get("/{scan_id}/stream")
async def stream_progress(
    scan_id: int, db: DbSession, _: Annotated[User, Depends(require("scan:read"))]
) -> StreamingResponse:
    """Server-Sent Events stream of live scan progress."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")

    queue: asyncio.Queue = asyncio.Queue(maxsize=128)
    loop = asyncio.get_running_loop()

    def on_event(event: dict) -> None:
        loop.call_soon_threadsafe(queue.put_nowait, event)

    progress_broker.subscribe(scan_id, on_event)

    async def generator():
        try:
            snapshot = progress_broker.latest(scan_id) or {
                "scan_id": scan_id,
                "stage": scan.current_stage,
                "progress": scan.progress,
                "status": scan.status,
                "message": "Current state",
            }
            yield f"data: {json.dumps(snapshot, default=str)}\n\n"

            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=20.0)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                yield f"data: {json.dumps(event, default=str)}\n\n"
                if event.get("status") in {s.value for s in TERMINAL_STATUSES} or (
                    event.get("stage") == "complete"
                ):
                    break
        finally:
            progress_broker.unsubscribe(scan_id, on_event)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.websocket("/{scan_id}/ws")
async def websocket_progress(websocket: WebSocket, scan_id: int) -> None:
    """WebSocket stream of live scan progress.

    The access token is passed as a query parameter because browsers cannot set
    headers on a WebSocket handshake.
    """
    from app.core.security import TokenError, decode_token

    token = websocket.query_params.get("token", "")
    try:
        decode_token(token, expected_type="access")
    except TokenError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    queue: asyncio.Queue = asyncio.Queue(maxsize=128)
    loop = asyncio.get_running_loop()

    def on_event(event: dict) -> None:
        loop.call_soon_threadsafe(queue.put_nowait, event)

    progress_broker.subscribe(scan_id, on_event)
    try:
        snapshot = progress_broker.latest(scan_id)
        if snapshot:
            await websocket.send_json(snapshot)
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=20.0)
            except asyncio.TimeoutError:
                await websocket.send_json({"scan_id": scan_id, "stage": "keep-alive"})
                continue
            await websocket.send_json(event)
            if event.get("stage") in ("complete", "failed", "cancelled"):
                break
    except WebSocketDisconnect:
        pass
    finally:
        progress_broker.unsubscribe(scan_id, on_event)


@router.get("/{scan_id}/stages")
def scan_stages(
    scan_id: int, db: DbSession, _: Annotated[User, Depends(require("scan:read"))]
) -> list[dict]:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan.stages or []


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def delete_scan(
    scan_id: int,
    db: DbSession,
    user: Annotated[User, Depends(require("target:delete"))],
) -> None:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if scan_service.is_running(scan_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cancel the scan before deleting it.",
        )
    db.delete(scan)
    db.commit()
    audit_service.record(
        db,
        "scan_deleted",
        actor_id=user.id,
        actor_name=user.username,
        entity_type="scan",
        entity_id=scan_id,
        message=f"Scan #{scan_id} deleted.",
    )
