"""Audit logging helper.

Callers pass descriptive metadata only. Credentials, tokens and secret values
must never be handed to this module.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.logging import get_logger, redact
from app.models.audit import AuditAction, AuditLog

logger = get_logger(__name__)

# Keys that are dropped from ``details`` before persisting, as a safety net.
FORBIDDEN_KEYS = {
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "credential", "credentials", "authorization", "private_key", "hash",
}


def _sanitize(details: dict | None) -> dict:
    if not details:
        return {}
    clean: dict = {}
    for key, value in details.items():
        if str(key).lower() in FORBIDDEN_KEYS:
            clean[key] = "[REDACTED]"
        elif isinstance(value, str):
            clean[key] = redact(value)
        elif isinstance(value, dict):
            clean[key] = _sanitize(value)
        else:
            clean[key] = value
    return clean


def record(
    db: Session,
    action: AuditAction | str,
    *,
    actor_id: int | None = None,
    actor_name: str = "system",
    outcome: str = "success",
    entity_type: str | None = None,
    entity_id: str | int | None = None,
    message: str = "",
    details: dict | None = None,
    source_ip: str | None = None,
    commit: bool = True,
) -> AuditLog:
    entry = AuditLog(
        action=action.value if isinstance(action, AuditAction) else str(action),
        outcome=outcome,
        actor_id=actor_id,
        actor_name=actor_name or "system",
        source_ip=source_ip,
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id is not None else None,
        message=redact(message),
        details=_sanitize(details),
    )
    db.add(entry)
    if commit:
        db.commit()
    logger.info(
        "audit action=%s actor=%s entity=%s:%s outcome=%s",
        entry.action, entry.actor_name, entity_type, entity_id, outcome,
    )
    return entry
