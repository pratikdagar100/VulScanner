"""Database bootstrap: create tables and seed roles / the initial admin user."""

from __future__ import annotations

import secrets

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.core.permissions import Role as RoleEnum
from app.core.security import hash_password
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.models import Role, User  # noqa: F401  (registers all tables)

logger = get_logger(__name__)

ROLE_DESCRIPTIONS = {
    RoleEnum.ADMINISTRATOR.value: (
        "Full control: user management, target authorization, risk acceptance, "
        "audit log access and all scanning operations."
    ),
    RoleEnum.ANALYST.value: (
        "Runs scans, triages findings and generates reports. Cannot manage users "
        "or accept risk."
    ),
    RoleEnum.VIEWER.value: (
        "Read-only access to dashboards, assets, findings and reports."
    ),
}


def create_tables() -> None:
    Base.metadata.create_all(bind=engine)


def seed_roles(db: Session) -> None:
    existing = {row.name for row in db.scalars(select(Role)).all()}
    for name, description in ROLE_DESCRIPTIONS.items():
        if name not in existing:
            db.add(Role(name=name, description=description))
    db.commit()


def seed_admin(db: Session) -> str | None:
    """Create the bootstrap administrator if no users exist.

    Returns a generated password when one had to be invented, so the caller can
    display it exactly once. Returns ``None`` when nothing was created.
    """
    if db.scalar(select(User).limit(1)) is not None:
        return None

    username = settings.bootstrap_admin_username or "admin"
    password = settings.bootstrap_admin_password
    generated = None
    if not password:
        if settings.is_production:
            logger.warning(
                "No bootstrap admin password configured; no administrator was "
                "created. Create one with: python -m app.cli_admin create-user"
            )
            return None
        password = secrets.token_urlsafe(18)
        generated = password

    role = db.scalar(select(Role).where(Role.name == RoleEnum.ADMINISTRATOR.value))
    user = User(
        username=username,
        password_hash=hash_password(password),
        role=RoleEnum.ADMINISTRATOR.value,
        role_id=role.id if role else None,
        full_name="VulScanner Administrator",
        must_change_password=generated is not None,
    )
    db.add(user)
    db.commit()
    logger.info("Bootstrap administrator '%s' created", username)
    return generated


def init_db() -> str | None:
    create_tables()
    db = SessionLocal()
    try:
        seed_roles(db)
        return seed_admin(db)
    finally:
        db.close()


if __name__ == "__main__":  # pragma: no cover
    password = init_db()
    if password:
        print(f"Bootstrap administrator created.")
        print(f"  username: {settings.bootstrap_admin_username}")
        print(f"  password: {password}")
        print("Store this password now - it is not recoverable.")
    else:
        print("Database initialized.")
