"""Test fixtures.

Tests run against an in-memory database and mock collector data, so the suite
passes on any platform and never needs an actually vulnerable machine. The
mock data is clearly labelled as such and is never used by the application at
runtime - see ``tests/mock_data.py``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

# Configure the environment before app.core.config is imported anywhere.
os.environ.setdefault("VULSCANNER_ENV", "test")
os.environ.setdefault("VULSCANNER_SECRET_KEY", "test-only-secret-key-not-for-production")
os.environ.setdefault("VULSCANNER_CVE_ONLINE", "false")
os.environ.setdefault("VULSCANNER_BOOTSTRAP_ADMIN_PASSWORD", "TestAdminPass!2026")


@pytest.fixture(scope="session")
def engine(tmp_path_factory):
    from sqlalchemy import create_engine

    from app.db.base import Base

    import app.models  # noqa: F401  (importing the package registers every table)

    path = tmp_path_factory.mktemp("db") / "vulscanner-test.db"
    engine = create_engine(
        f"sqlite:///{path.as_posix()}", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def db(engine):
    """A session wrapped in a transaction that is rolled back after each test."""
    from sqlalchemy.orm import Session

    connection = engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection)
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture
def api_client(engine, monkeypatch):
    """FastAPI test client bound to the test database with an admin session."""
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker

    import app.db.session as session_module

    TestSession = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(session_module, "SessionLocal", TestSession)
    monkeypatch.setattr(session_module, "engine", engine)

    from app.core.security import api_limiter, hash_password, login_limiter, scan_limiter
    from app.db.init_db import seed_roles
    from app.main import app
    from app.models.user import User

    # Rate limiters are per-process, so a test run would otherwise trip its own
    # login throttle after ten cases.
    for limiter in (login_limiter, api_limiter, scan_limiter):
        limiter.reset()

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[session_module.get_db] = override_get_db

    setup = TestSession()
    seed_roles(setup)
    if not setup.query(User).filter_by(username="tester").first():
        setup.add(
            User(
                username="tester",
                password_hash=hash_password("TestAdminPass!2026"),
                role="administrator",
            )
        )
        setup.commit()
    setup.close()

    with TestClient(app) as client:
        response = client.post(
            "/api/auth/login",
            json={"username": "tester", "password": "TestAdminPass!2026"},
        )
        token = response.json()["access_token"]
        client.headers.update({"Authorization": f"Bearer {token}"})
        yield client

    app.dependency_overrides.clear()


@pytest.fixture
def mock_scan_output():
    """A ScanOutput assembled from mock collector data."""
    from tests.mock_data import build_mock_scan_output

    return build_mock_scan_output()
