"""VulScanner API application.

Run with:
    uvicorn app.main:app --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import platform
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import assets, auth, dashboard, findings, network, reports, scans, vulnerabilities
from app.api.deps import rate_limit
from app.core.config import APP_DESCRIPTION, APP_TITLE, APP_VERSION, settings
from app.core.logging import configure_logging, get_logger
from app.core.permissions import AuthorizationError
from app.db.init_db import init_db
from app.scanner.runner import find_powershell

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    logger.info("Starting VulScanner API %s (%s)", APP_VERSION, settings.env)

    generated_password = init_db()
    if generated_password:
        # Printed once, never logged, never stored in plaintext.
        print("\n" + "=" * 68)
        print("  VulScanner bootstrap administrator created")
        print(f"    username: {settings.bootstrap_admin_username}")
        print(f"    password: {generated_password}")
        print("  Store this now - it cannot be recovered. Change it after login.")
        print("=" * 68 + "\n")

    if platform.system() != "Windows":
        logger.warning(
            "VulScanner is running on %s. Windows collectors will be skipped; "
            "network assessment remains available.",
            platform.system(),
        )
    elif not find_powershell():
        logger.error("PowerShell was not found. Windows collection is unavailable.")

    yield
    logger.info("VulScanner API shutting down")


app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    contact={"name": "VulScanner"},
    license_info={"name": "MIT"},
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if settings.is_production:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    # The API serves JSON and generated reports only.
    response.headers.setdefault(
        "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"
    )
    return response


@app.exception_handler(AuthorizationError)
async def authorization_error_handler(
    request: Request, exc: AuthorizationError
) -> JSONResponse:
    """A target outside the authorized scope is refused, not attempted."""
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={
            "detail": str(exc),
            "error": "target_not_authorized",
            "guidance": (
                "VulScanner only assesses targets inside a configured authorized "
                "scope. Add the target to VULSCANNER_AUTHORIZED_SCOPES, or register "
                "it via POST /api/targets with an authorization attestation."
            ),
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "Request validation failed.", "errors": exc.errors()},
    )


# Routers. Rate limiting is applied to every API route.
limited = [Depends(rate_limit)]
app.include_router(auth.router, dependencies=limited)
app.include_router(scans.router, dependencies=limited)
app.include_router(assets.router, dependencies=limited)
app.include_router(assets.targets_router, dependencies=limited)
app.include_router(findings.router, dependencies=limited)
app.include_router(vulnerabilities.router, dependencies=limited)
app.include_router(vulnerabilities.patches_router, dependencies=limited)
app.include_router(network.router, dependencies=limited)
app.include_router(reports.router, dependencies=limited)
app.include_router(dashboard.router, dependencies=limited)
app.include_router(dashboard.audit_router, dependencies=limited)


@app.get("/api/health", tags=["System"])
def health() -> dict:
    """Liveness and capability probe."""
    return {
        "status": "ok",
        "product": "VulScanner",
        "version": APP_VERSION,
        "environment": settings.env,
        "platform": platform.system(),
        "windows_collection_available": platform.system() == "Windows"
        and bool(find_powershell()),
        "authorized_scopes": settings.authorized_scopes,
    }


@app.get("/api", tags=["System"])
def api_root() -> dict:
    return {
        "product": "VulScanner",
        "description": (
            "Agent-less Windows vulnerability, security posture and network "
            "assessment platform. For authorized defensive assessment only."
        ),
        "version": APP_VERSION,
        "documentation": {"swagger": "/api/docs", "redoc": "/api/redoc"},
        "endpoints": [
            "/api/auth/login", "/api/scans", "/api/assets", "/api/findings",
            "/api/vulnerabilities", "/api/patches", "/api/network/topology",
            "/api/reports", "/api/dashboard", "/api/audit", "/api/targets",
        ],
    }
