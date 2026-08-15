"""VulScanner configuration.

All settings are environment driven. Secrets are never hard-coded; the
application refuses to start in production without an explicit secret key.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

APP_NAME = "VulScanner"
APP_TITLE = "VulScanner API"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = (
    "VulScanner - agent-less Windows vulnerability, security posture and "
    "network assessment platform. For authorized defensive assessment only."
)

# repo_root/backend/app/core/config.py -> repo_root
REPO_ROOT = Path(__file__).resolve().parents[3]


def _split_csv(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [part.strip() for part in str(value).split(",") if part.strip()]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="VULSCANNER_",
        env_file=(REPO_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- application ------------------------------------------------------
    env: str = "development"
    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "INFO"
    log_dir: Path = REPO_ROOT / "logs"

    # --- security ---------------------------------------------------------
    secret_key: str = ""
    access_token_minutes: int = 60
    refresh_token_days: int = 7
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = ""

    # --- database ---------------------------------------------------------
    database_url: str = f"sqlite:///{(REPO_ROOT / 'vulscanner.db').as_posix()}"

    # --- cors -------------------------------------------------------------
    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"]
    )

    # --- scanning ---------------------------------------------------------
    authorized_scopes: list[str] = Field(
        default_factory=lambda: [
            "127.0.0.0/8",
            "192.168.0.0/16",
            "10.0.0.0/8",
            "172.16.0.0/12",
        ]
    )
    max_concurrent_scans: int = 2
    collector_timeout: int = 120
    discovery_concurrency: int = 64
    portscan_concurrency: int = 256
    portscan_timeout: float = 0.7

    fs_max_files: int = 5000
    fs_max_depth: int = 4
    fs_hash: bool = False

    # --- vulnerability intelligence --------------------------------------
    nvd_api_key: str = ""
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )
    cve_cache_dir: Path = REPO_ROOT / "cache" / "cve"
    cve_cache_ttl_hours: int = 24
    cve_online: bool = True

    # --- reports ----------------------------------------------------------
    report_dir: Path = REPO_ROOT / "reports" / "generated"

    # --- remote -----------------------------------------------------------
    winrm_default_port: int = 5985

    @field_validator("cors_origins", "authorized_scopes", mode="before")
    @classmethod
    def _parse_csv(cls, value: object) -> list[str]:
        return _split_csv(value)

    @field_validator("log_level", mode="before")
    @classmethod
    def _upper(cls, value: object) -> str:
        return str(value).upper()

    @property
    def is_production(self) -> bool:
        return self.env.lower() in {"production", "prod"}

    @property
    def powershell_dir(self) -> Path:
        return REPO_ROOT / "backend" / "powershell"

    @property
    def report_template_dir(self) -> Path:
        return REPO_ROOT / "reports" / "templates"

    def resolved_secret_key(self) -> str:
        """Return the signing key, failing closed in production."""
        if self.secret_key:
            return self.secret_key
        if self.is_production:
            raise RuntimeError(
                "VULSCANNER_SECRET_KEY must be set in production. Generate one with:"
                '  python -c "import secrets; print(secrets.token_urlsafe(64))"'
            )
        # Development only: ephemeral key, tokens do not survive a restart.
        self.secret_key = secrets.token_urlsafe(64)
        return self.secret_key

    def ensure_directories(self) -> None:
        for path in (self.log_dir, self.cve_cache_dir, self.report_dir):
            Path(path).mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_directories()
    return settings


settings = get_settings()
