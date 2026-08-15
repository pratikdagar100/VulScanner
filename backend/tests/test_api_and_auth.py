"""API, authentication, RBAC and authorization-boundary tests."""

from __future__ import annotations

import pytest

from app.core.permissions import (
    AuthorizationError,
    Role,
    authorize_target,
    classify_target,
    has_permission,
    role_satisfies,
)
from app.core.security import (
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    password_problems,
    verify_password,
)


class TestPasswordHashing:
    def test_round_trip(self):
        hashed = hash_password("CorrectHorse!2026")
        assert hashed != "CorrectHorse!2026"
        assert verify_password("CorrectHorse!2026", hashed)

    def test_wrong_password_rejected(self):
        assert not verify_password("wrong", hash_password("CorrectHorse!2026"))

    def test_malformed_hash_does_not_raise(self):
        assert verify_password("anything", "not-a-bcrypt-hash") is False

    def test_salted(self):
        assert hash_password("Same!Password1") != hash_password("Same!Password1")

    def test_over_length_password_rejected(self):
        with pytest.raises(ValueError):
            hash_password("a" * 100)

    def test_policy(self):
        assert password_problems("Str0ng!Passphrase") == []
        assert password_problems("short") != []
        assert any("uppercase" in p for p in password_problems("alllower1!aaaa"))


class TestTokens:
    def test_access_token_round_trip(self):
        claims = decode_token(create_access_token("alice", "analyst", 7))
        assert claims["sub"] == "alice"
        assert claims["role"] == "analyst"
        assert claims["uid"] == 7

    def test_refresh_token_is_not_an_access_token(self):
        with pytest.raises(TokenError):
            decode_token(create_refresh_token("alice", 7), expected_type="access")

    def test_tampered_token_rejected(self):
        token = create_access_token("alice", "viewer", 1)
        with pytest.raises(TokenError):
            decode_token(token[:-4] + "AAAA")

    def test_garbage_rejected(self):
        with pytest.raises(TokenError):
            decode_token("not.a.token")


class TestRBAC:
    def test_role_hierarchy(self):
        assert role_satisfies(Role.ADMINISTRATOR, Role.VIEWER)
        assert role_satisfies(Role.ANALYST, Role.VIEWER)
        assert not role_satisfies(Role.VIEWER, Role.ANALYST)

    def test_capability_matrix(self):
        assert has_permission(Role.VIEWER, "finding:read")
        assert not has_permission(Role.VIEWER, "scan:create")
        assert has_permission(Role.ANALYST, "scan:create")
        assert not has_permission(Role.ANALYST, "finding:accept_risk")
        assert has_permission(Role.ADMINISTRATOR, "finding:accept_risk")

    def test_unknown_permission_defaults_to_administrator(self):
        assert not has_permission(Role.ANALYST, "totally:unknown")
        assert has_permission(Role.ADMINISTRATOR, "totally:unknown")


class TestTargetAuthorization:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("local", "local"),
            ("localhost", "local"),
            ("192.168.1.10", "ip"),
            ("192.168.1.0/24", "cidr"),
            ("server01.example.com", "hostname"),
        ],
    )
    def test_classification(self, value, expected):
        assert classify_target(value) == expected

    def test_local_is_always_authorized(self):
        assert authorize_target("local").kind == "local"

    def test_in_scope_address_allowed(self):
        result = authorize_target("192.168.1.25")
        assert result.kind == "ip"
        assert result.matched_scope

    def test_out_of_scope_address_refused(self):
        with pytest.raises(AuthorizationError) as exc:
            authorize_target("8.8.8.8")
        assert "not inside an authorized scope" in str(exc.value)

    def test_out_of_scope_network_refused(self):
        with pytest.raises(AuthorizationError):
            authorize_target("203.0.113.0/24")

    def test_network_wider_than_the_scope_is_refused(self):
        # 192.168.0.0/15 extends past the authorized 192.168.0.0/16.
        with pytest.raises(AuthorizationError):
            authorize_target("192.168.0.0/15")

    def test_extra_authorized_scope_extends_permission(self):
        result = authorize_target("203.0.113.5", extra_authorized=["203.0.113.0/24"])
        assert result.matched_scope == "203.0.113.0/24"

    def test_empty_target_refused(self):
        with pytest.raises(AuthorizationError):
            authorize_target("")


class TestApiEndpoints:
    def test_health_is_public(self, api_client):
        api_client.headers.pop("Authorization", None)
        response = api_client.get("/api/health")
        assert response.status_code == 200
        assert response.json()["product"] == "VulScanner"

    def test_authentication_required(self, api_client):
        headers = dict(api_client.headers)
        api_client.headers.pop("Authorization", None)
        assert api_client.get("/api/findings").status_code == 401
        api_client.headers.update(headers)

    def test_invalid_credentials_rejected(self, api_client):
        response = api_client.post(
            "/api/auth/login", json={"username": "tester", "password": "nope"}
        )
        assert response.status_code == 401

    def test_me_returns_the_session_user(self, api_client):
        response = api_client.get("/api/auth/me")
        assert response.status_code == 200
        assert response.json()["username"] == "tester"

    @pytest.mark.parametrize(
        "path",
        [
            "/api/dashboard", "/api/scans", "/api/assets", "/api/findings",
            "/api/vulnerabilities", "/api/patches", "/api/network/topology",
            "/api/network/ports", "/api/network/hosts", "/api/reports",
            "/api/audit", "/api/targets", "/api/scans/profiles",
            "/api/scans/collectors", "/api/findings/summary",
            "/api/findings/remediation", "/api/vulnerabilities/intelligence",
        ],
    )
    def test_endpoint_responds(self, api_client, path):
        assert api_client.get(path).status_code == 200

    def test_openapi_documents_every_router(self, api_client):
        paths = api_client.get("/api/openapi.json").json()["paths"]
        for expected in (
            "/api/scans", "/api/assets", "/api/findings", "/api/vulnerabilities",
            "/api/network/topology", "/api/reports",
        ):
            assert expected in paths

    def test_unauthorized_target_is_refused_not_scanned(self, api_client):
        response = api_client.post(
            "/api/scans", json={"target": "8.8.8.8", "profile": "quick"}
        )
        assert response.status_code == 403
        assert "authorized scope" in response.json()["detail"]

    def test_scan_creation_validates_the_profile(self, api_client):
        response = api_client.post(
            "/api/scans", json={"target": "local", "profile": "not-a-profile"}
        )
        assert response.status_code == 422

    def test_target_registration_requires_an_authorization_note(self, api_client):
        response = api_client.post(
            "/api/targets",
            json={"name": "Lab", "value": "10.90.0.0/24", "authorized": True},
        )
        assert response.status_code == 400
        assert "authorization note" in response.json()["detail"].lower()

    def test_security_headers_are_present(self, api_client):
        headers = api_client.get("/api/health").headers
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"
        assert "Content-Security-Policy" in headers

    def test_audit_log_records_the_login(self, api_client):
        entries = api_client.get("/api/audit", params={"action": "login"}).json()
        assert any(entry["actor_name"] == "tester" for entry in entries)

    def test_audit_log_never_contains_a_password(self, api_client):
        body = api_client.get("/api/audit").text
        assert "TestAdminPass" not in body


class TestSettingsParsing:
    """Comma-separated list settings must survive a real .env file.

    pydantic-settings JSON-decodes complex fields read from a dotenv source
    before validators run, which previously made a plain comma-separated
    VULSCANNER_CORS_ORIGINS crash startup. NoDecode keeps the raw string.
    """

    def _load(self, tmp_path, monkeypatch, body: str):
        from pydantic_settings import SettingsConfigDict

        from app.core.config import Settings

        env_file = tmp_path / ".env"
        env_file.write_text(body, encoding="utf-8")
        # Environment variables outrank the dotenv file, so clear them first.
        for name in ("VULSCANNER_CORS_ORIGINS", "VULSCANNER_AUTHORIZED_SCOPES"):
            monkeypatch.delenv(name, raising=False)

        class FileSettings(Settings):
            model_config = SettingsConfigDict(
                env_prefix="VULSCANNER_", env_file=env_file, extra="ignore"
            )

        return FileSettings()

    def test_comma_separated_values_parse(self, tmp_path, monkeypatch):
        settings = self._load(
            tmp_path,
            monkeypatch,
            "VULSCANNER_CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173\n"
            "VULSCANNER_AUTHORIZED_SCOPES=10.0.0.0/8,192.168.1.0/24\n",
        )
        assert settings.cors_origins == [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ]
        assert settings.authorized_scopes == ["10.0.0.0/8", "192.168.1.0/24"]

    def test_single_value_parses(self, tmp_path, monkeypatch):
        settings = self._load(
            tmp_path, monkeypatch, "VULSCANNER_AUTHORIZED_SCOPES=192.168.1.0/24\n"
        )
        assert settings.authorized_scopes == ["192.168.1.0/24"]

    def test_whitespace_is_trimmed(self, tmp_path, monkeypatch):
        settings = self._load(
            tmp_path, monkeypatch, "VULSCANNER_AUTHORIZED_SCOPES= 10.0.0.0/8 , 172.16.0.0/12 \n"
        )
        assert settings.authorized_scopes == ["10.0.0.0/8", "172.16.0.0/12"]


    def test_relative_sqlite_path_is_anchored_to_the_repo_root(self):
        """A relative SQLite URL must not depend on the working directory.

        The API launched from backend/ and the CLI launched from the repo root
        would otherwise open two different databases, and alembic would migrate
        whichever file sat next to the shell.
        """
        from app.core.config import REPO_ROOT, _resolve_sqlite_url

        resolved = _resolve_sqlite_url("sqlite:///./vulscanner.db")
        assert resolved.startswith("sqlite:///")
        assert REPO_ROOT.as_posix() in resolved
        # Bare relative form resolves to the same file as the ./ form.
        assert _resolve_sqlite_url("sqlite:///vulscanner.db") == resolved

    @pytest.mark.parametrize(
        "url",
        [
            "postgresql+psycopg://user:pass@localhost:5432/vulscanner",
            "sqlite:///:memory:",
            "sqlite:////var/lib/vulscanner/data.db",
            "sqlite:///C:/data/vulscanner.db",
        ],
    )
    def test_absolute_and_non_sqlite_urls_are_untouched(self, url):
        from app.core.config import _resolve_sqlite_url

        assert _resolve_sqlite_url(url) == url

    def test_defaults_apply_when_absent(self, tmp_path, monkeypatch):
        settings = self._load(tmp_path, monkeypatch, "VULSCANNER_LOG_LEVEL=INFO\n")
        assert "127.0.0.0/8" in settings.authorized_scopes
        assert settings.cors_origins
