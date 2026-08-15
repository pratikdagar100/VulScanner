"""Password hashing, JWT issuance/verification and rate limiting."""

from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt

from app.core.config import settings

ALGORITHM = "HS256"
BCRYPT_ROUNDS = 12


# --------------------------------------------------------------------------
# Passwords
# --------------------------------------------------------------------------
def hash_password(password: str) -> str:
    # bcrypt silently truncates beyond 72 bytes; reject rather than mislead.
    encoded = password.encode("utf-8")
    if len(encoded) > 72:
        raise ValueError("Password exceeds the 72 byte bcrypt limit")
    return bcrypt.hashpw(encoded, bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("ascii")


def verify_password(plain: str, hashed: str) -> bool:
    """Constant-time password check that never raises on malformed input."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8")[:72], hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def password_problems(password: str) -> list[str]:
    """Return a list of policy violations (empty list means acceptable)."""
    problems: list[str] = []
    if len(password) < 12:
        problems.append("Password must be at least 12 characters long.")
    if not any(c.islower() for c in password):
        problems.append("Password must contain a lowercase letter.")
    if not any(c.isupper() for c in password):
        problems.append("Password must contain an uppercase letter.")
    if not any(c.isdigit() for c in password):
        problems.append("Password must contain a digit.")
    if not any(not c.isalnum() for c in password):
        problems.append("Password must contain a symbol.")
    return problems


# --------------------------------------------------------------------------
# Tokens
# --------------------------------------------------------------------------
def _encode(claims: dict[str, Any], expires: timedelta, token_type: str) -> str:
    now = datetime.now(tz=timezone.utc)
    payload = {
        **claims,
        "iat": now,
        "nbf": now,
        "exp": now + expires,
        "jti": uuid.uuid4().hex,
        "typ": token_type,
        "iss": "vulscanner",
    }
    return jwt.encode(payload, settings.resolved_secret_key(), algorithm=ALGORITHM)


def create_access_token(subject: str, role: str, user_id: int) -> str:
    return _encode(
        {"sub": subject, "role": role, "uid": user_id},
        timedelta(minutes=settings.access_token_minutes),
        "access",
    )


def create_refresh_token(subject: str, user_id: int) -> str:
    return _encode(
        {"sub": subject, "uid": user_id},
        timedelta(days=settings.refresh_token_days),
        "refresh",
    )


class TokenError(Exception):
    """Raised when a token is missing, malformed, expired or of the wrong type."""


def decode_token(token: str, expected_type: str = "access") -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            settings.resolved_secret_key(),
            algorithms=[ALGORITHM],
            issuer="vulscanner",
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("Token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("Token is invalid") from exc
    if payload.get("typ") != expected_type:
        raise TokenError(f"Expected a {expected_type} token")
    return payload


# --------------------------------------------------------------------------
# Rate limiting (in-process sliding window; sufficient for a single node)
# --------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, limit: int, window_seconds: float) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> bool:
        """Record a hit. Returns False when the caller is over the limit."""
        now = time.monotonic()
        bucket = self._hits[key]
        while bucket and now - bucket[0] > self.window:
            bucket.popleft()
        if len(bucket) >= self.limit:
            return False
        bucket.append(now)
        return True

    def retry_after(self, key: str) -> int:
        bucket = self._hits.get(key)
        if not bucket:
            return 0
        return max(1, int(self.window - (time.monotonic() - bucket[0])))

    def reset(self, key: str | None = None) -> None:
        """Clear recorded hits. Used by the test suite between cases."""
        if key is None:
            self._hits.clear()
        else:
            self._hits.pop(key, None)


login_limiter = RateLimiter(limit=10, window_seconds=300)
api_limiter = RateLimiter(limit=600, window_seconds=60)
scan_limiter = RateLimiter(limit=30, window_seconds=300)
