"""Parsing helpers shared by collectors.

PowerShell's ``ConvertTo-Json`` has a few well known quirks these helpers absorb:
a single object is not wrapped in an array, ``DateTime`` values become
``/Date(1700000000000)/`` strings, and enum-backed properties may arrive as ints.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Iterable

_MS_DATE = re.compile(r"/Date\((-?\d+)(?:[+-]\d+)?\)/")
_ISO_LIKE = re.compile(r"^\d{4}-\d{2}-\d{2}")


def as_list(value: Any) -> list:
    """Normalize a ConvertTo-Json value into a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def dicts(value: Any) -> list[dict]:
    return [item for item in as_list(value) if isinstance(item, dict)]


def get(record: dict | None, *names: str, default: Any = None) -> Any:
    """Case-insensitive lookup across several candidate property names."""
    if not isinstance(record, dict):
        return default
    lowered = {str(k).lower(): v for k, v in record.items()}
    for name in names:
        if name in record and record[name] is not None:
            return record[name]
        value = lowered.get(name.lower())
        if value is not None:
            return value
    return default


def text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).strip()


def boolean(value: Any, default: bool | None = None) -> bool | None:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    lowered = str(value).strip().lower()
    if lowered in {"true", "1", "yes", "enabled", "on", "enable"}:
        return True
    if lowered in {"false", "0", "no", "disabled", "off", "disable"}:
        return False
    return default


def integer(value: Any, default: int | None = None) -> int | None:
    if value is None or isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def number(value: Any, default: float | None = None) -> float | None:
    if value is None or isinstance(value, bool):
        return default
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def parse_datetime(value: Any) -> datetime | None:
    """Parse the date shapes PowerShell emits."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, dict):  # {"DateTime": "...", "value": "/Date(...)/"}
        for key in ("DateTime", "value", "Value"):
            if key in value:
                return parse_datetime(value[key])
        return None
    raw = str(value).strip()
    if not raw:
        return None
    match = _MS_DATE.search(raw)
    if match:
        try:
            return datetime.fromtimestamp(int(match.group(1)) / 1000, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if _ISO_LIKE.match(raw):
        candidate = raw.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(candidate)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    for fmt in ("%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y", "%d-%m-%Y", "%Y%m%d"):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def iso(value: Any) -> str | None:
    parsed = parse_datetime(value)
    return parsed.isoformat() if parsed else None


def normalize_mac(value: Any) -> str | None:
    """Return a MAC as ``AA:BB:CC:DD:EE:FF`` or ``None`` if not a MAC."""
    if not value:
        return None
    raw = re.sub(r"[^0-9A-Fa-f]", "", str(value))
    if len(raw) != 12:
        return None
    if raw == "0" * 12:
        return None
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2)).upper()


def enum_name(value: Any, mapping: dict[int, str]) -> str:
    """Resolve a value that may arrive as an int or an already-named string."""
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, int):
        return mapping.get(value, str(value))
    raw = text(value)
    if raw.isdigit():
        return mapping.get(int(raw), raw)
    return raw


def chunked(items: Iterable, size: int) -> Iterable[list]:
    batch: list = []
    for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def version_tuple(version: str) -> tuple[int, ...]:
    """Best-effort numeric version tuple for comparisons."""
    parts = re.findall(r"\d+", version or "")
    return tuple(int(p) for p in parts[:6]) or (0,)


def compare_versions(left: str, right: str) -> int:
    a, b = version_tuple(left), version_tuple(right)
    length = max(len(a), len(b))
    a += (0,) * (length - len(a))
    b += (0,) * (length - len(b))
    return (a > b) - (a < b)
