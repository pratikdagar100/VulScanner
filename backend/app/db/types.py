"""Portable JSON column types.

SQLite and PostgreSQL both receive plain JSON; the defaults differ only in the
Python-side container type so ``default=list`` / ``default=dict`` behave.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import JSON
from sqlalchemy.types import TypeDecorator


class JSONMap(TypeDecorator):
    """JSON object column that never yields ``None`` to application code."""

    impl = JSON
    cache_ok = True

    def process_result_value(self, value: Any, dialect: Any) -> dict:
        return value if isinstance(value, dict) else {}


class JSONList(TypeDecorator):
    """JSON array column that never yields ``None`` to application code."""

    impl = JSON
    cache_ok = True

    def process_result_value(self, value: Any, dialect: Any) -> list:
        return value if isinstance(value, list) else []
