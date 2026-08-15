"""Collector contract shared by every VulScanner collector.

Every collector returns a :class:`CollectorResult`. A collector that fails must
never raise out of :meth:`BaseCollector.run` - the engine records the failure and
continues, so one denied permission cannot abort an entire assessment.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)


class CollectorStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(slots=True)
class CollectorResult:
    """Structured, uniform collector output."""

    collector: str
    status: CollectorStatus = CollectorStatus.SUCCESS
    data: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    collection_method: str = ""
    collected_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    duration_seconds: float = 0.0
    category: str = "windows"

    def warn(self, message: str) -> None:
        if message and message not in self.warnings:
            self.warnings.append(message)
        if self.status is CollectorStatus.SUCCESS:
            self.status = CollectorStatus.PARTIAL

    def fail(self, message: str) -> None:
        if message and message not in self.errors:
            self.errors.append(message)
        self.status = CollectorStatus.FAILED

    def degrade(self, message: str) -> None:
        """Record an error but keep whatever data was already collected."""
        if message and message not in self.errors:
            self.errors.append(message)
        if self.status is CollectorStatus.SUCCESS:
            self.status = CollectorStatus.PARTIAL

    def to_dict(self) -> dict[str, Any]:
        return {
            "collector": self.collector,
            "category": self.category,
            "status": self.status.value,
            "data": self.data,
            "warnings": self.warnings,
            "errors": self.errors,
            "collection_method": self.collection_method,
            "collected_at": self.collected_at.isoformat(),
            "duration_seconds": round(self.duration_seconds, 3),
        }


class BaseCollector(ABC):
    """Base class for all collectors.

    Subclasses implement :meth:`collect` and may override :meth:`supported`.
    """

    name: str = "collector"
    category: str = "windows"
    description: str = ""
    #: Collector needs an elevated session to return complete data.
    requires_admin: bool = False
    #: Profiles this collector participates in.
    profiles: tuple[str, ...] = ("quick", "standard", "full", "compliance")

    def __init__(self, context: "ScanContext") -> None:  # noqa: F821
        self.context = context

    # -- overridable ------------------------------------------------------
    def supported(self) -> tuple[bool, str]:
        """Return ``(is_supported, reason)`` for the current context."""
        if not self.context.is_windows_target:
            return False, "Collector requires a Windows target."
        return True, ""

    @abstractmethod
    def collect(self, result: CollectorResult) -> None:
        """Populate ``result.data``. May call ``result.warn`` / ``result.degrade``."""

    # -- engine entry point -----------------------------------------------
    def run(self) -> CollectorResult:
        result = CollectorResult(
            collector=self.name, category=self.category, data={}
        )
        supported, reason = self.supported()
        if not supported:
            result.status = CollectorStatus.SKIPPED
            result.warnings.append(reason)
            return result

        started = time.perf_counter()
        try:
            self.collect(result)
        except PermissionError as exc:
            result.fail(f"Permission denied: {exc}")
        except TimeoutError as exc:
            result.fail(f"Collector timed out: {exc}")
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Collector %s raised", self.name)
            result.fail(f"{type(exc).__name__}: {exc}")
        finally:
            result.duration_seconds = time.perf_counter() - started
        return result
