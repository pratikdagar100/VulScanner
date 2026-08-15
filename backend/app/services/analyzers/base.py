"""Finding drafts and the analyzer contract.

An analyzer reads normalized collector output and emits :class:`FindingDraft`
objects. A draft asserts a *base* severity; the risk engine converts that into
the final VulScanner risk score using exposure, confidence and asset context.

Rules must only fire on evidence actually present in the collector output. When
a collector could not read something, the correct behaviour is to emit nothing
(or an informational finding stating what could not be verified) - never to
assume the insecure case.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from app.models.finding import Confidence, FindingCategory, Severity
from app.services.risk_engine import ExposureLevel


@dataclass
class FindingDraft:
    """A detection before risk scoring."""

    rule_id: str
    title: str
    category: FindingCategory
    severity: Severity
    description: str
    impact: str
    remediation: str

    evidence: dict[str, Any] = field(default_factory=dict)
    evidence_summary: str = ""
    detection_method: str = ""
    remediation_command: str = ""
    references: list[str] = field(default_factory=list)

    confidence: Confidence = Confidence.HIGH
    exposure: ExposureLevel = ExposureLevel.LOCAL

    # Risk engine inputs.
    security_control_disabled: bool = False
    configuration_weakness: bool = True
    service_exposed: bool = False
    patch_missing: bool = False
    patch_available: bool = False
    kev: bool = False
    cvss_score: float | None = None
    attack_vector: str | None = None

    # Set when the finding is derived from a specific collector result.
    source_collector: str = ""
    #: Distinguishes multiple instances of one rule (port number, share name...).
    instance_key: str = ""

    @property
    def dedupe_key(self) -> str:
        return f"{self.rule_id}:{self.instance_key}" if self.instance_key else self.rule_id


AnalyzerFn = Callable[["AnalysisContext"], Iterable[FindingDraft]]


@dataclass
class AnalysisContext:
    """Read-only view of one scan's collected data."""

    collector_data: dict[str, dict]
    collector_status: dict[str, str] = field(default_factory=dict)
    discovery: dict = field(default_factory=dict)
    topology: dict = field(default_factory=dict)
    profile: str = "standard"
    elevated: bool = True
    asset_criticality: str = "normal"
    #: How the target was assessed - see ScanContext.assessment_mode.
    assessment_mode: str = "local-authenticated"

    def data(self, collector: str) -> dict:
        return self.collector_data.get(collector) or {}

    def available(self, collector: str) -> bool:
        """Whether a collector produced usable data."""
        return bool(self.collector_data.get(collector)) and self.collector_status.get(
            collector
        ) in (None, "success", "partial")

    def value(self, collector: str, key: str, default: Any = None) -> Any:
        return self.data(collector).get(key, default)


_REGISTRY: list[tuple[str, AnalyzerFn]] = []


def analyzer(name: str) -> Callable[[AnalyzerFn], AnalyzerFn]:
    """Register an analyzer function."""

    def decorator(fn: AnalyzerFn) -> AnalyzerFn:
        _REGISTRY.append((name, fn))
        return fn

    return decorator


def registered_analyzers() -> list[tuple[str, AnalyzerFn]]:
    return list(_REGISTRY)
