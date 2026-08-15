"""Detection rules and the analysis runner.

Importing this package registers every rule module with the analyzer registry.
"""

from __future__ import annotations

import hashlib

from app.core.logging import get_logger
from app.models.finding import Severity
from app.services.analyzers.base import (
    AnalysisContext,
    FindingDraft,
    analyzer,
    registered_analyzers,
)
from app.services.risk_engine import RiskInputs, risk_engine

# Rule modules - imported for their registration side effects.
from app.services.analyzers import network_rules  # noqa: F401,E402
from app.services.analyzers import windows_rules  # noqa: F401,E402
from app.services.analyzers import windows_rules2  # noqa: F401,E402

logger = get_logger(__name__)

SEVERITY_ORDER = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
    Severity.INFORMATIONAL.value: 4,
}


def finding_uid(rule_id: str, instance_key: str, target: str) -> str:
    """Deterministic identifier: the same issue on the same host keeps its ID."""
    digest = hashlib.sha256(
        f"{target}|{rule_id}|{instance_key}".encode("utf-8")
    ).hexdigest()[:8]
    return f"VS-{rule_id}-{digest.upper()}"


def analyze(context: AnalysisContext, target: str = "") -> list[dict]:
    """Run every registered rule and return scored, sorted findings."""
    drafts: list[FindingDraft] = []

    for name, fn in registered_analyzers():
        try:
            drafts.extend(fn(context))
        except Exception as exc:  # a broken rule must not lose the whole scan
            logger.exception("Analyzer %s failed", name)
            drafts.append(
                FindingDraft(
                    rule_id="ANALYZER-ERROR",
                    instance_key=name,
                    title=f"Analyzer '{name}' failed to run",
                    category=__import__(
                        "app.models.finding", fromlist=["FindingCategory"]
                    ).FindingCategory.SYSTEM,
                    severity=Severity.INFORMATIONAL,
                    description=(
                        "A detection rule raised an error, so its findings are "
                        f"missing from this scan: {type(exc).__name__}: {exc}"
                    ),
                    impact="Coverage for this rule set is incomplete for this scan.",
                    remediation="Review the VulScanner log and re-run the scan.",
                    detection_method="analysis runner",
                    configuration_weakness=False,
                )
            )

    findings: list[dict] = []
    seen: set[str] = set()

    for draft in drafts:
        if draft.dedupe_key in seen:
            continue
        seen.add(draft.dedupe_key)

        result = risk_engine.score(
            RiskInputs(
                cvss_score=draft.cvss_score,
                base_severity=draft.severity.value,
                exposure=draft.exposure,
                confidence=draft.confidence.value,
                asset_criticality=context.asset_criticality,
                kev=draft.kev,
                attack_vector=draft.attack_vector,
                patch_missing=draft.patch_missing,
                patch_available=draft.patch_available,
                configuration_weakness=draft.configuration_weakness,
                security_control_disabled=draft.security_control_disabled,
                service_exposed=draft.service_exposed,
            )
        )

        findings.append(
            {
                "finding_uid": finding_uid(draft.rule_id, draft.instance_key, target),
                "rule_id": draft.rule_id,
                "title": draft.title,
                "category": draft.category.value,
                "severity": result.severity.value,
                "rule_severity": draft.severity.value,
                "risk_score": result.score,
                "risk_factors": result.factors,
                "cvss_score": draft.cvss_score,
                "confidence": draft.confidence.value,
                "description": draft.description,
                "impact": draft.impact,
                "evidence": draft.evidence,
                "evidence_summary": draft.evidence_summary,
                "detection_method": draft.detection_method,
                "remediation": draft.remediation,
                "remediation_command": draft.remediation_command,
                "references": draft.references,
                "source_collector": draft.source_collector,
                "instance_key": draft.instance_key,
            }
        )

    findings.sort(
        key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), -f["risk_score"], f["title"])
    )
    return findings


__all__ = [
    "AnalysisContext",
    "FindingDraft",
    "analyze",
    "analyzer",
    "finding_uid",
    "registered_analyzers",
]
