"""VulScanner risk engine.

Produces the **VulScanner Risk Score** (0-100), which is always presented
separately from the official CVSS base score. CVSS describes a vulnerability in
the abstract; the VulScanner score describes *this* weakness on *this* asset,
given how exposed it is, whether it is known to be exploited, how confident the
detection is, and how important the asset is.

    score = clamp( base x exposure x exploitation x confidence x asset , 0, 100 )

Every score ships with the factor breakdown that produced it, so a reviewer can
always see why a number is what it is.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from app.models.finding import Confidence, Severity


class ExposureLevel(str, Enum):
    """How reachable the weakness is."""

    INTERNET = "internet"          # reachable from a public address
    NETWORK = "network"            # reachable from the local network
    ADJACENT = "adjacent"          # same broadcast domain only
    LOCAL = "local"                # requires local access
    NONE = "none"                  # not reachable (loopback / disabled)


# Multipliers. Kept explicit and small in number so scores stay explainable.
EXPOSURE_MULTIPLIERS: dict[ExposureLevel, float] = {
    ExposureLevel.INTERNET: 1.35,
    ExposureLevel.NETWORK: 1.15,
    ExposureLevel.ADJACENT: 1.0,
    ExposureLevel.LOCAL: 0.75,
    ExposureLevel.NONE: 0.4,
}

CONFIDENCE_MULTIPLIERS: dict[str, float] = {
    Confidence.CONFIRMED.value: 1.0,
    Confidence.HIGH.value: 0.95,
    Confidence.MEDIUM.value: 0.8,
    Confidence.LOW.value: 0.6,
    Confidence.INFORMATIONAL.value: 0.4,
}

CRITICALITY_MULTIPLIERS: dict[str, float] = {
    "critical": 1.25,
    "high": 1.12,
    "normal": 1.0,
    "low": 0.85,
}

# Severity bands. The upper bound is inclusive.
SEVERITY_BANDS: list[tuple[float, float, Severity]] = [
    (90.0, 100.0, Severity.CRITICAL),
    (70.0, 89.999, Severity.HIGH),
    (40.0, 69.999, Severity.MEDIUM),
    (0.001, 39.999, Severity.LOW),
    (0.0, 0.0, Severity.INFORMATIONAL),
]

# Base score a finding starts from, by the severity the detection rule asserts.
BASE_BY_SEVERITY: dict[str, float] = {
    Severity.CRITICAL.value: 88.0,
    Severity.HIGH.value: 70.0,
    Severity.MEDIUM.value: 45.0,
    Severity.LOW.value: 20.0,
    Severity.INFORMATIONAL.value: 0.0,
}


@dataclass
class RiskInputs:
    """Everything the engine considers. Unknown inputs are simply left unset."""

    # One of these two seeds the base score.
    cvss_score: float | None = None
    base_severity: str | None = None

    exposure: ExposureLevel = ExposureLevel.LOCAL
    confidence: str = Confidence.HIGH.value
    asset_criticality: str = "normal"

    kev: bool = False
    kev_ransomware: bool = False
    exploit_available: bool = False
    attack_vector: str | None = None          # NETWORK / ADJACENT / LOCAL / PHYSICAL
    exploitability_score: float | None = None  # NVD sub-score, 0-3.9

    patch_available: bool = False
    patch_missing: bool = False
    configuration_weakness: bool = False
    security_control_disabled: bool = False
    service_exposed: bool = False
    internet_facing_known: bool = False

    notes: list[str] = field(default_factory=list)


@dataclass
class RiskResult:
    score: float
    severity: Severity
    factors: dict[str, Any]

    def to_dict(self) -> dict:
        return {
            "risk_score": self.score,
            "severity": self.severity.value,
            "factors": self.factors,
        }


def severity_for_score(score: float) -> Severity:
    for low, high, severity in SEVERITY_BANDS:
        if low <= score <= high:
            return severity
    return Severity.INFORMATIONAL


def severity_for_cvss(score: float | None) -> Severity:
    """Official CVSS v3 qualitative rating - reported alongside, never merged."""
    if score is None:
        return Severity.INFORMATIONAL
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFORMATIONAL


def exposure_from_binding(exposure: str) -> ExposureLevel:
    """Map a socket binding classification to an exposure level."""
    return {
        "public": ExposureLevel.INTERNET,
        "all-interfaces": ExposureLevel.NETWORK,
        "private": ExposureLevel.NETWORK,
        "link-local": ExposureLevel.ADJACENT,
        "loopback": ExposureLevel.NONE,
    }.get(exposure, ExposureLevel.LOCAL)


class RiskEngine:
    """Calculates VulScanner risk scores."""

    def score(self, inputs: RiskInputs) -> RiskResult:
        factors: dict[str, Any] = {}

        base = self._base_score(inputs, factors)
        if base <= 0:
            return RiskResult(0.0, Severity.INFORMATIONAL, factors | {"base": 0.0})

        exposure_multiplier = self._exposure_multiplier(inputs, factors)
        exploitation_multiplier = self._exploitation_multiplier(inputs, factors)
        confidence_multiplier = CONFIDENCE_MULTIPLIERS.get(inputs.confidence, 0.8)
        asset_multiplier = CRITICALITY_MULTIPLIERS.get(inputs.asset_criticality, 1.0)

        factors["confidence"] = {
            "level": inputs.confidence,
            "multiplier": confidence_multiplier,
            "reason": "Lower detection confidence reduces the score.",
        }
        factors["asset_criticality"] = {
            "level": inputs.asset_criticality,
            "multiplier": asset_multiplier,
        }

        raw = (
            base
            * exposure_multiplier
            * exploitation_multiplier
            * confidence_multiplier
            * asset_multiplier
        )
        adjustment, adjustment_notes = self._adjustments(inputs)
        raw += adjustment
        if adjustment_notes:
            factors["adjustments"] = {
                "total": round(adjustment, 2),
                "reasons": adjustment_notes,
            }

        score = round(max(0.0, min(100.0, raw)), 1)
        factors["formula"] = (
            "base x exposure x exploitation x confidence x asset_criticality "
            "+ adjustments"
        )
        factors["computed_score"] = score
        if inputs.notes:
            factors["notes"] = list(inputs.notes)

        return RiskResult(score, severity_for_score(score), factors)

    # -- components --------------------------------------------------------
    def _base_score(self, inputs: RiskInputs, factors: dict) -> float:
        if inputs.cvss_score is not None:
            base = inputs.cvss_score * 10.0
            factors["base"] = {
                "value": round(base, 2),
                "source": "CVSS base score x 10",
                "cvss_score": inputs.cvss_score,
                "cvss_severity": severity_for_cvss(inputs.cvss_score).value,
            }
            return base

        severity = (inputs.base_severity or Severity.MEDIUM.value).lower()
        base = BASE_BY_SEVERITY.get(severity, 45.0)
        factors["base"] = {
            "value": base,
            "source": f"detection rule severity '{severity}'",
        }
        return base

    def _exposure_multiplier(self, inputs: RiskInputs, factors: dict) -> float:
        exposure = inputs.exposure
        # A network attack vector cannot be worse than local reachability allows,
        # but a locally-scored issue on an internet-facing service is worse.
        if inputs.internet_facing_known and exposure is not ExposureLevel.NONE:
            exposure = ExposureLevel.INTERNET

        multiplier = EXPOSURE_MULTIPLIERS[exposure]
        if inputs.attack_vector:
            vector = inputs.attack_vector.upper()
            if vector in ("LOCAL", "PHYSICAL") and exposure in (
                ExposureLevel.INTERNET,
                ExposureLevel.NETWORK,
            ):
                # A local-only vulnerability is not made remote by an open port.
                multiplier = min(multiplier, EXPOSURE_MULTIPLIERS[ExposureLevel.LOCAL])

        factors["exposure"] = {
            "level": exposure.value,
            "multiplier": multiplier,
            "attack_vector": inputs.attack_vector,
            "service_exposed": inputs.service_exposed,
        }
        return multiplier

    def _exploitation_multiplier(self, inputs: RiskInputs, factors: dict) -> float:
        multiplier = 1.0
        reasons: list[str] = []

        if inputs.kev:
            multiplier *= 1.30
            reasons.append(
                "Listed in the CISA Known Exploited Vulnerabilities catalogue."
            )
        if inputs.kev_ransomware:
            multiplier *= 1.08
            reasons.append("Known to be used in ransomware campaigns.")
        if inputs.exploit_available and not inputs.kev:
            multiplier *= 1.12
            reasons.append("Public exploit code is referenced by the advisory.")
        if inputs.exploitability_score is not None:
            # NVD exploitability sub-score runs 0-3.9; normalise to +/-10%.
            normalized = max(0.0, min(3.9, inputs.exploitability_score)) / 3.9
            adjustment = 0.9 + (normalized * 0.2)
            multiplier *= adjustment
            reasons.append(
                f"NVD exploitability sub-score {inputs.exploitability_score}."
            )

        factors["exploitation"] = {
            "multiplier": round(multiplier, 3),
            "kev": inputs.kev,
            "reasons": reasons or ["No exploitation intelligence available."],
        }
        return multiplier

    def _adjustments(self, inputs: RiskInputs) -> tuple[float, list[str]]:
        total = 0.0
        reasons: list[str] = []

        if inputs.security_control_disabled:
            total += 6.0
            reasons.append("A security control is disabled (+6).")
        if inputs.patch_missing:
            total += 5.0
            reasons.append("A vendor patch is available but not installed (+5).")
        elif inputs.patch_available:
            total += 2.0
            reasons.append("A vendor patch exists for this issue (+2).")
        if inputs.configuration_weakness and inputs.service_exposed:
            total += 4.0
            reasons.append(
                "A weak configuration is combined with network exposure (+4)."
            )
        return total, reasons


# Shared instance - the engine is stateless.
risk_engine = RiskEngine()


def score_finding(
    *,
    severity: str,
    exposure: ExposureLevel = ExposureLevel.LOCAL,
    confidence: str = Confidence.HIGH.value,
    asset_criticality: str = "normal",
    **kwargs: Any,
) -> RiskResult:
    """Convenience wrapper for configuration findings (no CVSS involved)."""
    return risk_engine.score(
        RiskInputs(
            base_severity=severity,
            exposure=exposure,
            confidence=confidence,
            asset_criticality=asset_criticality,
            **kwargs,
        )
    )


def score_vulnerability(
    *,
    cvss_score: float | None,
    exposure: ExposureLevel = ExposureLevel.LOCAL,
    confidence: str = Confidence.MEDIUM.value,
    asset_criticality: str = "normal",
    **kwargs: Any,
) -> RiskResult:
    """Convenience wrapper for CVE-backed vulnerabilities."""
    return risk_engine.score(
        RiskInputs(
            cvss_score=cvss_score,
            exposure=exposure,
            confidence=confidence,
            asset_criticality=asset_criticality,
            **kwargs,
        )
    )


# Per-finding penalty weights for the overall posture score.
POSTURE_WEIGHTS = {
    "critical": 0.35,
    "high": 0.12,
    "medium": 0.035,
    "low": 0.008,
}


def security_score(
    critical: int, high: int, medium: int, low: int, informational: int = 0
) -> float:
    """Overall posture score, 100 = no findings.

    Uses exponential decay rather than a linear penalty so the score degrades
    smoothly: a host with many low-severity findings never scores worse than one
    with an unpatched critical, and the score never collapses to a flat zero that
    hides further deterioration.
    """
    exponent = (
        POSTURE_WEIGHTS["critical"] * critical
        + POSTURE_WEIGHTS["high"] * high
        + POSTURE_WEIGHTS["medium"] * medium
        + POSTURE_WEIGHTS["low"] * low
    )
    return round(max(0.0, min(100.0, 100.0 * math.exp(-exponent))), 1)
