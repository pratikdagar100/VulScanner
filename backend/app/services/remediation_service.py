"""Remediation guidance.

Commands are produced as **guidance only**. VulScanner never executes a
remediation action: the operator reviews, approves and runs the change through
their own change-control process.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.models.finding import Severity

# How quickly a finding of each severity should be addressed.
SLA_DAYS = {
    Severity.CRITICAL.value: 7,
    Severity.HIGH.value: 30,
    Severity.MEDIUM.value: 90,
    Severity.LOW.value: 180,
    Severity.INFORMATIONAL.value: None,
}

# Effort estimate per finding category, used for planning order.
EFFORT_BY_CATEGORY = {
    "patch": "medium",
    "software": "medium",
    "firewall": "low",
    "defender": "low",
    "antivirus": "low",
    "rdp": "low",
    "accounts": "low",
    "policy": "low",
    "authentication": "medium",
    "network": "medium",
    "exposure": "medium",
    "shares": "low",
    "autorun": "low",
    "certificate": "medium",
    "boot_integrity": "high",
    "logging": "low",
    "filesystem": "medium",
    "secrets": "high",
    "vulnerability": "medium",
    "system": "medium",
}

# Categories where the fix requires a restart or has user-visible impact.
DISRUPTIVE_CATEGORIES = {"boot_integrity", "authentication", "patch"}


@dataclass
class RemediationItem:
    finding_uid: str
    title: str
    severity: str
    risk_score: float
    category: str

    what_is_wrong: str
    why_it_matters: str
    recommended_fix: str
    verification: str

    patch_reference: str = ""
    configuration_recommendation: str = ""
    command: str = ""
    references: list[str] = field(default_factory=list)

    priority: int = 3
    sla_days: int | None = None
    effort: str = "medium"
    disruptive: bool = False
    requires_reboot: bool = False
    automated_execution: bool = False  # always False by design

    def to_dict(self) -> dict:
        return {
            "finding_uid": self.finding_uid,
            "title": self.title,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "category": self.category,
            "what_is_wrong": self.what_is_wrong,
            "why_it_matters": self.why_it_matters,
            "recommended_fix": self.recommended_fix,
            "verification": self.verification,
            "patch_reference": self.patch_reference,
            "configuration_recommendation": self.configuration_recommendation,
            "command": self.command,
            "references": self.references,
            "priority": self.priority,
            "sla_days": self.sla_days,
            "effort": self.effort,
            "disruptive": self.disruptive,
            "requires_reboot": self.requires_reboot,
            "automated_execution": False,
            "execution_note": (
                "VulScanner does not apply this change. Review it against your "
                "change-control process and run it yourself."
            ),
        }


SEVERITY_PRIORITY = {
    Severity.CRITICAL.value: 1,
    Severity.HIGH.value: 2,
    Severity.MEDIUM.value: 3,
    Severity.LOW.value: 4,
    Severity.INFORMATIONAL.value: 5,
}

VERIFICATION_BY_RULE_PREFIX = {
    "FW": "Re-run `Get-NetFirewallProfile` and confirm Enabled is True for every profile.",
    "DEF": "Re-run `Get-MpComputerStatus` and `Get-MpPreference` and confirm the setting changed.",
    "UAC": "Re-read the Policies\\System key and confirm EnableLUA is 1; a restart is required.",
    "ACC": "Re-run `Get-LocalUser` / `net accounts` and confirm the account or policy change.",
    "RDP": "Re-read the RDP-Tcp key and re-run `Get-NetTCPConnection -LocalPort 3389 -State Listen`.",
    "AUTH": "Re-read the relevant LSA/LanmanServer key, then re-run the VulScanner scan.",
    "NET": "Re-run `Get-NetTCPConnection -State Listen` and confirm the port is gone or bound to loopback.",
    "SHARE": "Re-run `Get-SmbShareAccess` and `Get-SmbServerConfiguration`.",
    "PATCH": "Re-run the scan with the full profile and confirm the pending update count is zero.",
    "BOOT": "Re-run `Get-BitLockerVolume` / `Confirm-SecureBootUEFI`.",
    "LOG": "Re-run `auditpol /get /category:*` and confirm the subcategory is enabled.",
    "RUN": "Re-run the scan and confirm the autorun entry is no longer reported.",
    "CERT": "Re-enumerate the certificate store and confirm the certificate is removed or renewed.",
    "SEC": "Rotate the exposed credential, then re-run the scan to confirm no match remains.",
    "RPC": "Re-run `Get-Service` for the service and confirm it is stopped and disabled.",
    "DISC": "Re-run network discovery for the scope and confirm the port no longer responds.",
    "CVE": "Update the affected product, then re-run the scan to confirm the version changed.",
    "AMSI": "Re-enumerate AMSI providers and confirm the registration resolves.",
}


class RemediationService:
    """Turns findings into an ordered, actionable remediation plan."""

    def build_plan(self, findings: list[dict]) -> list[RemediationItem]:
        items: list[RemediationItem] = []

        for finding in findings:
            severity = finding.get("severity", Severity.MEDIUM.value)
            category = finding.get("category", "system")
            rule_id = finding.get("rule_id", "")
            prefix = rule_id.split("-")[0] if "-" in rule_id else rule_id

            patch_reference = ""
            evidence = finding.get("evidence") or {}
            if isinstance(evidence, dict):
                kbs = evidence.get("kbs") or evidence.get("kb") or []
                if isinstance(kbs, str):
                    kbs = [kbs]
                if kbs:
                    patch_reference = ", ".join(kbs)
                elif evidence.get("patch"):
                    patch_reference = str(evidence["patch"])

            items.append(
                RemediationItem(
                    finding_uid=finding.get("finding_uid", ""),
                    title=finding.get("title", ""),
                    severity=severity,
                    risk_score=float(finding.get("risk_score") or 0.0),
                    category=category,
                    what_is_wrong=finding.get("description", ""),
                    why_it_matters=finding.get("impact", ""),
                    recommended_fix=finding.get("remediation", ""),
                    verification=VERIFICATION_BY_RULE_PREFIX.get(
                        prefix,
                        "Re-run the VulScanner scan and confirm the finding no longer "
                        "appears.",
                    ),
                    patch_reference=patch_reference,
                    configuration_recommendation=finding.get("remediation", ""),
                    command=finding.get("remediation_command", ""),
                    references=list(finding.get("references") or []),
                    priority=SEVERITY_PRIORITY.get(severity, 3),
                    sla_days=SLA_DAYS.get(severity),
                    effort=EFFORT_BY_CATEGORY.get(category, "medium"),
                    disruptive=category in DISRUPTIVE_CATEGORIES,
                    requires_reboot=category in {"boot_integrity", "patch"}
                    or "restart" in (finding.get("remediation") or "").lower()
                    or "reboot" in (finding.get("remediation") or "").lower(),
                )
            )

        items.sort(key=lambda item: (item.priority, -item.risk_score, item.title))
        return items

    def summarize_plan(self, items: list[RemediationItem]) -> dict:
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        for item in items:
            by_severity[item.severity] = by_severity.get(item.severity, 0) + 1
            by_category[item.category] = by_category.get(item.category, 0) + 1

        quick_wins = [
            item.to_dict()
            for item in items
            if item.effort == "low" and item.priority <= 3
        ][:10]

        return {
            "total_items": len(items),
            "by_severity": by_severity,
            "by_category": dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
            "immediate_action_required": [
                item.to_dict() for item in items if item.priority == 1
            ],
            "quick_wins": quick_wins,
            "requires_reboot_count": sum(1 for item in items if item.requires_reboot),
            "policy": (
                "VulScanner never applies remediation automatically. Every command "
                "shown is guidance for an authorized operator to review and execute."
            ),
        }


remediation_service = RemediationService()
