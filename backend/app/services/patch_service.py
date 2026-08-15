"""Patch posture assessment.

The rule this module enforces: never claim a patch is missing without evidence.
There are exactly three evidence classes, in descending strength:

``confirmed``  the Windows Update agent reported the update as applicable and
               not installed;
``high``       the OS build is below a build known to have reached end of
               servicing, or a required KB is absent while a later KB from the
               same servicing family is present;
``low``        informational only - patch level could not be determined.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.scanner.util import parse_datetime

KB_PATTERN = re.compile(r"KB(\d{6,})", re.IGNORECASE)

# Days after which a host with no observed servicing activity is called stale.
STALE_PATCH_DAYS = 60


@dataclass
class PatchRecord:
    kb_id: str
    title: str = ""
    description: str = ""
    classification: str = ""
    state: str = "installed"  # installed | missing | unknown
    installed_on: str | None = None
    installed_by: str | None = None
    severity: str | None = None
    confidence: str = "confirmed"
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "kb_id": self.kb_id,
            "title": self.title,
            "description": self.description,
            "classification": self.classification,
            "state": self.state,
            "installed_on": self.installed_on,
            "installed_by": self.installed_by,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


class PatchService:
    """Builds the patch inventory and posture summary for one asset."""

    def build_inventory(
        self, hotfix_data: dict, update_data: dict
    ) -> list[PatchRecord]:
        records: list[PatchRecord] = []
        seen: set[str] = set()

        for hotfix in hotfix_data.get("hotfixes", []):
            kb = (hotfix.get("kb") or "").upper()
            if not kb or kb in seen:
                continue
            seen.add(kb)
            source = hotfix.get("source", "")
            records.append(
                PatchRecord(
                    kb_id=kb,
                    title=hotfix.get("description", ""),
                    classification=hotfix.get("description", ""),
                    state="installed",
                    installed_on=hotfix.get("installed_on"),
                    installed_by=hotfix.get("installed_by"),
                    # QFE entries are authoritative; CBS package keys are strong
                    # but do not always carry an install date.
                    confidence="confirmed" if "QuickFix" in source else "high",
                    evidence={"source": source},
                )
            )

        for update in update_data.get("pending_updates", []):
            kbs = [kb.upper() for kb in (update.get("kbs") or [])]
            if not kbs:
                # An update with no KB identifier still matters, but cannot be
                # keyed by KB - record it under its title.
                kbs = [f"UPDATE:{(update.get('title') or 'unnamed')[:40]}"]
            for kb in kbs:
                if kb in seen:
                    continue
                seen.add(kb)
                records.append(
                    PatchRecord(
                        kb_id=kb,
                        title=update.get("title", ""),
                        classification=", ".join(update.get("categories") or []),
                        state="missing",
                        severity=update.get("msrc_severity"),
                        confidence="confirmed",
                        evidence={
                            "source": "Windows Update agent applicability search",
                            "reboot_required": update.get("reboot_required"),
                            "mandatory": update.get("mandatory"),
                            "support_url": update.get("support_url", ""),
                        },
                    )
                )

        return records

    def summarize(
        self, records: list[PatchRecord], hotfix_data: dict, update_data: dict, os_data: dict
    ) -> dict:
        installed = [r for r in records if r.state == "installed"]
        missing = [r for r in records if r.state == "missing"]
        security_missing = [
            r
            for r in missing
            if (r.severity and r.severity.lower() != "unspecified")
            or "security" in (r.classification or "").lower()
        ]

        latest = self._latest_install(installed)
        days_since = None
        if latest:
            days_since = (datetime.now(tz=timezone.utc) - latest).days

        queried = bool(update_data.get("queried_update_agent"))
        if queried and not update_data.get("evidence_quality") == "registry-only":
            evidence_quality = "confirmed"
            note = (
                "Missing updates were enumerated by the Windows Update agent, which "
                "evaluates applicability against this specific host."
            )
        else:
            evidence_quality = "partial"
            note = (
                "The Windows Update agent was not queried for this scan, so missing "
                "updates are not enumerated. Installed patches are still reported. "
                "Run the 'full' profile for missing-update evidence."
            )

        return {
            "installed_count": len(installed),
            "missing_count": len(missing),
            "missing_security_count": len(security_missing),
            "installed_kbs": sorted(r.kb_id for r in installed),
            "missing_kbs": sorted(r.kb_id for r in missing),
            "critical_missing": [
                r.to_dict()
                for r in missing
                if (r.severity or "").lower() == "critical"
            ],
            "latest_patch_date": latest.isoformat() if latest else None,
            "days_since_last_patch": days_since,
            "patching_stale": bool(days_since is not None and days_since > STALE_PATCH_DAYS),
            "stale_threshold_days": STALE_PATCH_DAYS,
            "pending_reboot": bool(update_data.get("pending_reboot")),
            "os_build": os_data.get("full_build"),
            "os_display_version": os_data.get("display_version"),
            "end_of_servicing": os_data.get("end_of_servicing"),
            "build_supported": os_data.get("supported_build"),
            "automatic_updates": update_data.get("automatic_updates", {}),
            "evidence_quality": evidence_quality,
            "evidence_note": note,
            "failed_installs": update_data.get("failed_installs", []),
        }

    @staticmethod
    def _latest_install(records: list[PatchRecord]) -> datetime | None:
        dates = [
            parse_datetime(r.installed_on) for r in records if r.installed_on
        ]
        valid = [d for d in dates if d]
        return max(valid) if valid else None


patch_service = PatchService()
