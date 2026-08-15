"""Local groups and their membership, with focus on privileged groups."""

from __future__ import annotations

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import dicts, get, text

SCRIPT = r"""
$groups = @()
try {
  $groups = Get-LocalGroup -ErrorAction Stop | ForEach-Object {
    $members = @()
    try {
      $members = @(Get-LocalGroupMember -Group $_.Name -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
          Name=$_.Name; SID=$_.SID.Value
          ObjectClass=[string]$_.ObjectClass
          PrincipalSource=[string]$_.PrincipalSource
        }
      })
    } catch {
      # Group membership can fail for groups holding orphaned domain SIDs.
      $members = @()
    }
    [pscustomobject]@{
      Name=$_.Name; Description=$_.Description; SID=$_.SID.Value; Members=$members
    }
  }
} catch {
  $groups = Get-CimInstance Win32_Group -Filter "LocalAccount=True" -ErrorAction SilentlyContinue |
    ForEach-Object { [pscustomobject]@{ Name=$_.Name; Description=$_.Description; SID=$_.SID; Members=@() } }
}
,$groups
"""

# Well-known privileged group SIDs (suffix match against the machine SID).
PRIVILEGED_GROUP_SIDS = {
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-547": "Power Users",
    "S-1-5-32-562": "Distributed COM Users",
    "S-1-5-32-578": "Hyper-V Administrators",
    "S-1-5-32-580": "Remote Management Users",
    "S-1-5-32-555": "Remote Desktop Users",
}

# Accounts that legitimately belong to Administrators on a default install.
EXPECTED_ADMIN_SUFFIXES = ("-500", "-512")  # built-in Administrator, Domain Admins


class LocalGroupsCollector(BaseCollector):
    name = "local_groups"
    category = "windows"
    description = "Local groups, membership and privileged group analysis"
    profiles = ("quick", "standard", "full", "compliance")

    def collect(self, result: CollectorResult) -> None:
        records, ps = self.context.runner.run_list(SCRIPT, depth=5)
        result.collection_method = self.context.runner.describe_method(
            "Get-LocalGroup and Get-LocalGroupMember"
        )
        if not ps.ok:
            result.fail(ps.friendly_error())
            return

        groups = []
        for record in dicts(records):
            sid = text(get(record, "SID"))
            members = []
            for member in dicts(get(record, "Members")):
                members.append(
                    {
                        "name": text(get(member, "Name")),
                        "sid": text(get(member, "SID")),
                        "object_class": text(get(member, "ObjectClass")),
                        "source": text(get(member, "PrincipalSource")),
                    }
                )
            groups.append(
                {
                    "name": text(get(record, "Name")),
                    "description": text(get(record, "Description")),
                    "sid": sid,
                    "privileged": sid in PRIVILEGED_GROUP_SIDS,
                    "privileged_role": PRIVILEGED_GROUP_SIDS.get(sid, ""),
                    "members": members,
                    "member_count": len(members),
                }
            )

        administrators = next(
            (g for g in groups if g["sid"] == "S-1-5-32-544"), None
        )
        admin_members = administrators["members"] if administrators else []
        unexpected_admins = [
            m
            for m in admin_members
            if not any(m["sid"].endswith(suffix) for suffix in EXPECTED_ADMIN_SUFFIXES)
            and m["sid"] not in ("S-1-5-32-544",)
        ]

        result.data = {
            "groups": groups,
            "group_count": len(groups),
            "non_empty_groups": [g for g in groups if g["member_count"] > 0],
            "privileged_groups": [g for g in groups if g["privileged"]],
            "administrators": {
                "members": admin_members,
                "member_count": len(admin_members),
                "unexpected_members": unexpected_admins,
                "unexpected_count": len(unexpected_admins),
            },
            "remote_desktop_users": next(
                (g["members"] for g in groups if g["sid"] == "S-1-5-32-555"), []
            ),
            "remote_management_users": next(
                (g["members"] for g in groups if g["sid"] == "S-1-5-32-580"), []
            ),
            "backup_operators": next(
                (g["members"] for g in groups if g["sid"] == "S-1-5-32-551"), []
            ),
        }

        if administrators is None:
            result.warn("The local Administrators group could not be enumerated.")
