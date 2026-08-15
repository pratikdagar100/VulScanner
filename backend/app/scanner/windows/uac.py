"""User Account Control configuration."""

from __future__ import annotations

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import get, integer

SCRIPT = r"""
$p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$k = $null
try { $k = Get-ItemProperty $p -ErrorAction Stop } catch {}
[pscustomobject]@{
  EnableLUA                     = $k.EnableLUA
  ConsentPromptBehaviorAdmin    = $k.ConsentPromptBehaviorAdmin
  ConsentPromptBehaviorUser     = $k.ConsentPromptBehaviorUser
  PromptOnSecureDesktop         = $k.PromptOnSecureDesktop
  EnableInstallerDetection      = $k.EnableInstallerDetection
  EnableSecureUIAPaths          = $k.EnableSecureUIAPaths
  EnableVirtualization          = $k.EnableVirtualization
  FilterAdministratorToken      = $k.FilterAdministratorToken
  LocalAccountTokenFilterPolicy = $k.LocalAccountTokenFilterPolicy
  ValidateAdminCodeSignatures   = $k.ValidateAdminCodeSignatures
}
"""

ADMIN_PROMPT = {
    0: "Elevate without prompting",
    1: "Prompt for credentials on the secure desktop",
    2: "Prompt for consent on the secure desktop",
    3: "Prompt for credentials",
    4: "Prompt for consent",
    5: "Prompt for consent for non-Windows binaries (default)",
}
USER_PROMPT = {
    0: "Automatically deny elevation requests",
    1: "Prompt for credentials on the secure desktop",
    3: "Prompt for credentials",
}


class UACCollector(BaseCollector):
    name = "uac"
    category = "windows"
    description = "User Account Control policy configuration"
    profiles = ("quick", "standard", "full", "compliance")

    def collect(self, result: CollectorResult) -> None:
        ps = self.context.runner.run(SCRIPT, depth=3)
        result.collection_method = self.context.runner.describe_method(
            "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "UAC configuration returned nothing")
            return

        raw = ps.data
        enable_lua = integer(get(raw, "EnableLUA"))
        admin_prompt = integer(get(raw, "ConsentPromptBehaviorAdmin"))
        secure_desktop = integer(get(raw, "PromptOnSecureDesktop"))
        token_filter = integer(get(raw, "LocalAccountTokenFilterPolicy"))

        result.data = {
            "enabled": enable_lua == 1,
            "enable_lua_raw": enable_lua,
            "admin_prompt_behavior": ADMIN_PROMPT.get(
                admin_prompt if admin_prompt is not None else -1, "Unknown"
            ),
            "admin_prompt_raw": admin_prompt,
            "user_prompt_behavior": USER_PROMPT.get(
                integer(get(raw, "ConsentPromptBehaviorUser"), -1) or -1, "Unknown"
            ),
            "secure_desktop": secure_desktop == 1,
            "installer_detection": integer(get(raw, "EnableInstallerDetection")) == 1,
            "secure_uia_paths": integer(get(raw, "EnableSecureUIAPaths")) == 1,
            "virtualization": integer(get(raw, "EnableVirtualization")) == 1,
            "admin_approval_mode": integer(get(raw, "FilterAdministratorToken")) == 1,
            "local_account_token_filter_policy": token_filter,
            "remote_uac_filtering_disabled": token_filter == 1,
            "validate_admin_code_signatures": integer(
                get(raw, "ValidateAdminCodeSignatures")
            ) == 1,
            # Windows default for the built-in admin prompt is 5.
            "weakened_from_default": admin_prompt in (0, 4) or secure_desktop == 0,
        }

        if enable_lua is None:
            result.warn("EnableLUA value was not present in the registry.")
