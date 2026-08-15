"""Windows security configuration detection rules."""

from __future__ import annotations

from typing import Iterator

from app.models.finding import Confidence, FindingCategory, Severity
from app.services.analyzers.base import AnalysisContext, FindingDraft, analyzer
from app.services.risk_engine import ExposureLevel

MS_DOCS = "https://learn.microsoft.com/windows/security/"
CIS_BENCHMARK = "https://www.cisecurity.org/benchmark/microsoft_windows_desktop"


# ---------------------------------------------------------------------------
# Antivirus / Defender
# ---------------------------------------------------------------------------
@analyzer("defender")
def analyze_defender(ctx: AnalysisContext) -> Iterator[FindingDraft]:
    defender = ctx.data("defender")
    antivirus = ctx.data("antivirus")

    third_party = antivirus.get("third_party_antivirus") or []
    defender_installed = defender.get("installed", False)

    if not defender_installed and not antivirus.get("any_antivirus_enabled"):
        if antivirus:
            yield FindingDraft(
                rule_id="AV-001",
                title="No enabled antivirus product was detected",
                category=FindingCategory.ANTIVIRUS,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                description=(
                    "The Windows Security Center reports no antivirus product in an "
                    "enabled state, and Microsoft Defender is not available."
                ),
                impact=(
                    "Malware executing on this host would not be detected or blocked "
                    "by any real-time scanning engine."
                ),
                remediation=(
                    "Enable Microsoft Defender Antivirus, or install and enable a "
                    "supported third-party endpoint protection product."
                ),
                evidence={
                    "registered_products": antivirus.get("products", []),
                    "defender_installed": defender_installed,
                },
                evidence_summary="Security Center reports no enabled antivirus product.",
                detection_method="root/SecurityCenter2 AntiVirusProduct enumeration",
                security_control_disabled=True,
                references=[f"{MS_DOCS}threat-protection/microsoft-defender-antivirus/"],
                source_collector="antivirus",
            )
        return

    if not defender_installed:
        return

    if defender.get("real_time_protection") is False:
        severity = Severity.HIGH if third_party else Severity.CRITICAL
        yield FindingDraft(
            rule_id="DEF-001",
            title="Microsoft Defender real-time protection is disabled",
            category=FindingCategory.DEFENDER,
            severity=severity,
            confidence=Confidence.CONFIRMED,
            description=(
                "Get-MpComputerStatus reports RealTimeProtectionEnabled = false. "
                + (
                    f"A third-party product is present ({', '.join(third_party)}), "
                    "which may be handling protection instead."
                    if third_party
                    else "No third-party antivirus was detected on this host."
                )
            ),
            impact=(
                "Files are not scanned as they are written or executed, so malware "
                "can run without interception."
            ),
            remediation=(
                "Re-enable real-time protection in Windows Security, or via "
                "Set-MpPreference. If a third-party product manages protection, "
                "confirm it is enabled and up to date."
            ),
            remediation_command="Set-MpPreference -DisableRealtimeMonitoring $false",
            evidence={
                "real_time_protection": False,
                "third_party_antivirus": third_party,
                "antivirus_enabled": defender.get("antivirus_enabled"),
            },
            evidence_summary="RealTimeProtectionEnabled = false",
            detection_method="Get-MpComputerStatus",
            security_control_disabled=True,
            references=[f"{MS_DOCS}threat-protection/microsoft-defender-antivirus/"],
            source_collector="defender",
        )

    if defender.get("tamper_protection") is False:
        yield FindingDraft(
            rule_id="DEF-002",
            title="Microsoft Defender tamper protection is disabled",
            category=FindingCategory.DEFENDER,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            description=(
                "Tamper protection prevents Defender settings from being changed by "
                "anything other than the Windows Security app or managed policy. It "
                "is currently disabled."
            ),
            impact=(
                "An attacker who gains administrative rights can silently disable "
                "real-time protection, add exclusions or stop the service."
            ),
            remediation=(
                "Enable tamper protection in Windows Security > Virus & threat "
                "protection > Manage settings, or through Intune/Defender for "
                "Endpoint policy."
            ),
            evidence={"tamper_protection": False},
            evidence_summary="IsTamperProtected = false",
            detection_method="Get-MpComputerStatus / Windows Defender Features registry",
            security_control_disabled=True,
            references=[f"{MS_DOCS}threat-protection/microsoft-defender-antivirus/prevent-changes-to-security-settings-with-tamper-protection"],
            source_collector="defender",
        )

    broad = defender.get("broad_exclusions") or []
    if broad:
        yield FindingDraft(
            rule_id="DEF-003",
            title="Microsoft Defender has overly broad path exclusions",
            category=FindingCategory.DEFENDER,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            description=(
                "The following exclusion paths cover large parts of the filesystem, "
                f"so nothing beneath them is scanned: {', '.join(broad)}."
            ),
            impact=(
                "Malware placed inside an excluded directory is never scanned. Broad "
                "exclusions are a common persistence technique after compromise."
            ),
            remediation=(
                "Replace broad directory exclusions with narrowly scoped ones "
                "(specific files or process paths), and remove any exclusion that "
                "is no longer needed. Review exclusions with Get-MpPreference."
            ),
            remediation_command=(
                "Get-MpPreference | Select-Object -ExpandProperty ExclusionPath"
            ),
            evidence={
                "broad_exclusions": broad,
                "all_exclusions": defender.get("exclusions", {}),
            },
            evidence_summary=f"{len(broad)} broad exclusion path(s) configured.",
            detection_method="Get-MpPreference ExclusionPath",
            references=[f"{MS_DOCS}threat-protection/microsoft-defender-antivirus/configure-exclusions-microsoft-defender-antivirus"],
            source_collector="defender",
        )

    signatures = defender.get("signatures") or {}
    if signatures.get("out_of_date"):
        yield FindingDraft(
            rule_id="DEF-004",
            title="Microsoft Defender signatures are out of date",
            category=FindingCategory.DEFENDER,
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            description=(
                "Defender reports that its antimalware definitions are out of date. "
                f"Last update: {signatures.get('last_updated') or 'unknown'}."
            ),
            impact="Recently discovered malware families may not be detected.",
            remediation="Run Update-MpSignature, and confirm the host can reach Windows Update.",
            remediation_command="Update-MpSignature",
            evidence=signatures,
            evidence_summary="DefenderSignaturesOutOfDate = true",
            detection_method="Get-MpComputerStatus",
            source_collector="defender",
        )

    cloud = defender.get("cloud_protection") or {}
    if cloud.get("maps_raw") == 0:
        yield FindingDraft(
            rule_id="DEF-005",
            title="Microsoft Defender cloud-delivered protection is disabled",
            category=FindingCategory.DEFENDER,
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            description=(
                "MAPS (cloud-delivered protection) reporting is set to Disabled, so "
                "Defender cannot use cloud intelligence for fast-moving threats."
            ),
            impact=(
                "Detection of new and polymorphic malware is materially slower "
                "without cloud lookups."
            ),
            remediation="Enable cloud-delivered protection in Windows Security.",
            remediation_command="Set-MpPreference -MAPSReporting Advanced",
            evidence=cloud,
            evidence_summary="MAPSReporting = 0 (Disabled)",
            detection_method="Get-MpPreference",
            source_collector="defender",
        )

    features = defender.get("features") or {}
    if features.get("script_scanning_disabled"):
        yield FindingDraft(
            rule_id="DEF-006",
            title="Microsoft Defender script scanning is disabled",
            category=FindingCategory.DEFENDER,
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            description="DisableScriptScanning is set, so script content is not inspected.",
            impact="Malicious PowerShell, JScript and VBScript content is not scanned.",
            remediation="Re-enable script scanning.",
            remediation_command="Set-MpPreference -DisableScriptScanning $false",
            evidence=features,
            evidence_summary="DisableScriptScanning = true",
            detection_method="Get-MpPreference",
            source_collector="defender",
        )


@analyzer("amsi")
def analyze_amsi(ctx: AnalysisContext) -> Iterator[FindingDraft]:
    amsi = ctx.data("amsi")
    if not amsi:
        return

    dangling = amsi.get("dangling_providers") or []
    if dangling:
        yield FindingDraft(
            rule_id="AMSI-001",
            title="AMSI provider registered to a missing DLL",
            category=FindingCategory.SYSTEM,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description=(
                "One or more AMSI providers point at a COM server file that does not "
                "exist. A dangling provider registration can indicate a removed "
                "security product, or an attempt to hijack AMSI loading."
            ),
            impact=(
                "Script content may not be submitted for inspection, and the missing "
                "path could be used for DLL planting."
            ),
            remediation=(
                "Confirm which product owns the registration. Remove the orphaned "
                "CLSID entry if the product is no longer installed."
            ),
            evidence={"dangling_providers": dangling},
            evidence_summary=f"{len(dangling)} AMSI provider(s) reference a missing DLL.",
            detection_method="HKLM AMSI\\Providers CLSID resolution",
            source_collector="amsi",
        )

    if amsi.get("provider_count") == 0:
        yield FindingDraft(
            rule_id="AMSI-002",
            title="No AMSI providers are registered",
            category=FindingCategory.SYSTEM,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description=(
                "No antimalware provider is registered with the Antimalware Scan "
                "Interface, so script and macro content is not submitted for scanning."
            ),
            impact="Obfuscated script payloads execute without antimalware inspection.",
            remediation=(
                "Ensure an antimalware product that registers an AMSI provider is "
                "installed and running."
            ),
            evidence=amsi,
            evidence_summary="AMSI provider count = 0",
            detection_method="HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers",
            security_control_disabled=True,
            source_collector="amsi",
        )


# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------
@analyzer("firewall")
def analyze_firewall(ctx: AnalysisContext) -> Iterator[FindingDraft]:
    firewall = ctx.data("firewall")
    if not firewall:
        return

    disabled = firewall.get("disabled_profiles") or []
    if disabled:
        public_disabled = "Public" in disabled
        yield FindingDraft(
            rule_id="FW-001",
            title=f"Windows Firewall is disabled for the {', '.join(disabled)} profile(s)",
            category=FindingCategory.FIREWALL,
            severity=Severity.CRITICAL if public_disabled else Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            description=(
                "The host firewall is turned off for "
                f"{', '.join(disabled)}. Inbound connections to any listening "
                "service are unfiltered while that profile is active."
            ),
            impact=(
                "Every listening service becomes reachable from the network, "
                "removing the primary containment control against lateral movement."
            ),
            remediation=(
                "Re-enable the firewall for all profiles. If an application requires "
                "inbound access, create a narrowly scoped rule instead of disabling "
                "the profile."
            ),
            remediation_command=(
                "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
            ),
            evidence={
                "disabled_profiles": disabled,
                "profiles": firewall.get("profiles", []),
            },
            evidence_summary=f"Firewall disabled on: {', '.join(disabled)}",
            detection_method="Get-NetFirewallProfile",
            exposure=ExposureLevel.NETWORK,
            service_exposed=True,
            security_control_disabled=True,
            references=[f"{MS_DOCS}operating-system-security/network-security/windows-firewall/"],
            source_collector="firewall",
        )

    for rule in firewall.get("risky_rules") or []:
        ports = ", ".join(rule.get("local_ports") or []) or "any"
        yield FindingDraft(
            rule_id="FW-002",
            instance_key=rule.get("name", ports),
            title=f"Permissive inbound firewall rule: {rule.get('display_name') or rule.get('name')}",
            category=FindingCategory.FIREWALL,
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            description=(
                f"{rule.get('risk_reason')} Rule '{rule.get('display_name') or rule.get('name')}' "
                f"allows inbound {rule.get('protocol')} traffic on port(s) {ports}."
            ),
            impact=(
                "Any host that can route to this machine can reach the service "
                "behind this rule, widening the attack surface beyond what is "
                "usually intended."
            ),
            remediation=(
                "Restrict the rule's RemoteAddress to the specific hosts or subnets "
                "that need access, or disable the rule if it is no longer required."
            ),
            remediation_command=(
                f"Set-NetFirewallRule -Name '{rule.get('name')}' "
                "-RemoteAddress <authorized-subnet>"
            ),
            evidence=rule,
            evidence_summary=(
                f"Inbound allow, remote address any, ports {ports}, "
                f"profiles {', '.join(rule.get('profiles') or []) or 'all'}"
            ),
            detection_method="Get-NetFirewallRule with port and address filters",
            exposure=ExposureLevel.NETWORK,
            service_exposed=True,
            source_collector="firewall",
        )


# ---------------------------------------------------------------------------
# UAC
# ---------------------------------------------------------------------------
@analyzer("uac")
def analyze_uac(ctx: AnalysisContext) -> Iterator[FindingDraft]:
    uac = ctx.data("uac")
    if not uac:
        return

    if uac.get("enable_lua_raw") == 0:
        yield FindingDraft(
            rule_id="UAC-001",
            title="User Account Control is disabled",
            category=FindingCategory.POLICY,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            description=(
                "EnableLUA is set to 0, which turns off User Account Control "
                "entirely. All processes started by an administrator run fully "
                "elevated with no prompt."
            ),
            impact=(
                "Any code an administrator runs - including malware delivered by "
                "phishing - obtains full administrative rights silently."
            ),
            remediation=(
                "Set EnableLUA to 1 and restart. Configure the admin consent prompt "
                "to at least 'Prompt for consent on the secure desktop'."
            ),
            remediation_command=(
                "Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
                "\\Policies\\System' -Name EnableLUA -Value 1"
            ),
            evidence=uac,
            evidence_summary="EnableLUA = 0",
            detection_method="Policies\\System registry key",
            security_control_disabled=True,
            references=[f"{MS_DOCS}application-security/application-control/user-account-control/"],
            source_collector="uac",
        )
    elif uac.get("admin_prompt_raw") == 0:
        yield FindingDraft(
            rule_id="UAC-002",
            title="UAC elevates administrators without prompting",
            category=FindingCategory.POLICY,
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            description=(
                "ConsentPromptBehaviorAdmin is 0 ('Elevate without prompting'), so "
                "administrators are elevated silently."
            ),
            impact=(
                "A user has no opportunity to notice or refuse an unexpected "
                "elevation request."
            ),
            remediation="Set the admin consent prompt to 5 (the Windows default).",
            remediation_command=(
                "Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
                "\\Policies\\System' -Name ConsentPromptBehaviorAdmin -Value 5"
            ),
            evidence=uac,
            evidence_summary="ConsentPromptBehaviorAdmin = 0",
            detection_method="Policies\\System registry key",
            source_collector="uac",
        )

    if uac.get("enabled") and uac.get("secure_desktop") is False:
        yield FindingDraft(
            rule_id="UAC-003",
            title="UAC prompts are not shown on the secure desktop",
            category=FindingCategory.POLICY,
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            description=(
                "PromptOnSecureDesktop is 0, so elevation prompts render on the "
                "normal desktop where other processes can interact with them."
            ),
            impact="An attacker's process can spoof or automate the consent prompt.",
            remediation="Set PromptOnSecureDesktop to 1.",
            remediation_command=(
                "Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
                "\\Policies\\System' -Name PromptOnSecureDesktop -Value 1"
            ),
            evidence=uac,
            evidence_summary="PromptOnSecureDesktop = 0",
            detection_method="Policies\\System registry key",
            source_collector="uac",
        )

    if uac.get("remote_uac_filtering_disabled"):
        yield FindingDraft(
            rule_id="UAC-004",
            title="Remote UAC token filtering is disabled",
            category=FindingCategory.AUTHENTICATION,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            description=(
                "LocalAccountTokenFilterPolicy is 1, so local administrator accounts "
                "receive a full administrative token over the network rather than a "
                "filtered one."
            ),
            impact=(
                "Any local admin account can be used for full remote administration, "
                "which makes local-account credential reuse a lateral-movement path "
                "across every machine sharing that password."
            ),
            remediation=(
                "Remove LocalAccountTokenFilterPolicy unless a management tool "
                "specifically requires it, and use LAPS to ensure local admin "
                "passwords are unique per host."
            ),
            evidence=uac,
            evidence_summary="LocalAccountTokenFilterPolicy = 1",
            detection_method="Policies\\System registry key",
            exposure=ExposureLevel.NETWORK,
            source_collector="uac",
        )


# ---------------------------------------------------------------------------
# Accounts and groups
# ---------------------------------------------------------------------------
@analyzer("accounts")
def analyze_accounts(ctx: AnalysisContext) -> Iterator[FindingDraft]:
    users = ctx.data("local_users")
    groups = ctx.data("local_groups")

    if users:
        if users.get("guest_enabled"):
            yield FindingDraft(
                rule_id="ACC-001",
                title="The built-in Guest account is enabled",
                category=FindingCategory.ACCOUNTS,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                description=(
                    "The built-in Guest account is enabled. It is intended to be "
                    "disabled on all modern Windows installations."
                ),
                impact=(
                    "Guest provides an unauthenticated-equivalent logon path and can "
                    "be used to enumerate the system."
                ),
                remediation="Disable the Guest account.",
                remediation_command="Disable-LocalUser -Name 'Guest'",
                evidence={
                    "guest_accounts": [
                        u for u in users.get("users", []) if u.get("builtin_role") == "Guest"
                    ]
                },
                evidence_summary="Guest account Enabled = true",
                detection_method="Get-LocalUser",
                references=[CIS_BENCHMARK],
                source_collector="local_users",
            )

        no_password = users.get("accounts_without_password_required") or []
        if no_password:
            yield FindingDraft(
                rule_id="ACC-002",
                title="Enabled accounts do not require a password",
                category=FindingCategory.ACCOUNTS,
                severity=Severity.HIGH,
                # Microsoft-account and Windows Hello profiles legitimately report
                # PasswordRequired = false while still being credential protected,
                # so this needs operator confirmation rather than being asserted.
                confidence=Confidence.MEDIUM,
                description=(
                    "The following enabled local accounts have PasswordRequired = "
                    f"false: {', '.join(no_password)}. Note that accounts linked to a "
                    "Microsoft account or signed in with Windows Hello also report "
                    "this flag while remaining credential-protected - confirm each "
                    "account before treating it as passwordless."
                ),
                impact=(
                    "A genuinely passwordless account can be used to log on without "
                    "any credential, locally and potentially over the network."
                ),
                remediation=(
                    "Verify each account. Set a password on any local account that "
                    "truly has none, and disable accounts that are not needed."
                ),
                evidence={
                    "accounts": no_password,
                    "caveat": (
                        "PasswordRequired is false for Microsoft-account and Windows "
                        "Hello profiles even when a credential exists."
                    ),
                },
                evidence_summary=f"{len(no_password)} account(s) with PasswordRequired = false",
                detection_method="Get-LocalUser",
                source_collector="local_users",
            )

        policy = users.get("password_policy") or {}
        minimum_length = policy.get("min_password_length")
        if isinstance(minimum_length, int) and minimum_length < 14:
            severity = Severity.HIGH if minimum_length < 8 else Severity.MEDIUM
            yield FindingDraft(
                rule_id="ACC-003",
                title=f"Minimum password length is {minimum_length} characters",
                category=FindingCategory.POLICY,
                severity=severity,
                confidence=Confidence.CONFIRMED,
                description=(
                    f"The effective local password policy permits passwords of "
                    f"{minimum_length} characters. Current guidance is a minimum of "
                    "14 characters for local accounts."
                ),
                impact=(
                    "Short passwords are materially faster to crack offline once a "
                    "hash is obtained, and easier to guess online."
                ),
                remediation=(
                    "Raise the minimum password length to at least 14 characters via "
                    "Local Security Policy or Group Policy."
                ),
                remediation_command="net accounts /minpwlen:14",
                evidence=policy,
                evidence_summary=f"Minimum password length = {minimum_length}",
                detection_method="net accounts",
                references=[CIS_BENCHMARK],
                source_collector="local_users",
            )

        lockout = policy.get("lockout_threshold")
        if lockout == 0 or (lockout is None and "lockout_threshold_raw" in policy):
            yield FindingDraft(
                rule_id="ACC-004",
                title="Account lockout is not configured",
                category=FindingCategory.POLICY,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                description=(
                    "The account lockout threshold is set to 'Never', so an "
                    "unlimited number of failed logon attempts is permitted."
                ),
                impact="Online password guessing against local accounts is unthrottled.",
                remediation=(
                    "Configure a lockout threshold (commonly 10 attempts) with a "
                    "lockout duration and observation window of at least 15 minutes."
                ),
                remediation_command="net accounts /lockoutthreshold:10 /lockoutduration:15",
                evidence=policy,
                evidence_summary="Lockout threshold = Never",
                detection_method="net accounts",
                references=[CIS_BENCHMARK],
                source_collector="local_users",
            )

        auto_logon = users.get("auto_logon") or {}
        if auto_logon.get("enabled") and auto_logon.get("stored_password_present"):
            yield FindingDraft(
                rule_id="ACC-005",
                title="Automatic logon is configured with a stored password",
                category=FindingCategory.ACCOUNTS,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                description=(
                    "AutoAdminLogon is enabled and a DefaultPassword value is present "
                    "in the Winlogon registry key. VulScanner detected the presence "
                    "of the value only and did not read it."
                ),
                impact=(
                    "The password is recoverable by any process able to read that "
                    "registry key, and the machine logs on without authentication."
                ),
                remediation=(
                    "Disable automatic logon and delete the DefaultPassword value. If "
                    "auto-logon is required for a kiosk, use the Autologon tool which "
                    "stores the secret in LSA rather than the registry."
                ),
                evidence={
                    "auto_admin_logon": True,
                    "default_username": auto_logon.get("default_username"),
                    "password_value_read": False,
                },
                evidence_summary="AutoAdminLogon = 1 with DefaultPassword value present",
                detection_method="Winlogon registry key (value presence only)",
                source_collector="local_users",
            )

    if groups:
        administrators = groups.get("administrators") or {}
        unexpected = administrators.get("unexpected_members") or []
        if len(unexpected) > 1:
            names = ", ".join(m.get("name", "?") for m in unexpected)
            yield FindingDraft(
                rule_id="ACC-006",
                title=f"{len(unexpected)} non-default accounts are local administrators",
                category=FindingCategory.ACCOUNTS,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description=(
                    f"The local Administrators group contains: {names}. Each "
                    "additional administrator increases the number of accounts whose "
                    "compromise leads directly to full control of this host."
                ),
                impact=(
                    "Administrative rights allow disabling security controls, "
                    "installing persistence and accessing all user data."
                ),
                remediation=(
                    "Review each member. Remove accounts that do not require standing "
                    "administrative rights and use a separate admin account for "
                    "administrative work."
                ),
                remediation_command="Get-LocalGroupMember -Group 'Administrators'",
                evidence={"members": administrators.get("members", [])},
                evidence_summary=(
                    f"Administrators group has {administrators.get('member_count')} members."
                ),
                detection_method="Get-LocalGroupMember",
                source_collector="local_groups",
            )
