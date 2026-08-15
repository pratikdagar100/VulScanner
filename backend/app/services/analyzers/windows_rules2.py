"""Windows detection rules: RDP, authentication, boot integrity, logging,
autoruns, certificates, secrets exposure and patch posture."""

from __future__ import annotations

from typing import Iterator

from app.models.finding import Confidence, FindingCategory, Severity
from app.services.analyzers.base import AnalysisContext, FindingDraft, analyzer
from app.services.risk_engine import ExposureLevel

MS_DOCS = "https://learn.microsoft.com/windows/security/"
CIS_BENCHMARK = "https://www.cisecurity.org/benchmark/microsoft_windows_desktop"


# ---------------------------------------------------------------------------
# Remote Desktop
# ---------------------------------------------------------------------------
@analyzer("rdp")
def analyze_rdp(ctx: AnalysisContext) -> Iterator[FindingDraft]:
    rdp = ctx.data("rdp")
    if not rdp or rdp.get("deny_connections_raw") is None:
        return
    if not rdp.get("enabled"):
        return

    exposed = rdp.get("network_exposed")
    profiles_allowing = rdp.get("firewall_profiles_allowing") or []
    public_exposure = any("Public" in p for p in profiles_allowing)

    if not rdp.get("nla_enabled"):
        yield FindingDraft(
            rule_id="RDP-001",
            title="Remote Desktop is enabled without Network Level Authentication",
            category=FindingCategory.RDP,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            description=(
                "RDP is enabled and UserAuthentication is 0, so a session is "
                "established before the user authenticates."
            ),
            impact=(
                "Pre-authentication attack surface is exposed to anyone who can "
                "reach the RDP port, and the host is more susceptible to "
                "denial-of-service and credential-relay attacks."
            ),
            remediation=(
                "Require Network Level Authentication for Remote Desktop connections."
            ),
            remediation_command=(
                "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal "
                "Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1"
            ),
            evidence={
                "nla_enabled": False,
                "security_layer": rdp.get("security_layer"),
                "port": rdp.get("port"),
                "network_exposed": exposed,
            },
            evidence_summary="UserAuthentication = 0 with RDP enabled",
            detection_method="Terminal Server WinStations\\RDP-Tcp registry key",
            exposure=ExposureLevel.INTERNET if public_exposure
            else (ExposureLevel.NETWORK if exposed else ExposureLevel.LOCAL),
            service_exposed=bool(exposed),
            references=[f"{MS_DOCS}operating-system-security/network-security/"],
            source_collector="rdp",
        )

    if exposed:
        severity = Severity.HIGH if public_exposure else Severity.MEDIUM
        yield FindingDraft(
            rule_id="RDP-002",
            title="Remote Desktop is reachable from the network",
            category=FindingCategory.EXPOSURE,
            severity=severity,
            confidence=Confidence.CONFIRMED,
            description=(
                f"RDP is listening on port {rdp.get('port')} and an enabled inbound "
                f"firewall rule permits access on the "
                f"{', '.join(profiles_allowing) or 'active'} profile(s)."
                + (
                    " This includes the Public profile, which applies on untrusted "
                    "networks."
                    if public_exposure
                    else ""
                )
            ),
            impact=(
                "RDP is one of the most heavily targeted services for credential "
                "stuffing, password spraying and ransomware initial access."
            ),
            remediation=(
                "Restrict the Remote Desktop firewall rules to specific management "
                "subnets, require a VPN or RD Gateway for remote access, and disable "
                "RDP on the Public profile."
            ),
            remediation_command=(
                "Set-NetFirewallRule -DisplayGroup 'Remote Desktop' "
                "-RemoteAddress <management-subnet>"
            ),
            evidence={
                "port": rdp.get("port"),
                "listening_endpoints": rdp.get("listening_endpoints"),
                "firewall_profiles_allowing": profiles_allowing,
                "nla_enabled": rdp.get("nla_enabled"),
            },
            evidence_summary=(
                f"Listening on {rdp.get('port')}; inbound allowed on "
                f"{', '.join(profiles_allowing) or 'unknown profile'}"
            ),
            detection_method="Get-NetTCPConnection and Remote Desktop firewall group",
            exposure=ExposureLevel.INTERNET if public_exposure else ExposureLevel.NETWORK,
            service_exposed=True,
            source_collector="rdp",
        )

    if rdp.get("security_layer_raw") == 0:
        yield FindingDraft(
            rule_id="RDP-003",
            title="Remote Desktop uses the legacy RDP security layer",
            category=FindingCategory.RDP,
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            description=(
                "SecurityLayer is 0, so the connection uses native RDP encryption "
                "rather than TLS, and the server is not authenticated to the client."
            ),
            impact="Sessions are susceptible to man-in-the-middle interception.",
            remediation="Set the security layer to SSL/TLS (2).",
            remediation_command=(
                "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal "
                "Server\\WinStations\\RDP-Tcp' -Name SecurityLayer -Value 2"
            ),
            evidence={"security_layer_raw": 0},
            evidence_summary="SecurityLayer = 0 (legacy RDP encryption)",
            detection_method="RDP-Tcp registry key",
            exposure=ExposureLevel.NETWORK if exposed else ExposureLevel.LOCAL,
            source_collector="rdp",
        )


# ---------------------------------------------------------------------------
# Authentication hardening
# ---------------------------------------------------------------------------
@analyzer("authentication")
def analyze_authentication(ctx: AnalysisContext) -> Iterator[FindingDraft]:
    ntlm = ctx.data("ntlm")
    if not ntlm:
        return

    if ntlm.get("smb1_enabled"):
        yield FindingDraft(
            rule_id="AUTH-001",
            title="SMBv1 is enabled",
            category=FindingCategory.NETWORK,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            description=(
                "The SMB server has SMB1 enabled. SMBv1 is deprecated, lacks "
                "pre-authentication integrity, and is the protocol exploited by "
                "EternalBlue-class attacks and the WannaCry/NotPetya families."
            ),
            impact=(
                "The host is exposed to well-known remote code execution and "
                "man-in-the-middle techniques that do not affect SMBv2/3."
            ),
            remediation="Remove the SMB1 protocol feature and disable it on the server.",
            remediation_command=(
                "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
            ),
            evidence={"smb1_enabled": True},
            evidence_summary="LanmanServer SMB1 = 1",
            detection_method="LanmanServer parameters registry key",
            exposure=ExposureLevel.NETWORK,
            service_exposed=True,
            references=[
                "https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"
            ],
            source_collector="ntlm",
        )

    if ntlm.get("wdigest_plaintext_credentials"):
        yield FindingDraft(
            rule_id="AUTH-002",
            title="WDigest is configured to keep plaintext credentials in memory",
            category=FindingCategory.AUTHENTICATION,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            description=(
                "UseLogonCredential is set to 1 under the WDigest security provider, "
                "which makes Windows cache logon credentials in reversible form in "
                "LSASS memory."
            ),
            impact=(
                "An attacker with administrative rights can recover cleartext "
                "passwords from memory rather than only hashes."
            ),
            remediation="Set UseLogonCredential to 0 (or remove the value) and reboot.",
            remediation_command=(
                "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\"
                "SecurityProviders\\WDigest' -Name UseLogonCredential -Value 0"
            ),
            evidence={"use_logon_credential": 1},
            evidence_summary="WDigest UseLogonCredential = 1",
            detection_method="WDigest registry key",
            source_collector="ntlm",
        )

    level = ntlm.get("lm_compatibility_level")
    if isinstance(level, int) and level < 3:
        yield FindingDraft(
            rule_id="AUTH-003",
            title=f"Weak NTLM compatibility level ({level})",
            category=FindingCategory.AUTHENTICATION,
            severity=Severity.HIGH if level < 2 else Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            description=(
                f"LmCompatibilityLevel is {level}: {ntlm.get('lm_compatibility_description')}. "
                "Levels below 3 permit LM or NTLMv1 responses."
            ),
            impact=(
                "LM and NTLMv1 responses can be cracked or relayed far more easily "
                "than NTLMv2, enabling credential recovery and relay attacks."
            ),
            remediation=(
                "Set LmCompatibilityLevel to 5 (send NTLMv2 only, refuse LM and NTLM) "
                "after confirming no legacy system depends on the older protocols."
            ),
            evidence={"lm_compatibility_level": level},
            evidence_summary=f"LmCompatibilityLevel = {level}",
            detection_method="LSA registry key",
            exposure=ExposureLevel.NETWORK,
            references=[CIS_BENCHMARK],
            source_collector="ntlm",
        )

    if ntlm.get("smb_server_signing_required") is False:
        yield FindingDraft(
            rule_id="AUTH-004",
            title="SMB server signing is not required",
            category=FindingCategory.AUTHENTICATION,
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            description=(
                "RequireSecuritySignature is 0 on the SMB server, so clients may "
                "negotiate unsigned sessions."
            ),
            impact=(
                "Unsigned SMB sessions can be relayed, allowing an attacker to "
                "authenticate to this host using a victim's captured session."
            ),
            remediation="Require SMB signing on both the server and the client.",
            remediation_command="Set-SmbServerConfiguration -RequireSecuritySignature $true",
            evidence={"smb_server_signing_required": False},
            evidence_summary="LanmanServer RequireSecuritySignature = 0",
            detection_method="LanmanServer parameters registry key",
            exposure=ExposureLevel.NETWORK,
            references=[CIS_BENCHMARK],
            source_collector="ntlm",
        )

    if ntlm.get("lsa_protection_ppl") is False:
        yield FindingDraft(
            rule_id="AUTH-005",
            title="LSA protection (RunAsPPL) is not enabled",
            category=FindingCategory.AUTHENTICATION,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description=(
                "RunAsPPL is not enabled, so LSASS does not run as a protected "
                "process and its memory is more readily accessible."
            ),
            impact=(
                "Credential-dumping tools can read LSASS memory more easily once "
                "administrative rights are obtained."
            ),
            remediation=(
                "Enable LSA protection by setting RunAsPPL to 1 and rebooting. "
                "Validate driver compatibility first."
            ),
            evidence={"run_as_ppl": ntlm.get("lsa_protection_raw")},
            evidence_summary="LSA RunAsPPL not enabled",
            detection_method="LSA registry key",
            references=[f"{MS_DOCS}identity-protection/credential-guard/"],
            source_collector="ntlm",
        )


# ---------------------------------------------------------------------------
# Boot integrity and disk encryption
# ---------------------------------------------------------------------------
@analyzer("boot_integrity")
def analyze_boot_integrity(ctx: AnalysisContext) -> Iterator[FindingDraft]:
    boot = ctx.data("secure_boot")
    if not boot:
        return

    if boot.get("secure_boot_enabled") is False:
        yield FindingDraft(
            rule_id="BOOT-001",
            title="Secure Boot is disabled",
            category=FindingCategory.BOOT_INTEGRITY,
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            description=(
                "The platform supports Secure Boot but it is currently turned off, "
                "so the firmware does not verify the signature of the bootloader."
            ),
            impact="Bootkits and unsigned boot components can load before Windows.",
            remediation="Enable Secure Boot in UEFI firmware settings.",
            evidence={"secure_boot_enabled": False, "firmware": boot.get("firmware_type")},
            evidence_summary="Confirm-SecureBootUEFI returned false",
            detection_method="Confirm-SecureBootUEFI",
            source_collector="secure_boot",
        )

    bitlocker = boot.get("bitlocker") or {}
    volumes = bitlocker.get("volumes") or []
    if volumes and not bitlocker.get("os_volume_protected"):
        yield FindingDraft(
            rule_id="BOOT-002",
            title="The operating system volume is not encrypted with BitLocker",
            category=FindingCategory.BOOT_INTEGRITY,
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            description=(
                "BitLocker protection is not on for the operating system volume."
            ),
            impact=(
                "Anyone with physical access to the disk can read all data by "
                "booting another operating system or removing the drive."
            ),
            remediation=(
                "Enable BitLocker on the OS volume with TPM protection, and store "
                "recovery keys in a managed location."
            ),
            remediation_command="Enable-BitLocker -MountPoint C: -TpmProtector",
            evidence={"volumes": volumes},
            evidence_summary="OS volume ProtectionStatus is not 'On'",
            detection_method="Get-BitLockerVolume",
            exposure=ExposureLevel.LOCAL,
            source_collector="secure_boot",
        )

    device_guard = boot.get("device_guard") or {}
    tpm = boot.get("tpm") or {}
    if (
        tpm.get("present")
        and boot.get("secure_boot_enabled")
        and device_guard.get("credential_guard_running") is False
    ):
        yield FindingDraft(
            rule_id="BOOT-003",
            title="Credential Guard is not running",
            category=FindingCategory.AUTHENTICATION,
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            description=(
                "The hardware supports virtualization-based security (TPM present, "
                "Secure Boot enabled) but Credential Guard is not running."
            ),
            impact=(
                "Domain credentials and NTLM secrets in LSASS are not isolated by "
                "the hypervisor and remain extractable by an administrator-level "
                "attacker."
            ),
            remediation=(
                "Enable Virtualization-Based Security and Credential Guard through "
                "Group Policy or Intune, after validating application compatibility."
            ),
            evidence=device_guard,
            evidence_summary=(
                f"VBS status: {device_guard.get('vbs_status')}; running services: "
                f"{device_guard.get('services_running')}"
            ),
            detection_method="Win32_DeviceGuard",
            references=[f"{MS_DOCS}identity-protection/credential-guard/"],
            source_collector="secure_boot",
        )


# ---------------------------------------------------------------------------
# Logging and detection capability
# ---------------------------------------------------------------------------
@analyzer("logging")
def analyze_logging(ctx: AnalysisContext) -> Iterator[FindingDraft]:
    audit = ctx.data("audit_policy")
    powershell = ctx.data("powershell")

    gaps = (audit.get("coverage_gaps") or []) if audit else []
    high_gaps = [g for g in gaps if g.get("severity") == "high"]
    if high_gaps:
        names = ", ".join(g["subcategory"] for g in high_gaps)
        yield FindingDraft(
            rule_id="LOG-001",
            title="Security-critical audit subcategories are not being audited",
            category=FindingCategory.LOGGING,
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            description=(
                f"The following audit subcategories are set to 'No Auditing': {names}. "
                "Without them the Security log will not record the corresponding "
                "events."
            ),
            impact=(
                "Incident responders cannot reconstruct logons, privilege use or "
                "account changes, materially reducing detection and forensic "
                "capability."
            ),
            remediation=(
                "Enable the missing subcategories through Advanced Audit Policy "
                "Configuration, following the Microsoft audit policy recommendations."
            ),
            remediation_command=(
                'auditpol /set /subcategory:"Logon" /success:enable /failure:enable'
            ),
            evidence={"coverage_gaps": gaps},
            evidence_summary=f"{len(high_gaps)} critical audit subcategories disabled.",
            detection_method="auditpol /get /category:*",
            references=[
                "https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations"
            ],
            source_collector="audit_policy",
        )

    if audit and audit.get("security_log_small"):
        log = audit.get("security_log") or {}
        size_mb = round((log.get("max_size_bytes") or 0) / (1024 * 1024), 1)
        yield FindingDraft(
            rule_id="LOG-002",
            title=f"The Security event log is limited to {size_mb} MB",
            category=FindingCategory.LOGGING,
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            description=(
                f"The Security log maximum size is {size_mb} MB. On a busy host this "
                "can wrap within hours, discarding evidence before it is collected."
            ),
            impact="Security events may be overwritten before they can be reviewed.",
            remediation=(
                "Increase the Security log to at least 256 MB, and forward events to "
                "a central collector."
            ),
            remediation_command=(
                "wevtutil sl Security /ms:268435456"
            ),
            evidence=log,
            evidence_summary=f"Security log MaximumSizeInBytes = {log.get('max_size_bytes')}",
            detection_method="Get-WinEvent -ListLog Security",
            source_collector="audit_policy",
        )

    if powershell:
        logging_config = powershell.get("logging") or {}
        if not logging_config.get("script_block_logging"):
            yield FindingDraft(
                rule_id="LOG-003",
                title="PowerShell script block logging is not enabled",
                category=FindingCategory.LOGGING,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description=(
                    "EnableScriptBlockLogging is not set, so PowerShell does not "
                    "record the content of executed script blocks to the event log."
                ),
                impact=(
                    "Obfuscated or fileless PowerShell activity leaves little "
                    "forensic evidence."
                ),
                remediation=(
                    "Enable PowerShell script block logging via Group Policy "
                    "(Administrative Templates > Windows Components > Windows "
                    "PowerShell)."
                ),
                evidence=logging_config,
                evidence_summary="EnableScriptBlockLogging not configured",
                detection_method="PowerShell ScriptBlockLogging policy key",
                source_collector="powershell",
            )

        if powershell.get("powershell_v2_engine_present"):
            yield FindingDraft(
                rule_id="LOG-004",
                title="The PowerShell 2.0 engine is installed",
                category=FindingCategory.SYSTEM,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description=(
                    "The legacy PowerShell 2.0 engine is present. It predates script "
                    "block logging, AMSI and constrained language mode."
                ),
                impact=(
                    "An attacker can invoke 'powershell -version 2' to bypass modern "
                    "logging and antimalware inspection entirely."
                ),
                remediation="Remove the PowerShell 2.0 optional feature.",
                remediation_command=(
                    "Disable-WindowsOptionalFeature -Online -FeatureName "
                    "MicrosoftWindowsPowerShellV2Root"
                ),
                evidence={"engines": powershell.get("engines")},
                evidence_summary="PowerShell engine version 2 registered as installed",
                detection_method="HKLM PowerShell engine registry keys",
                source_collector="powershell",
            )

    sysmon = ctx.data("sysmon")
    if sysmon and not sysmon.get("installed"):
        yield FindingDraft(
            rule_id="LOG-005",
            title="Sysmon is not installed",
            category=FindingCategory.LOGGING,
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            description=(
                "Sysmon is not present. It is optional, but it is the standard way "
                "to obtain process-creation, network-connection and image-load "
                "telemetry on Windows endpoints."
            ),
            impact=(
                "Endpoint telemetry is limited to what the built-in audit policy "
                "records, which is substantially less detailed."
            ),
            remediation=(
                "Deploy Sysmon with a reviewed configuration if the organisation "
                "relies on host telemetry for detection."
            ),
            evidence={"installed": False},
            evidence_summary="No Sysmon service, driver or binary found.",
            detection_method="Win32_Service, SysmonDrv and binary presence checks",
            configuration_weakness=False,
            source_collector="sysmon",
        )


# ---------------------------------------------------------------------------
# Autoruns
# ---------------------------------------------------------------------------
@analyzer("autoruns")
def analyze_autoruns(ctx: AnalysisContext) -> Iterator[FindingDraft]:
    autoruns = ctx.data("autoruns")
    if not autoruns:
        return

    high_risk = autoruns.get("high_risk_entries") or []
    for entry in high_risk[:25]:
        yield FindingDraft(
            rule_id="RUN-001",
            instance_key=f"{entry.get('kind')}:{entry.get('name')}",
            title=f"High-risk autorun entry: {entry.get('name')}",
            category=FindingCategory.AUTORUN,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description=(
                f"The autorun entry '{entry.get('name')}' ({entry.get('kind')}) "
                f"targets {entry.get('path') or entry.get('command')}. "
                + " ".join(entry.get("risk_reasons") or [])
            ),
            impact=(
                "Unsigned executables in user-writable locations that run "
                "automatically are a common persistence mechanism, and the file can "
                "be replaced by any user who can write to that directory."
            ),
            remediation=(
                "Verify the entry is expected and that its publisher is legitimate. "
                "Remove it if unrecognised, and move required binaries into a "
                "directory that only administrators can write to."
            ),
            evidence=entry,
            evidence_summary=(
                f"{entry.get('kind')} entry, signature: {entry.get('signature_status')}"
            ),
            detection_method="Run keys, Startup folders, services and scheduled tasks",
            source_collector="autoruns",
        )

    missing = autoruns.get("missing_targets") or []
    if len(missing) > 2:
        yield FindingDraft(
            rule_id="RUN-002",
            title=f"{len(missing)} autorun entries point at files that do not exist",
            category=FindingCategory.AUTORUN,
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            description=(
                "Several autorun entries reference executables that are missing. "
                "These are usually leftovers from uninstalled software, but a "
                "writable missing path can be claimed by an attacker."
            ),
            impact=(
                "If the referenced path is user-writable, planting a file there "
                "yields automatic execution."
            ),
            remediation="Remove the stale autorun entries.",
            evidence={"entries": missing[:20], "total": len(missing)},
            evidence_summary=f"{len(missing)} autorun targets missing on disk.",
            detection_method="Autorun path resolution",
            source_collector="autoruns",
        )


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------
@analyzer("certificates")
def analyze_certificates(ctx: AnalysisContext) -> Iterator[FindingDraft]:
    certificates = ctx.data("certificates")
    if not certificates:
        return

    trust_issues = certificates.get("weak_in_trust_stores") or []
    if trust_issues:
        yield FindingDraft(
            rule_id="CERT-001",
            title=f"{len(trust_issues)} expired or weak certificates in trust stores",
            category=FindingCategory.CERTIFICATE,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description=(
                "Certificates in the Root, CA or TrustedPublisher stores are either "
                "expired or use a weak signature algorithm or key size."
            ),
            impact=(
                "A weak or unexpected trust anchor can allow forged certificates to "
                "be accepted, enabling interception of TLS traffic or trust of "
                "unsigned code."
            ),
            remediation=(
                "Review each certificate. Remove expired or unrecognised trust "
                "anchors, and replace weak certificates with SHA-256 / RSA-2048 or "
                "stronger equivalents."
            ),
            evidence={
                "certificates": [
                    {
                        "subject": c.get("subject"),
                        "issuer": c.get("issuer"),
                        "store": c.get("store"),
                        "thumbprint": c.get("thumbprint"),
                        "not_after": c.get("not_after"),
                        "signature_algorithm": c.get("signature_algorithm"),
                        "key_size": c.get("key_size"),
                        "issues": c.get("issues"),
                    }
                    for c in trust_issues[:25]
                ],
                "total": len(trust_issues),
            },
            evidence_summary=f"{len(trust_issues)} problematic certificates in trust stores.",
            detection_method="Cert: store enumeration (metadata only)",
            source_collector="certificates",
        )

    expiring = [
        c
        for c in (certificates.get("expiring_soon") or [])
        if c.get("has_private_key")
    ]
    if expiring:
        yield FindingDraft(
            rule_id="CERT-002",
            title=f"{len(expiring)} certificates with private keys expire within 30 days",
            category=FindingCategory.CERTIFICATE,
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            description=(
                "Certificates held with a private key on this host are close to "
                "expiry. VulScanner reads metadata only and never touches key material."
            ),
            impact="Services relying on these certificates will fail once they expire.",
            remediation="Renew the certificates before their expiry date.",
            evidence={
                "certificates": [
                    {
                        "subject": c.get("subject"),
                        "store": c.get("store"),
                        "not_after": c.get("not_after"),
                        "days_remaining": c.get("days_remaining"),
                    }
                    for c in expiring[:25]
                ]
            },
            evidence_summary=f"{len(expiring)} certificates expiring within 30 days.",
            detection_method="Cert: store enumeration (metadata only)",
            configuration_weakness=False,
            source_collector="certificates",
        )


# ---------------------------------------------------------------------------
# Secret exposure
# ---------------------------------------------------------------------------
@analyzer("secrets")
def analyze_secrets(ctx: AnalysisContext) -> Iterator[FindingDraft]:
    history = ctx.data("powershell_history")
    environment = ctx.data("environment")

    exposures = (history.get("secret_exposures") or []) if history else []
    if exposures:
        types = sorted({e["type"] for e in exposures})
        yield FindingDraft(
            rule_id="SEC-001",
            title=f"Credentials found in PowerShell history ({len(exposures)} occurrences)",
            category=FindingCategory.SECRETS,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description=(
                "PowerShell console history contains command lines matching "
                f"credential patterns: {', '.join(types)}. VulScanner redacted every "
                "matched value at detection time and did not store any secret."
            ),
            impact=(
                "History files are plain text, readable by the user and by anyone "
                "with access to the profile. Any credential typed on the command "
                "line should be treated as compromised."
            ),
            remediation=(
                "Rotate the affected credentials. Clear the history file, and use "
                "Get-Credential or a secret manager instead of passing secrets as "
                "command-line arguments."
            ),
            remediation_command=(
                "Remove-Item (Get-PSReadLineOption).HistorySavePath"
            ),
            evidence={
                "occurrences": [
                    {
                        "type": e["type"],
                        "file": e["file"],
                        "line_number": e["line_number"],
                        "redacted_line": e["redacted_line"],
                    }
                    for e in exposures[:30]
                ],
                "total": len(exposures),
                "note": "Secret values were redacted before storage.",
            },
            evidence_summary=f"{len(exposures)} credential-shaped entries (values redacted).",
            detection_method="PSReadLine history pattern analysis with redaction",
            source_collector="powershell_history",
        )

    risky = (history.get("risky_commands") or []) if history else []
    if len(risky) >= 3:
        types = sorted({r["type"] for r in risky})
        yield FindingDraft(
            rule_id="SEC-002",
            title="Security-relevant commands found in PowerShell history",
            category=FindingCategory.SECRETS,
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            description=(
                "PowerShell history contains commands that weaken security controls "
                f"or download and execute remote content: {', '.join(types)}. These "
                "may be legitimate administration, and are reported for review."
            ),
            impact=(
                "If these commands were not run by an authorized administrator, they "
                "indicate that controls were deliberately weakened."
            ),
            remediation=(
                "Confirm each command was expected. Investigate any that were not."
            ),
            evidence={"commands": risky[:30], "total": len(risky)},
            evidence_summary=f"{len(risky)} security-relevant commands in history.",
            detection_method="PSReadLine history pattern analysis",
            configuration_weakness=False,
            source_collector="powershell_history",
        )

    env_secrets = (environment.get("suspected_secret_variables") or []) if environment else []
    if env_secrets:
        yield FindingDraft(
            rule_id="SEC-003",
            title=f"{len(env_secrets)} environment variables appear to hold credentials",
            category=FindingCategory.SECRETS,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            description=(
                "Persistent environment variables have names or values matching "
                "credential patterns. Their values were redacted and never stored."
            ),
            impact=(
                "Environment variables are readable by every process running as that "
                "user and are frequently captured by malware and crash dumps."
            ),
            remediation=(
                "Move secrets into a credential store (Windows Credential Manager, "
                "Azure Key Vault, or an equivalent) and remove the variables."
            ),
            evidence={"variables": env_secrets},
            evidence_summary=f"{len(env_secrets)} credential-shaped environment variables.",
            detection_method="Machine and user environment variable name/value analysis",
            source_collector="environment",
        )

    writable_path = (environment.get("writable_path_entries") or []) if environment else []
    if writable_path:
        yield FindingDraft(
            rule_id="SEC-004",
            title="System PATH contains user-writable directories",
            category=FindingCategory.FILESYSTEM,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description=(
                "The machine PATH includes directories that non-administrative users "
                f"can write to: {', '.join(p['entry'] for p in writable_path)}."
            ),
            impact=(
                "A standard user can plant an executable in one of these directories "
                "and have it executed by a privileged process that resolves a command "
                "by name, escalating privileges."
            ),
            remediation=(
                "Remove the writable directories from the system PATH, or tighten "
                "their ACLs so only administrators can write to them."
            ),
            evidence={"entries": writable_path},
            evidence_summary=f"{len(writable_path)} writable PATH directories.",
            detection_method="Get-Acl on each machine PATH entry",
            source_collector="environment",
        )


# ---------------------------------------------------------------------------
# Patch posture
# ---------------------------------------------------------------------------
@analyzer("patching")
def analyze_patching(ctx: AnalysisContext) -> Iterator[FindingDraft]:
    updates = ctx.data("updates")
    os_data = ctx.data("os")

    if updates:
        pending = updates.get("pending_updates") or []
        security_pending = [u for u in pending if u.get("is_security_update")]
        if security_pending and updates.get("evidence_quality") == "windows-update-agent":
            critical = [
                u for u in security_pending if u.get("msrc_severity", "").lower() == "critical"
            ]
            kbs = sorted({kb for u in security_pending for kb in u.get("kbs", [])})
            yield FindingDraft(
                rule_id="PATCH-001",
                title=f"{len(security_pending)} security updates are pending installation",
                category=FindingCategory.PATCH,
                severity=Severity.CRITICAL if critical else Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                description=(
                    "The Windows Update agent reports these security updates as "
                    "applicable to this host and not installed: "
                    + ", ".join(u["title"] for u in security_pending[:5])
                    + ("..." if len(security_pending) > 5 else "")
                ),
                impact=(
                    "The host remains vulnerable to the issues these updates fix, "
                    "including any with public exploit code."
                ),
                remediation=(
                    "Install the pending updates and reboot. Confirm Windows Update "
                    "is able to reach its configured source."
                ),
                remediation_command="Install-WindowsUpdate -AcceptAll -AutoReboot",
                evidence={
                    "pending_updates": pending,
                    "kbs": kbs,
                    "source": "Microsoft.Update.Session searcher (IsInstalled=0)",
                },
                evidence_summary=(
                    f"{len(security_pending)} pending security updates"
                    + (f", {len(critical)} rated Critical by MSRC" if critical else "")
                ),
                detection_method="Windows Update agent applicability search",
                patch_missing=True,
                patch_available=True,
                source_collector="updates",
            )

        if updates.get("pending_reboot"):
            yield FindingDraft(
                rule_id="PATCH-002",
                title="A reboot is pending to complete update installation",
                category=FindingCategory.PATCH,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                description=(
                    "A servicing operation has staged changes that only take effect "
                    "after a restart."
                ),
                impact=(
                    "Security fixes that are already downloaded are not yet active on "
                    "this host."
                ),
                remediation="Restart the machine at the next opportunity.",
                evidence={"pending_reboot": True},
                evidence_summary="RebootPending / RebootRequired registry key present",
                detection_method="Component Based Servicing and WindowsUpdate registry keys",
                configuration_weakness=False,
                source_collector="updates",
            )

        automatic = updates.get("automatic_updates") or {}
        service = updates.get("service") or {}
        if automatic.get("disabled") or service.get("disabled"):
            yield FindingDraft(
                rule_id="PATCH-003",
                title="Automatic Windows updates are disabled",
                category=FindingCategory.PATCH,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                description=(
                    "Automatic updating is turned off"
                    + (
                        " and the Windows Update service is disabled."
                        if service.get("disabled")
                        else "."
                    )
                ),
                impact=(
                    "Security updates will not install on their own, so the host will "
                    "progressively fall behind on patches."
                ),
                remediation=(
                    "Re-enable automatic updates, or ensure the host is patched by a "
                    "managed process such as WSUS, Intune or Configuration Manager."
                ),
                evidence={"automatic_updates": automatic, "service": service},
                evidence_summary="NoAutoUpdate set or wuauserv disabled",
                detection_method="Windows Update registry configuration and service state",
                security_control_disabled=True,
                source_collector="updates",
            )

    if os_data:
        end_of_servicing = os_data.get("end_of_servicing")
        if end_of_servicing:
            yield FindingDraft(
                rule_id="PATCH-004",
                title=(
                    f"Windows build {os_data.get('full_build')} reached end of "
                    "servicing"
                ),
                category=FindingCategory.PATCH,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                description=(
                    f"This host runs {os_data.get('product_name')} "
                    f"{os_data.get('display_version')} (build {os_data.get('build')}), "
                    f"which stopped receiving security servicing on {end_of_servicing}."
                ),
                impact=(
                    "No further security updates are issued for this build. Any "
                    "vulnerability discovered after that date remains unpatched."
                ),
                remediation=(
                    "Upgrade to a currently serviced Windows feature update."
                ),
                evidence={
                    "build": os_data.get("build"),
                    "display_version": os_data.get("display_version"),
                    "end_of_servicing": end_of_servicing,
                },
                evidence_summary=f"Build {os_data.get('build')} EOS {end_of_servicing}",
                detection_method="OS build number against the Windows servicing calendar",
                patch_available=True,
                references=["https://learn.microsoft.com/lifecycle/products/windows-11-home-and-pro"],
                source_collector="os",
            )
