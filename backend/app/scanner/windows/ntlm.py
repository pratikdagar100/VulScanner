"""NTLM, LSA and authentication hardening settings."""

from __future__ import annotations

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import get, integer, text

SCRIPT = r"""
function Read-Value($path, $name) {
  try { return (Get-ItemProperty $path -ErrorAction Stop).$name } catch { return $null }
}

$lsa   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$msv   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
$pku2u = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u'
$netlogon = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
$lanman = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$lanwork = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
$wdigest = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'

[pscustomobject]@{
  LmCompatibilityLevel      = Read-Value $lsa 'LmCompatibilityLevel'
  NoLmHash                  = Read-Value $lsa 'NoLmHash'
  RestrictAnonymous         = Read-Value $lsa 'RestrictAnonymous'
  RestrictAnonymousSAM      = Read-Value $lsa 'RestrictAnonymousSAM'
  EveryoneIncludesAnonymous = Read-Value $lsa 'EveryoneIncludesAnonymous'
  RunAsPPL                  = Read-Value $lsa 'RunAsPPL'
  LimitBlankPasswordUse     = Read-Value $lsa 'LimitBlankPasswordUse'
  DisableDomainCreds        = Read-Value $lsa 'DisableDomainCreds'
  RestrictSendingNTLMTraffic = Read-Value $msv 'RestrictSendingNTLMTraffic'
  NTLMMinClientSec          = Read-Value $msv 'NTLMMinClientSec'
  NTLMMinServerSec          = Read-Value $msv 'NTLMMinServerSec'
  AuditReceivingNTLMTraffic = Read-Value $msv 'AuditReceivingNTLMTraffic'
  AllowOnlineID             = Read-Value $pku2u 'AllowOnlineID'
  RequireSignOrSeal         = Read-Value $netlogon 'RequireSignOrSeal'
  RequireStrongKey          = Read-Value $netlogon 'RequireStrongKey'
  SmbServerSigningRequired  = Read-Value $lanman 'RequireSecuritySignature'
  SmbServerSigningEnabled   = Read-Value $lanman 'EnableSecuritySignature'
  SmbClientSigningRequired  = Read-Value $lanwork 'RequireSecuritySignature'
  Smb1ServerEnabled         = Read-Value $lanman 'SMB1'
  UseLogonCredential        = Read-Value $wdigest 'UseLogonCredential'
  CachedLogonsCount         = Read-Value 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount'
}
"""

LM_LEVELS = {
    0: "Send LM & NTLM responses",
    1: "Send LM & NTLM, use NTLMv2 session security if negotiated",
    2: "Send NTLM response only",
    3: "Send NTLMv2 response only",
    4: "Send NTLMv2 only, refuse LM",
    5: "Send NTLMv2 only, refuse LM & NTLM",
}
RESTRICT_OUTBOUND_NTLM = {
    0: "Allow all",
    1: "Audit all",
    2: "Deny all",
}


class NTLMCollector(BaseCollector):
    name = "ntlm"
    category = "windows"
    description = "NTLM, LSA protection and SMB signing configuration"
    profiles = ("standard", "full", "compliance")

    def collect(self, result: CollectorResult) -> None:
        ps = self.context.runner.run(SCRIPT, depth=3)
        result.collection_method = self.context.runner.describe_method(
            "LSA, MSV1_0, Netlogon, LanmanServer/Workstation and WDigest registry keys"
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "Authentication settings returned nothing")
            return

        raw = ps.data
        lm_level = integer(get(raw, "LmCompatibilityLevel"))
        cached_logons = integer(get(raw, "CachedLogonsCount"))
        if cached_logons is None:
            cached_logons = integer(text(get(raw, "CachedLogonsCount")))

        result.data = {
            "lm_compatibility_level": lm_level,
            "lm_compatibility_description": LM_LEVELS.get(
                lm_level if lm_level is not None else -1,
                "Not configured (Windows default: 3)",
            ),
            "lm_hash_storage_disabled": integer(get(raw, "NoLmHash")) == 1,
            "restrict_anonymous": integer(get(raw, "RestrictAnonymous")),
            "restrict_anonymous_sam": integer(get(raw, "RestrictAnonymousSAM")),
            "everyone_includes_anonymous": integer(
                get(raw, "EveryoneIncludesAnonymous")
            ) == 1,
            "lsa_protection_ppl": integer(get(raw, "RunAsPPL")) in (1, 2),
            "lsa_protection_raw": integer(get(raw, "RunAsPPL")),
            "limit_blank_password_use": integer(get(raw, "LimitBlankPasswordUse")) != 0,
            "outbound_ntlm_restriction": RESTRICT_OUTBOUND_NTLM.get(
                integer(get(raw, "RestrictSendingNTLMTraffic"), -1) or -1,
                "Not configured",
            ),
            "ntlm_min_client_sec": integer(get(raw, "NTLMMinClientSec")),
            "ntlm_min_server_sec": integer(get(raw, "NTLMMinServerSec")),
            "ntlm_inbound_auditing": integer(get(raw, "AuditReceivingNTLMTraffic")),
            "online_id_auth_allowed": integer(get(raw, "AllowOnlineID")) == 1,
            "netlogon_require_sign_or_seal": integer(get(raw, "RequireSignOrSeal")) == 1,
            "netlogon_require_strong_key": integer(get(raw, "RequireStrongKey")) == 1,
            "smb_server_signing_required": integer(
                get(raw, "SmbServerSigningRequired")
            ) == 1,
            "smb_server_signing_enabled": integer(
                get(raw, "SmbServerSigningEnabled")
            ) == 1,
            "smb_client_signing_required": integer(
                get(raw, "SmbClientSigningRequired")
            ) == 1,
            # An absent SMB1 value means "not overridden", which does not by
            # itself mean disabled - the optional feature may still be installed.
            # Get-SmbServerConfiguration (shares collector) is authoritative.
            "smb1_registry_value": integer(get(raw, "Smb1ServerEnabled")),
            "smb1_enabled": (
                integer(get(raw, "Smb1ServerEnabled")) == 1
                if get(raw, "Smb1ServerEnabled") is not None
                else None
            ),
            "wdigest_plaintext_credentials": integer(
                get(raw, "UseLogonCredential")
            ) == 1,
            "cached_logon_count": cached_logons,
            # Windows default is 3 (NTLMv2 response only) when unset.
            "weak_ntlm_configuration": lm_level is not None and lm_level < 3,
        }
