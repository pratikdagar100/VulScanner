"""Certificate store audit.

Metadata only. Private keys are never exported, read or transmitted - the
collector records nothing more than whether a private key is associated.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import dicts, get, integer, parse_datetime, text

SCRIPT = r"""
$stores = @(
  'Cert:\LocalMachine\My','Cert:\LocalMachine\Root','Cert:\LocalMachine\CA',
  'Cert:\LocalMachine\TrustedPublisher','Cert:\LocalMachine\Disallowed',
  'Cert:\CurrentUser\My','Cert:\CurrentUser\Root'
)
$out = New-Object System.Collections.ArrayList
foreach ($store in $stores) {
  try {
    Get-ChildItem $store -ErrorAction Stop | ForEach-Object {
      [void]$out.Add([pscustomobject]@{
        Store=$store
        Subject=$_.Subject
        Issuer=$_.Issuer
        Thumbprint=$_.Thumbprint
        NotBefore=$_.NotBefore
        NotAfter=$_.NotAfter
        SignatureAlgorithm=$_.SignatureAlgorithm.FriendlyName
        PublicKeyAlgorithm=$_.PublicKey.Oid.FriendlyName
        KeySize=$(try { $_.PublicKey.Key.KeySize } catch { $null })
        SerialNumberPresent=[bool]$_.SerialNumber
        # Only the existence of a private key is recorded; it is never read.
        HasPrivateKey=$_.HasPrivateKey
        SelfSigned=($_.Subject -eq $_.Issuer)
        FriendlyName=$_.FriendlyName
      })
    }
  } catch {}
}
,@($out)
"""

WEAK_SIGNATURE_ALGORITHMS = re.compile(r"(md2|md4|md5|sha1)", re.IGNORECASE)
MIN_RSA_KEY_SIZE = 2048


class CertificatesCollector(BaseCollector):
    name = "certificates"
    category = "windows"
    description = "Certificate store metadata, expiry and algorithm strength"
    profiles = ("standard", "full", "compliance")

    def collect(self, result: CollectorResult) -> None:
        records, ps = self.context.runner.run_list(SCRIPT, depth=4)
        result.collection_method = self.context.runner.describe_method(
            "Cert: PSDrive enumeration (LocalMachine and CurrentUser stores)"
        )
        if not ps.ok:
            result.fail(ps.friendly_error())
            return

        now = datetime.now(tz=timezone.utc)
        certificates: list[dict] = []
        for record in dicts(records):
            not_after = parse_datetime(get(record, "NotAfter"))
            not_before = parse_datetime(get(record, "NotBefore"))
            signature_algorithm = text(get(record, "SignatureAlgorithm"))
            key_size = integer(get(record, "KeySize"))
            store = text(get(record, "Store"))

            days_remaining = (
                int((not_after - now).total_seconds() // 86400) if not_after else None
            )
            issues = []
            if days_remaining is not None and days_remaining < 0:
                issues.append("expired")
            elif days_remaining is not None and days_remaining <= 30:
                issues.append("expiring-soon")
            if WEAK_SIGNATURE_ALGORITHMS.search(signature_algorithm):
                issues.append("weak-signature-algorithm")
            if key_size and key_size < MIN_RSA_KEY_SIZE and "ecc" not in (
                text(get(record, "PublicKeyAlgorithm")).lower()
            ):
                issues.append("weak-key-size")
            if bool(get(record, "SelfSigned")) and store.endswith("Root") is False:
                issues.append("self-signed")

            certificates.append(
                {
                    "store": store,
                    "subject": text(get(record, "Subject")),
                    "issuer": text(get(record, "Issuer")),
                    "thumbprint": text(get(record, "Thumbprint")),
                    "not_before": not_before.isoformat() if not_before else None,
                    "not_after": not_after.isoformat() if not_after else None,
                    "days_remaining": days_remaining,
                    "signature_algorithm": signature_algorithm,
                    "public_key_algorithm": text(get(record, "PublicKeyAlgorithm")),
                    "key_size": key_size,
                    "self_signed": bool(get(record, "SelfSigned")),
                    "has_private_key": bool(get(record, "HasPrivateKey")),
                    "friendly_name": text(get(record, "FriendlyName")),
                    "issues": issues,
                }
            )

        expired = [c for c in certificates if "expired" in c["issues"]]
        expiring = [c for c in certificates if "expiring-soon" in c["issues"]]
        weak = [
            c
            for c in certificates
            if "weak-signature-algorithm" in c["issues"] or "weak-key-size" in c["issues"]
        ]

        result.data = {
            "certificates": certificates,
            "certificate_count": len(certificates),
            "by_store": {
                store: sum(1 for c in certificates if c["store"] == store)
                for store in sorted({c["store"] for c in certificates})
            },
            "expired": expired,
            "expired_count": len(expired),
            "expiring_soon": expiring,
            "weak_algorithm_certificates": weak,
            # Weak or expired certificates in a trust root are the material risk.
            "weak_in_trust_stores": [
                c
                for c in weak + expired
                if c["store"].endswith(("Root", "CA", "TrustedPublisher"))
            ],
            "private_key_count": sum(1 for c in certificates if c["has_private_key"]),
        }

        if not certificates:
            result.warn("No certificates could be enumerated.")
