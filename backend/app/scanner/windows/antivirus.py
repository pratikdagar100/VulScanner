"""Registered security products from the Windows Security Center.

Read-only. VulScanner never disables, reconfigures or interferes with any
security product it discovers.
"""

from __future__ import annotations

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import dicts, get, integer, text

# Known EDR / security service names, used only to report what is present.
KNOWN_SECURITY_SERVICES = {
    "windefend": "Microsoft Defender Antivirus",
    "sense": "Microsoft Defender for Endpoint (EDR)",
    "csagent": "CrowdStrike Falcon",
    "sentinelagent": "SentinelOne",
    "cbdefense": "VMware Carbon Black",
    "cylancesvc": "BlackBerry Cylance",
    "sophosagent": "Sophos Endpoint",
    "mcafeeframework": "McAfee/Trellix Agent",
    "symantec antivirus": "Symantec Endpoint Protection",
    "sedservice": "Sophos Endpoint Defense",
    "eset service": "ESET Endpoint",
    "avastsvc": "Avast",
    "avgsvc": "AVG",
    "klnagent": "Kaspersky Network Agent",
    "tmbmserver": "Trend Micro",
    "elastic-agent": "Elastic Agent",
}

SCRIPT = r"""
function Get-SecurityProducts($class) {
  try {
    Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName $class -ErrorAction Stop |
      ForEach-Object {
        [pscustomobject]@{
          Class=$class; DisplayName=$_.displayName; ProductState=$_.productState
          PathToSignedProductExe=$_.pathToSignedProductExe
          Timestamp=$_.timestamp; InstanceGuid=$_.instanceGuid
        }
      }
  } catch { @() }
}

$products = @()
$products += Get-SecurityProducts 'AntiVirusProduct'
$products += Get-SecurityProducts 'AntiSpywareProduct'
$products += Get-SecurityProducts 'FirewallProduct'

$services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match 'defend|sense|csagent|sentinel|cb|cylance|sophos|mcafee|symantec|eset|avast|avg|klnagent|tmbm|elastic' } |
  ForEach-Object {
    [pscustomobject]@{ Name=$_.Name; DisplayName=$_.DisplayName; State=$_.State; StartMode=$_.StartMode; Path=$_.PathName }
  }

[pscustomobject]@{ Products=$products; Services=$services }
"""


def decode_product_state(state: int | None) -> dict:
    """Decode the Security Center productState bit field.

    Bits: 0x1000 = enabled (real-time protection on), 0x10 = signatures out of
    date. This encoding is undocumented but stable across Windows releases.
    """
    if state is None:
        return {"enabled": None, "up_to_date": None, "raw": None}
    enabled_byte = (state >> 12) & 0xF
    signature_byte = state & 0xFF
    return {
        "raw": state,
        "hex": f"0x{state:06X}",
        "enabled": enabled_byte in (1, 0x1),
        "up_to_date": signature_byte == 0x00,
    }


class AntivirusCollector(BaseCollector):
    name = "antivirus"
    category = "windows"
    description = "Registered antivirus, antispyware and firewall products"
    profiles = ("quick", "standard", "full", "compliance")

    def collect(self, result: CollectorResult) -> None:
        ps = self.context.runner.run(SCRIPT, depth=4)
        result.collection_method = self.context.runner.describe_method(
            "root/SecurityCenter2 WMI namespace and Win32_Service"
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "Security Center query returned nothing")
            return

        products = []
        for record in dicts(get(ps.data, "Products")):
            state = decode_product_state(integer(get(record, "ProductState")))
            products.append(
                {
                    "type": text(get(record, "Class")).replace("Product", ""),
                    "name": text(get(record, "DisplayName")),
                    "path": text(get(record, "PathToSignedProductExe")),
                    "enabled": state["enabled"],
                    "signatures_up_to_date": state["up_to_date"],
                    "product_state": state,
                }
            )

        services = []
        for record in dicts(get(ps.data, "Services")):
            service_name = text(get(record, "Name"))
            services.append(
                {
                    "service": service_name,
                    "display_name": text(get(record, "DisplayName")),
                    "state": text(get(record, "State")),
                    "start_mode": text(get(record, "StartMode")),
                    "identified_as": KNOWN_SECURITY_SERVICES.get(
                        service_name.lower(), "Unclassified security service"
                    ),
                }
            )

        antivirus = [p for p in products if p["type"] == "AntiVirus"]
        result.data = {
            "products": products,
            "antivirus_products": antivirus,
            "firewall_products": [p for p in products if p["type"] == "Firewall"],
            "security_services": services,
            "antivirus_count": len(antivirus),
            "any_antivirus_enabled": any(p["enabled"] for p in antivirus),
            "third_party_antivirus": [
                p["name"] for p in antivirus if "defender" not in p["name"].lower()
            ],
            "edr_detected": [
                s["identified_as"]
                for s in services
                if s["state"].lower() == "running"
                and "Unclassified" not in s["identified_as"]
            ],
        }

        if not products:
            result.warn(
                "Security Center reported no products. This is expected on Windows "
                "Server, where the SecurityCenter2 namespace is unavailable."
            )
