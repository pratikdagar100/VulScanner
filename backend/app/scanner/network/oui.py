"""MAC OUI vendor resolution.

Ships with a small built-in table of common vendors. When the operator supplies
an IEEE OUI registry export (``oui.csv``) in the cache directory, that file is
used instead, giving full coverage without bundling a large dataset.

Download the registry with:
    curl -o cache/oui.csv https://standards-oui.ieee.org/oui/oui.csv
"""

from __future__ import annotations

import csv
from functools import lru_cache
from pathlib import Path

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# Prefix (first 3 octets, no separators) -> vendor.
BUILTIN_OUI: dict[str, str] = {
    "000C29": "VMware", "005056": "VMware", "000569": "VMware",
    "080027": "Oracle VirtualBox", "0A0027": "Oracle VirtualBox",
    "00155D": "Microsoft (Hyper-V)", "001DD8": "Microsoft",
    "00163E": "Xensource", "525400": "QEMU/KVM",
    "001A11": "Google", "3C5AB4": "Google", "F4F5D8": "Google",
    "B827EB": "Raspberry Pi Foundation", "DCA632": "Raspberry Pi Trading",
    "E45F01": "Raspberry Pi Trading", "D83ADD": "Raspberry Pi Trading",
    "001C42": "Parallels",
    "00E04C": "Realtek", "52544C": "Realtek",
    "001B21": "Intel", "8C1645": "Intel", "3C970E": "Intel", "A0A8CD": "Intel",
    "00248C": "ASUSTek", "1C872C": "ASUSTek", "D850E6": "ASUSTek",
    "0026B9": "Dell", "B8CA3A": "Dell", "F8BC12": "Dell", "D067E5": "Dell",
    "3CD92B": "Hewlett Packard", "9457A5": "Hewlett Packard", "00215A": "Hewlett Packard",
    "001B63": "Apple", "3C0754": "Apple", "F0DBF8": "Apple", "A4C361": "Apple",
    "AC87A3": "Apple", "DC2B2A": "Apple", "8C8590": "Apple",
    "001E58": "D-Link", "1CBDB9": "D-Link", "C8BE19": "D-Link",
    "0018E7": "Netgear", "A040A0": "Netgear", "9C3DCF": "Netgear",
    "002401": "TP-Link", "1027F5": "TP-Link", "50C7BF": "TP-Link", "C46E1F": "TP-Link",
    "F4EC38": "TP-Link", "AC84C6": "TP-Link",
    "00259C": "Cisco-Linksys", "0024C4": "Cisco", "00000C": "Cisco",
    "F09FC2": "Ubiquiti", "802AA8": "Ubiquiti", "24A43C": "Ubiquiti", "788A20": "Ubiquiti",
    "FCECDA": "Ubiquiti", "687251": "Ubiquiti",
    "001CC0": "Intel", "000AF7": "Broadcom", "001018": "Broadcom",
    "0050F2": "Microsoft", "7C1E52": "Microsoft", "C83F26": "Microsoft",
    "78E103": "Samsung", "F008F1": "Samsung", "5CF6DC": "Samsung", "8C71F8": "Samsung",
    "001788": "Signify (Philips Hue)", "ECB5FA": "Signify (Philips Hue)",
    "18B430": "Nest Labs", "641666": "Amazon Technologies", "FC65DE": "Amazon Technologies",
    "44650D": "Amazon Technologies", "68DBF5": "Amazon Technologies",
    "0004A3": "Microchip", "2CF432": "Espressif", "246F28": "Espressif",
    "A020A6": "Espressif", "3C71BF": "Espressif", "8CAAB5": "Espressif",
    "001132": "Synology", "0011D8": "ASUSTek", "00907F": "WatchGuard",
    "000E8F": "Sercomm", "84948C": "Hitron", "3872C0": "Comtrend",
    "E0CB4E": "ASUSTek", "704D7B": "ASUSTek",
    "0009B0": "Onkyo", "B0A737": "Roku", "CC6DA0": "Roku",
    "00D861": "Micro-Star (MSI)", "4CCC6A": "Micro-Star (MSI)",
    "48A472": "Gigabyte", "1C1B0D": "Gigabyte",
    "6C2408": "ASRock", "70854D": "ASRock",
    "001DE1": "Cisco", "0021D8": "Cisco", "00269C": "Juniper",
    "2C6BF5": "Juniper", "84B59C": "Juniper", "F4CC55": "Aruba (HPE)",
    "6CF37F": "Aruba (HPE)", "94B40F": "Aruba (HPE)",
    "001CF0": "D-Link", "C0C1C0": "Cisco-Linksys", "9C5C8E": "ASUSTek",
}


@lru_cache(maxsize=1)
def _registry() -> dict[str, str]:
    """Load an IEEE ``oui.csv`` export if the operator supplied one."""
    table = dict(BUILTIN_OUI)
    candidate = Path(settings.cve_cache_dir).parent / "oui.csv"
    if not candidate.exists():
        return table
    try:
        with candidate.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            for row in csv.DictReader(handle):
                assignment = (row.get("Assignment") or "").strip().upper()
                organization = (row.get("Organization Name") or "").strip()
                if len(assignment) == 6 and organization:
                    table[assignment] = organization
        logger.info("Loaded IEEE OUI registry with %d entries", len(table))
    except (OSError, csv.Error) as exc:  # pragma: no cover - operator data
        logger.warning("Could not read OUI registry %s: %s", candidate, exc)
    return table


def lookup_vendor(mac: str | None) -> tuple[str, str]:
    """Return ``(vendor, matched_oui)``; vendor is empty when unknown."""
    if not mac:
        return "", ""
    prefix = mac.replace(":", "").replace("-", "").upper()[:6]
    if len(prefix) < 6:
        return "", ""
    vendor = _registry().get(prefix)
    if vendor:
        return vendor, prefix
    # Locally administered addresses (bit 1 of the first octet) are randomized.
    try:
        if int(prefix[:2], 16) & 0b10:
            return "Randomized / locally administered", prefix
    except ValueError:
        pass
    return "", prefix


def registry_size() -> int:
    return len(_registry())
