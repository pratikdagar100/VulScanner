"""Vulnerability intelligence: NVD lookups, CISA KEV enrichment and caching.

Correlation is deliberately conservative. A CVE is only attached to an asset
when there is evidence linking it: a CPE match against an inventoried product
and version, or a Microsoft advisory tied to a KB the host is missing. Running
Windows is not, by itself, evidence of anything.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

import httpx

from app.core.config import settings
from app.core.logging import get_logger
from app.scanner.util import compare_versions, version_tuple

logger = get_logger(__name__)

# Product name -> (vendor, cpe product) for CPE-based matching.
CPE_PRODUCT_MAP: dict[str, tuple[str, str]] = {
    "google chrome": ("google", "chrome"),
    "mozilla firefox": ("mozilla", "firefox"),
    "microsoft edge": ("microsoft", "edge_chromium"),
    "7-zip": ("7-zip", "7-zip"),
    "winrar": ("rarlab", "winrar"),
    "notepad++": ("notepad-plus-plus", "notepad\\+\\+"),
    "vlc media player": ("videolan", "vlc_media_player"),
    "python": ("python", "python"),
    "node.js": ("nodejs", "node.js"),
    "git": ("git-scm", "git"),
    "openssl": ("openssl", "openssl"),
    "openssh": ("openbsd", "openssh"),
    "putty": ("putty", "putty"),
    "filezilla": ("filezilla-project", "filezilla_client"),
    "wireshark": ("wireshark", "wireshark"),
    "oracle vm virtualbox": ("oracle", "vm_virtualbox"),
    "mysql": ("oracle", "mysql"),
    "postgresql": ("postgresql", "postgresql"),
    "mongodb": ("mongodb", "mongodb"),
    "apache tomcat": ("apache", "tomcat"),
    "docker desktop": ("docker", "desktop"),
    "zoom": ("zoom", "zoom"),
    "adobe acrobat reader": ("adobe", "acrobat_reader"),
    "java": ("oracle", "jre"),
    "libreoffice": ("libreoffice", "libreoffice"),
    "winscp": ("winscp", "winscp"),
    "teamviewer": ("teamviewer", "teamviewer"),
    "anydesk": ("anydesk", "anydesk"),
    "curl": ("haxx", "curl"),
    "thunderbird": ("mozilla", "thunderbird"),
}

VERSION_CLEAN = re.compile(r"[^0-9.]")
KB_PATTERN = re.compile(r"KB(\d{6,})", re.IGNORECASE)


@dataclass
class CVERecord:
    cve_id: str
    description: str = ""
    cvss_v3_score: float | None = None
    cvss_v3_vector: str = ""
    cvss_v2_score: float | None = None
    cvss_severity: str = ""
    attack_vector: str = ""
    exploitability_score: float | None = None
    impact_score: float | None = None
    cwe_ids: list[str] = field(default_factory=list)
    cpe_matches: list[dict] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    published_at: str | None = None
    modified_at: str | None = None
    kev: bool = False
    kev_date_added: str | None = None
    kev_due_date: str | None = None
    kev_ransomware: bool = False
    source: str = "nvd"

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_v3_score": self.cvss_v3_score,
            "cvss_v3_vector": self.cvss_v3_vector,
            "cvss_v2_score": self.cvss_v2_score,
            "cvss_severity": self.cvss_severity,
            "attack_vector": self.attack_vector,
            "exploitability_score": self.exploitability_score,
            "impact_score": self.impact_score,
            "cwe_ids": self.cwe_ids,
            "references": self.references,
            "published_at": self.published_at,
            "modified_at": self.modified_at,
            "kev": self.kev,
            "kev_date_added": self.kev_date_added,
            "kev_due_date": self.kev_due_date,
            "kev_ransomware": self.kev_ransomware,
            "source": self.source,
        }


class FileCache:
    """Simple TTL cache on disk so repeat scans do not re-query the API."""

    def __init__(self, directory: Path, ttl_hours: int) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.ttl = timedelta(hours=ttl_hours)

    def _path(self, key: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", key)[:120]
        return self.directory / f"{safe}.json"

    def get(self, key: str, ignore_ttl: bool = False) -> Any | None:
        path = self._path(key)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        stored = payload.get("_cached_at")
        if not ignore_ttl and stored:
            try:
                cached_at = datetime.fromisoformat(stored)
            except ValueError:
                return None
            if datetime.now(tz=timezone.utc) - cached_at > self.ttl:
                return None
        return payload.get("data")

    def set(self, key: str, data: Any) -> None:
        try:
            self._path(key).write_text(
                json.dumps(
                    {"_cached_at": datetime.now(tz=timezone.utc).isoformat(), "data": data}
                ),
                encoding="utf-8",
            )
        except OSError as exc:  # pragma: no cover
            logger.warning("Could not write CVE cache entry %s: %s", key, exc)


class CVEService:
    """Fetches and correlates vulnerability intelligence."""

    def __init__(self, online: bool | None = None) -> None:
        self.online = settings.cve_online if online is None else online
        self.cache = FileCache(settings.cve_cache_dir, settings.cve_cache_ttl_hours)
        self._kev: dict[str, dict] | None = None
        self._last_request = 0.0
        # NVD asks for 6s between requests without a key, 0.6s with one.
        self._min_interval = 0.6 if settings.nvd_api_key else 6.0

    # -- HTTP --------------------------------------------------------------
    def _headers(self) -> dict[str, str]:
        headers = {"User-Agent": "VulScanner/1.0 (defensive security assessment)"}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key
        return headers

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.monotonic()

    def _get(self, url: str, params: dict | None = None) -> dict | None:
        if not self.online:
            return None
        self._throttle()
        try:
            with httpx.Client(timeout=30.0, follow_redirects=True) as client:
                response = client.get(url, params=params, headers=self._headers())
                if response.status_code == 403:
                    logger.warning(
                        "NVD returned 403. Configure VULSCANNER_NVD_API_KEY to raise "
                        "the rate limit."
                    )
                    return None
                if response.status_code == 404:
                    return None
                response.raise_for_status()
                return response.json()
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            logger.warning("Vulnerability intelligence request failed: %s", exc)
            return None

    # -- CISA KEV ----------------------------------------------------------
    def kev_catalog(self) -> dict[str, dict]:
        """Return the KEV catalogue keyed by CVE id."""
        if self._kev is not None:
            return self._kev

        cached = self.cache.get("cisa-kev")
        payload = cached or self._get(settings.kev_url)
        if payload is None:
            # Fall back to a stale cache rather than losing KEV enrichment.
            payload = self.cache.get("cisa-kev", ignore_ttl=True)
            if payload:
                logger.info("Using stale CISA KEV cache (catalogue refresh failed).")
        if payload and not cached:
            self.cache.set("cisa-kev", payload)

        catalogue: dict[str, dict] = {}
        for entry in (payload or {}).get("vulnerabilities", []):
            cve_id = entry.get("cveID")
            if cve_id:
                catalogue[cve_id.upper()] = entry
        self._kev = catalogue
        if catalogue:
            logger.info("CISA KEV catalogue loaded: %d entries", len(catalogue))
        return catalogue

    # -- NVD ---------------------------------------------------------------
    def search_by_cpe(self, cpe_name: str, limit: int = 200) -> list[CVERecord]:
        cache_key = f"cpe-{cpe_name}"
        cached = self.cache.get(cache_key)
        if cached is None:
            payload = self._get(
                settings.nvd_base_url,
                params={"cpeName": cpe_name, "resultsPerPage": limit},
            )
            if payload is None:
                stale = self.cache.get(cache_key, ignore_ttl=True)
                if stale is None:
                    return []
                cached = stale
            else:
                self.cache.set(cache_key, payload)
                cached = payload
        return [self._parse_cve(item) for item in cached.get("vulnerabilities", [])]

    def get_cve(self, cve_id: str) -> CVERecord | None:
        cache_key = f"cve-{cve_id.upper()}"
        cached = self.cache.get(cache_key)
        if cached is None:
            payload = self._get(settings.nvd_base_url, params={"cveId": cve_id})
            if payload is None:
                cached = self.cache.get(cache_key, ignore_ttl=True)
                if cached is None:
                    return None
            else:
                self.cache.set(cache_key, payload)
                cached = payload
        items = cached.get("vulnerabilities", [])
        return self._parse_cve(items[0]) if items else None

    def _parse_cve(self, item: dict) -> CVERecord:
        cve = item.get("cve", item) or {}
        cve_id = (cve.get("id") or "").upper()

        description = ""
        for entry in cve.get("descriptions", []):
            if entry.get("lang") == "en":
                description = entry.get("value", "")
                break

        metrics = cve.get("metrics", {}) or {}
        record = CVERecord(cve_id=cve_id, description=description)

        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key) or []
            if not entries:
                continue
            primary = next(
                (e for e in entries if e.get("type") == "Primary"), entries[0]
            )
            data = primary.get("cvssData", {})
            record.cvss_v3_score = data.get("baseScore")
            record.cvss_v3_vector = data.get("vectorString", "")
            record.cvss_severity = data.get("baseSeverity", "")
            record.attack_vector = data.get("attackVector", "")
            record.exploitability_score = primary.get("exploitabilityScore")
            record.impact_score = primary.get("impactScore")
            break

        v2 = metrics.get("cvssMetricV2") or []
        if v2:
            record.cvss_v2_score = (v2[0].get("cvssData") or {}).get("baseScore")

        record.cwe_ids = [
            desc.get("value", "")
            for weakness in cve.get("weaknesses", [])
            for desc in weakness.get("description", [])
            if desc.get("value", "").startswith("CWE-")
        ]
        record.references = [
            ref.get("url", "") for ref in cve.get("references", []) if ref.get("url")
        ][:15]
        record.published_at = cve.get("published")
        record.modified_at = cve.get("lastModified")

        for configuration in cve.get("configurations", []):
            for node in configuration.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        record.cpe_matches.append(
                            {
                                "criteria": match.get("criteria", ""),
                                "version_start_including": match.get(
                                    "versionStartIncluding"
                                ),
                                "version_start_excluding": match.get(
                                    "versionStartExcluding"
                                ),
                                "version_end_including": match.get("versionEndIncluding"),
                                "version_end_excluding": match.get("versionEndExcluding"),
                            }
                        )

        kev_entry = self.kev_catalog().get(cve_id)
        if kev_entry:
            record.kev = True
            record.kev_date_added = kev_entry.get("dateAdded")
            record.kev_due_date = kev_entry.get("dueDate")
            record.kev_ransomware = (
                str(kev_entry.get("knownRansomwareCampaignUse", "")).lower() == "known"
            )
        return record

    # -- correlation -------------------------------------------------------
    def correlate_software(
        self, applications: Iterable[dict], max_products: int = 25
    ) -> list[dict]:
        """Correlate inventoried software with CVE data.

        Only products with a recognised CPE mapping and a parseable version are
        considered, so the result set is evidence-backed rather than speculative.
        """
        correlations: list[dict] = []
        processed = 0

        for application in applications:
            if processed >= max_products:
                break
            name = (application.get("name") or "").strip()
            version = (application.get("version") or "").strip()
            if not name or not version:
                continue

            mapping = self._map_product(name)
            if not mapping:
                continue
            vendor, product = mapping
            clean_version = VERSION_CLEAN.sub("", version.split()[0]).strip(".")
            if not clean_version or not version_tuple(clean_version):
                continue

            processed += 1
            cpe_name = f"cpe:2.3:a:{vendor}:{product}:{clean_version}:*:*:*:*:*:*:*"
            records = self.search_by_cpe(cpe_name)
            if not records:
                continue

            for record in records:
                affected, evidence = self._version_affected(record, clean_version)
                if not affected:
                    continue
                correlations.append(
                    {
                        "cve": record,
                        "product": name,
                        "vendor": vendor,
                        "product_version": version,
                        "normalized_version": clean_version,
                        "match_method": "cpe",
                        "confidence": "high",
                        "evidence": {
                            "cpe_name": cpe_name,
                            "installed_version": version,
                            "matched_range": evidence,
                            "source": "NVD CPE match",
                            "inventory_source": application.get("registry_key", ""),
                        },
                        "affected_versions": evidence,
                    }
                )

        return correlations

    def _map_product(self, name: str) -> tuple[str, str] | None:
        lowered = name.lower()
        for key, mapping in CPE_PRODUCT_MAP.items():
            if key in lowered:
                return mapping
        return None

    @staticmethod
    def _version_affected(record: CVERecord, version: str) -> tuple[bool, str]:
        """Check the installed version against the CVE's affected ranges."""
        if not record.cpe_matches:
            # A CPE-name query already constrained the version, but without an
            # explicit range we cannot claim a confident match.
            return False, ""

        for match in record.cpe_matches:
            start_inc = match.get("version_start_including")
            start_exc = match.get("version_start_excluding")
            end_inc = match.get("version_end_including")
            end_exc = match.get("version_end_excluding")

            if not any((start_inc, start_exc, end_inc, end_exc)):
                # Exact-version CPE: compare the version field directly.
                parts = (match.get("criteria") or "").split(":")
                if len(parts) > 5 and parts[5] not in ("*", "-"):
                    if compare_versions(version, parts[5]) == 0:
                        return True, f"= {parts[5]}"
                continue

            if start_inc and compare_versions(version, start_inc) < 0:
                continue
            if start_exc and compare_versions(version, start_exc) <= 0:
                continue
            if end_inc and compare_versions(version, end_inc) > 0:
                continue
            if end_exc and compare_versions(version, end_exc) >= 0:
                continue

            bounds = []
            if start_inc:
                bounds.append(f">= {start_inc}")
            if start_exc:
                bounds.append(f"> {start_exc}")
            if end_inc:
                bounds.append(f"<= {end_inc}")
            if end_exc:
                bounds.append(f"< {end_exc}")
            return True, " and ".join(bounds)

        return False, ""

    def correlate_missing_updates(self, pending_updates: Iterable[dict]) -> list[dict]:
        """Derive vulnerability records from updates the host is missing.

        Evidence is the Windows Update agent's own applicability determination,
        so these records carry 'confirmed' confidence for the missing patch even
        though the specific CVEs are advisory-level information.
        """
        correlations: list[dict] = []
        for update in pending_updates:
            kbs = update.get("kbs") or []
            if not kbs:
                continue
            severity = (update.get("msrc_severity") or "").strip()
            correlations.append(
                {
                    "cve": None,
                    "kbs": kbs,
                    "title": update.get("title", ""),
                    "msrc_severity": severity or "Unspecified",
                    "match_method": "kb-missing",
                    "confidence": "confirmed",
                    "evidence": {
                        "source": "Windows Update agent (IsInstalled=0)",
                        "kbs": kbs,
                        "categories": update.get("categories", []),
                        "support_url": update.get("support_url", ""),
                    },
                    "remediation": (
                        f"Install {', '.join(kbs)} through Windows Update, or "
                        "download it from the Microsoft Update Catalog."
                    ),
                    "references": [
                        f"https://catalog.update.microsoft.com/Search.aspx?q={kb}"
                        for kb in kbs
                    ],
                }
            )
        return correlations

    def status(self) -> dict:
        """Report intelligence availability for the UI and reports."""
        kev = self.kev_catalog()
        return {
            "online": self.online,
            "nvd_api_key_configured": bool(settings.nvd_api_key),
            "kev_entries": len(kev),
            "kev_available": bool(kev),
            "cache_directory": str(settings.cve_cache_dir),
            "cache_ttl_hours": settings.cve_cache_ttl_hours,
            "rate_limit_interval_seconds": self._min_interval,
        }


cve_service = CVEService()
