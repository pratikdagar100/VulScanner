"""Report generation, patch correlation, remediation, CVE and CLI tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from app.services.cve_service import CVEService, CVERecord
from app.services.patch_service import patch_service
from app.services.remediation_service import remediation_service
from app.services.report_service import report_service
from tests.mock_data import COLLECTOR_DATA, MOCK_MARKER, build_analysis_context

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def mock_findings():
    from app.services.analyzers import analyze

    return analyze(build_analysis_context(), target="mock-host")


class TestPatchService:
    def test_inventory_separates_installed_and_missing(self):
        records = patch_service.build_inventory(
            COLLECTOR_DATA["hotfixes"], COLLECTOR_DATA["updates"]
        )
        states = {record.kb_id: record.state for record in records}
        assert states["KB5034123"] == "installed"
        assert states["KB5099999"] == "missing"

    def test_missing_updates_carry_confirmed_evidence(self):
        records = patch_service.build_inventory(
            COLLECTOR_DATA["hotfixes"], COLLECTOR_DATA["updates"]
        )
        missing = next(r for r in records if r.state == "missing")
        assert missing.confidence == "confirmed"
        assert "Windows Update agent" in missing.evidence["source"]

    def test_summary_reports_evidence_quality(self):
        records = patch_service.build_inventory(
            COLLECTOR_DATA["hotfixes"], COLLECTOR_DATA["updates"]
        )
        summary = patch_service.summarize(
            records, COLLECTOR_DATA["hotfixes"], COLLECTOR_DATA["updates"],
            COLLECTOR_DATA["os"],
        )
        assert summary["evidence_quality"] == "confirmed"
        assert summary["missing_security_count"] >= 1
        assert summary["pending_reboot"] is True

    def test_without_an_agent_query_missing_updates_are_not_claimed(self):
        registry_only = {"queried_update_agent": False, "evidence_quality": "registry-only",
                         "pending_updates": []}
        records = patch_service.build_inventory(COLLECTOR_DATA["hotfixes"], registry_only)
        summary = patch_service.summarize(
            records, COLLECTOR_DATA["hotfixes"], registry_only, COLLECTOR_DATA["os"]
        )
        assert summary["missing_count"] == 0
        assert summary["evidence_quality"] == "partial"
        assert "not queried" in summary["evidence_note"]


class TestRemediationService:
    def test_plan_is_ordered_by_priority(self, mock_findings):
        items = remediation_service.build_plan(mock_findings)
        priorities = [item.priority for item in items]
        assert priorities == sorted(priorities)

    def test_every_item_answers_the_four_questions(self, mock_findings):
        for item in remediation_service.build_plan(mock_findings):
            assert item.what_is_wrong
            assert item.why_it_matters
            assert item.recommended_fix
            assert item.verification

    def test_execution_is_never_automated(self, mock_findings):
        for item in remediation_service.build_plan(mock_findings):
            payload = item.to_dict()
            assert payload["automated_execution"] is False
            assert "does not apply" in payload["execution_note"]

    def test_summary_highlights_immediate_work(self, mock_findings):
        items = remediation_service.build_plan(mock_findings)
        summary = remediation_service.summarize_plan(items)
        assert summary["total_items"] == len(items)
        assert "never applies remediation automatically" in summary["policy"]


class TestCVEService:
    def test_offline_service_makes_no_requests(self, tmp_path, monkeypatch):
        """Offline mode must never reach the network, even on a cache miss."""
        service = CVEService(online=False)
        monkeypatch.setattr(service.cache, "directory", tmp_path)

        def explode(*args, **kwargs):  # pragma: no cover - must not be called
            raise AssertionError("offline mode attempted a network request")

        monkeypatch.setattr("httpx.Client", explode)
        assert service.get_cve("CVE-2021-34527") is None
        assert service.search_by_cpe("cpe:2.3:a:google:chrome:1.0:*:*:*:*:*:*:*") == []

    def test_missing_update_correlation_is_confirmed(self):
        service = CVEService(online=False)
        records = service.correlate_missing_updates(
            COLLECTOR_DATA["updates"]["pending_updates"]
        )
        assert len(records) == 1
        assert records[0]["confidence"] == "confirmed"
        assert records[0]["kbs"] == ["KB5099999"]

    def test_version_range_matching(self):
        record = CVERecord(
            cve_id="CVE-2024-0001",
            cpe_matches=[
                {
                    "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                    "version_start_including": "100.0.0.0",
                    "version_end_excluding": "121.0.0.0",
                }
            ],
        )
        affected, evidence = CVEService._version_affected(record, "120.0.6099.71")
        assert affected is True
        assert ">= 100.0.0.0" in evidence

        not_affected, _ = CVEService._version_affected(record, "121.0.0.1")
        assert not_affected is False

    def test_no_range_means_no_confident_match(self):
        """Without an explicit affected range VulScanner does not claim a match."""
        record = CVERecord(cve_id="CVE-2024-0002", cpe_matches=[])
        affected, _ = CVEService._version_affected(record, "1.0")
        assert affected is False

    def test_products_without_a_version_are_skipped(self):
        service = CVEService(online=False)
        result = service.correlate_software([{"name": "Google Chrome", "version": ""}])
        assert result == []


class TestReportGeneration:
    @pytest.fixture
    def scan_id(self, db):
        """Persist a mock scan so reports have something real to render."""
        from datetime import datetime, timezone

        from app.models.asset import Asset
        from app.models.finding import Finding
        from app.models.scan import Scan, ScanResult
        from app.services.analyzers import analyze

        now = datetime.now(tz=timezone.utc)
        scan = Scan(
            name="Mock scan", target="mock-host", target_type="local", profile="full",
            status="completed", security_score=42.0, risk_score=88.0,
            scanner_version="1.0.0", started_at=now, finished_at=now,
            duration_seconds=12.3,
        )
        db.add(scan)
        db.flush()

        asset = Asset(
            asset_uid="mock-asset-uid", hostname="EXAMPLE-WORKSTATION",
            ip_address="192.0.2.10", os_name="Windows 11 Pro", os_build="22621.3007",
            first_seen=now, last_seen=now,
        )
        db.add(asset)
        db.flush()

        for name, data in COLLECTOR_DATA.items():
            db.add(
                ScanResult(
                    scan_id=scan.id, asset_id=asset.id, collector=name,
                    status="success", data=data,
                    collection_method=f"mock ({MOCK_MARKER})", collected_at=now,
                    duration_seconds=0.5,
                )
            )

        for finding in analyze(build_analysis_context(), target="mock-host"):
            db.add(
                Finding(
                    finding_uid=finding["finding_uid"], rule_id=finding["rule_id"],
                    title=finding["title"], category=finding["category"],
                    severity=finding["severity"], risk_score=finding["risk_score"],
                    cvss_score=finding["cvss_score"], confidence=finding["confidence"],
                    description=finding["description"], impact=finding["impact"],
                    evidence=finding["evidence"],
                    evidence_summary=finding["evidence_summary"],
                    detection_method=finding["detection_method"],
                    remediation=finding["remediation"],
                    remediation_command=finding["remediation_command"],
                    references=finding["references"],
                    risk_factors=finding["risk_factors"],
                    scan_id=scan.id, asset_id=asset.id,
                    first_detected_at=now, last_detected_at=now,
                )
            )
        db.flush()
        return scan.id

    def test_payload_contains_every_report_section(self, db, scan_id):
        payload = report_service.build_payload(db, scan_id)
        for section in (
            "meta", "executive_summary", "system_information", "software",
            "patches", "defender", "firewall", "rdp", "users_and_groups",
            "security_policies", "network", "ports", "findings",
            "vulnerabilities", "remediation", "topology", "methodology",
            "collectors",
        ):
            assert section in payload, section

    def test_meta_establishes_provenance(self, db, scan_id):
        meta = report_service.build_payload(db, scan_id)["meta"]
        assert meta["scan_id"] == scan_id
        assert meta["target"] == "mock-host"
        assert meta["scanner_version"] == "1.0.0"
        assert meta["profile"] == "full"
        assert meta["evidence_timestamps"]

    def test_html_renders(self, db, scan_id, tmp_path, monkeypatch):
        monkeypatch.setattr(report_service, "output_dir", tmp_path)
        path, summary = report_service.generate(db, scan_id, "html")
        html = path.read_text(encoding="utf-8")
        assert path.exists() and path.stat().st_size > 2000
        assert "VulScanner Security Assessment Report" in html
        assert "VulScanner risk score" in html
        # Every report states that the official CVSS is reported separately.
        assert "official CVSS base score" in html
        assert "never merged into the VulScanner score" in html
        assert summary["total_findings"] > 0

    def test_json_is_machine_readable(self, db, scan_id, tmp_path, monkeypatch):
        monkeypatch.setattr(report_service, "output_dir", tmp_path)
        path, _ = report_service.generate(db, scan_id, "json")
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["meta"]["scan_id"] == scan_id
        assert isinstance(payload["findings"], list)

    def test_csv_separates_cvss_from_the_risk_score(self, db, scan_id, tmp_path, monkeypatch):
        monkeypatch.setattr(report_service, "output_dir", tmp_path)
        path, _ = report_service.generate(db, scan_id, "csv")
        header = path.read_text(encoding="utf-8").splitlines()[0]
        assert "vulscanner_risk_score" in header
        assert "official_cvss" in header

    def test_pdf_is_generated_without_an_external_binary(
        self, db, scan_id, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(report_service, "output_dir", tmp_path)
        path, _ = report_service.generate(db, scan_id, "pdf")
        assert path.exists()
        assert path.read_bytes()[:5] == b"%PDF-"

    def test_unknown_format_is_rejected(self, db, scan_id):
        with pytest.raises(ValueError):
            report_service.generate(db, scan_id, "docx")


class TestCLI:
    """The CLI is exercised as a subprocess, exactly as an operator runs it."""

    CLI = REPO_ROOT / "cli" / "vulscanner.py"

    def run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(self.CLI), *args],
            capture_output=True, text=True, timeout=180,
            cwd=str(REPO_ROOT),
        )

    def test_help(self):
        result = self.run("--help")
        assert result.returncode == 0
        assert "vulscanner" in result.stdout
        for command in ("scan", "network", "findings", "report", "version"):
            assert command in result.stdout

    def test_version_json(self):
        result = self.run("version", "--json")
        assert result.returncode == 0
        payload = json.loads(result.stdout)
        assert payload["product"] == "VulScanner"
        assert payload["collectors"] > 20

    def test_scan_help_documents_profiles(self):
        result = self.run("scan", "--help")
        assert result.returncode == 0
        for profile in ("quick", "standard", "full", "network", "compliance"):
            assert profile in result.stdout

    def test_unauthorized_target_is_refused(self):
        result = self.run("scan", "--target", "8.8.8.8", "--quiet", "--no-colour")
        assert result.returncode == 3
        assert "authorized" in (result.stderr + result.stdout).lower()

    def test_password_is_never_accepted_as_an_argument(self):
        result = self.run("scan", "--target", "192.168.1.5", "--username", "admin")
        assert result.returncode == 2
        assert "never accepts a password" in (result.stderr + result.stdout)
