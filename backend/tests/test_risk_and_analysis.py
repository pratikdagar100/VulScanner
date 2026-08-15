"""Risk engine, detection rule and topology tests."""

from __future__ import annotations

import pytest

from app.models.finding import Confidence, Severity
from app.services.analyzers import analyze
from app.services.risk_engine import (
    ExposureLevel,
    RiskInputs,
    risk_engine,
    score_finding,
    security_score,
    severity_for_cvss,
    severity_for_score,
)
from tests.mock_data import build_analysis_context


class TestSeverityBands:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (95.0, Severity.CRITICAL),
            (90.0, Severity.CRITICAL),
            (89.9, Severity.HIGH),
            (70.0, Severity.HIGH),
            (69.9, Severity.MEDIUM),
            (40.0, Severity.MEDIUM),
            (39.9, Severity.LOW),
            (0.0, Severity.INFORMATIONAL),
        ],
    )
    def test_bands_match_the_documented_thresholds(self, score, expected):
        assert severity_for_score(score) is expected

    @pytest.mark.parametrize(
        "cvss,expected",
        [(9.8, Severity.CRITICAL), (7.5, Severity.HIGH), (5.0, Severity.MEDIUM),
         (2.1, Severity.LOW), (None, Severity.INFORMATIONAL)],
    )
    def test_official_cvss_rating_is_separate(self, cvss, expected):
        assert severity_for_cvss(cvss) is expected


class TestRiskEngine:
    def test_exposure_raises_the_score(self):
        local = score_finding(severity="high", exposure=ExposureLevel.LOCAL)
        network = score_finding(severity="high", exposure=ExposureLevel.NETWORK)
        internet = score_finding(severity="high", exposure=ExposureLevel.INTERNET)
        assert local.score < network.score < internet.score

    def test_kev_membership_raises_the_score(self):
        base = risk_engine.score(RiskInputs(cvss_score=7.5))
        kev = risk_engine.score(RiskInputs(cvss_score=7.5, kev=True))
        assert kev.score > base.score
        assert kev.factors["exploitation"]["kev"] is True

    def test_low_confidence_reduces_the_score(self):
        confirmed = score_finding(severity="high", confidence=Confidence.CONFIRMED.value)
        low = score_finding(severity="high", confidence=Confidence.LOW.value)
        assert low.score < confirmed.score

    def test_asset_criticality_matters(self):
        normal = score_finding(severity="medium", asset_criticality="normal")
        critical = score_finding(severity="medium", asset_criticality="critical")
        assert critical.score > normal.score

    def test_local_attack_vector_is_not_inflated_by_network_exposure(self):
        """A local-only CVE must not be scored as remotely reachable."""
        result = risk_engine.score(
            RiskInputs(
                cvss_score=7.8,
                exposure=ExposureLevel.NETWORK,
                attack_vector="LOCAL",
            )
        )
        assert result.factors["exposure"]["multiplier"] <= 0.75

    def test_score_is_bounded(self):
        result = risk_engine.score(
            RiskInputs(
                cvss_score=10.0,
                exposure=ExposureLevel.INTERNET,
                kev=True,
                kev_ransomware=True,
                exploit_available=True,
                asset_criticality="critical",
                patch_missing=True,
                security_control_disabled=True,
                confidence=Confidence.CONFIRMED.value,
            )
        )
        assert 0.0 <= result.score <= 100.0
        assert result.severity is Severity.CRITICAL

    def test_informational_stays_zero(self):
        assert score_finding(severity="informational").score == 0.0

    def test_factors_explain_the_result(self):
        factors = score_finding(severity="high", exposure=ExposureLevel.NETWORK).factors
        assert "base" in factors and "exposure" in factors and "formula" in factors

    def test_cvss_is_recorded_separately_from_the_risk_score(self):
        result = risk_engine.score(RiskInputs(cvss_score=7.5))
        assert result.factors["base"]["cvss_score"] == 7.5
        assert result.score != 7.5


class TestSecurityScore:
    def test_clean_host_scores_full_marks(self):
        assert security_score(0, 0, 0, 0) == 100.0

    def test_score_degrades_monotonically(self):
        scores = [security_score(critical, 0, 0, 0) for critical in range(5)]
        assert scores == sorted(scores, reverse=True)

    def test_one_critical_outweighs_many_lows(self):
        assert security_score(1, 0, 0, 0) < security_score(0, 0, 0, 20)

    def test_never_collapses_to_zero(self):
        # Exponential decay keeps further deterioration visible.
        assert security_score(10, 20, 30, 40) > 0.0


class TestDetectionRules:
    @pytest.fixture(scope="class")
    def findings(self):
        return analyze(build_analysis_context(), target="mock-host")

    def test_findings_are_produced(self, findings):
        assert len(findings) > 15

    @pytest.mark.parametrize(
        "rule_id",
        [
            "DEF-001",   # real-time protection disabled
            "DEF-002",   # tamper protection disabled
            "DEF-003",   # broad exclusions
            "FW-001",    # firewall profile disabled
            "FW-002",    # permissive inbound rule
            "RDP-001",   # NLA disabled
            "RDP-002",   # RDP network exposed
            "ACC-001",   # guest enabled
            "ACC-002",   # no password required
            "ACC-005",   # autologon with stored password
            "ACC-006",   # unexpected administrators
            "UAC-004",   # remote UAC filtering disabled
            "AUTH-002",  # wdigest plaintext
            "AUTH-003",  # weak NTLM level
            "SHARE-001", # world accessible share
            "SHARE-002", # SMBv1
            "NET-001",   # high-risk listening port
            "PATCH-001", # missing security updates
            "PATCH-003", # automatic updates disabled
            "PATCH-004", # end of servicing
            "DISC-001",  # exposed service on the network
        ],
    )
    def test_expected_rule_fires(self, findings, rule_id):
        assert any(f["rule_id"] == rule_id for f in findings), (
            f"{rule_id} did not fire against the mock data"
        )

    def test_every_finding_carries_evidence_and_remediation(self, findings):
        for finding in findings:
            assert finding["evidence_summary"], finding["rule_id"]
            assert finding["detection_method"], finding["rule_id"]
            assert finding["remediation"], finding["rule_id"]
            assert finding["risk_factors"], finding["rule_id"]

    def test_findings_are_sorted_by_severity_then_risk(self, findings):
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        keys = [(order[f["severity"]], -f["risk_score"]) for f in findings]
        assert keys == sorted(keys)

    def test_finding_ids_are_deterministic(self):
        first = analyze(build_analysis_context(), target="mock-host")
        second = analyze(build_analysis_context(), target="mock-host")
        assert [f["finding_uid"] for f in first] == [f["finding_uid"] for f in second]

    def test_finding_ids_differ_per_target(self):
        a = analyze(build_analysis_context(), target="host-a")
        b = analyze(build_analysis_context(), target="host-b")
        assert {f["finding_uid"] for f in a}.isdisjoint({f["finding_uid"] for f in b})

    def test_no_duplicate_findings(self, findings):
        uids = [f["finding_uid"] for f in findings]
        assert len(uids) == len(set(uids))

    def test_loopback_only_service_is_not_reported_as_exposed(self, findings):
        # PostgreSQL is bound to 127.0.0.1 in the mock data.
        exposure_findings = [f for f in findings if f["rule_id"] == "NET-001"]
        assert all("5432" not in f["title"] for f in exposure_findings)


class TestEmptyEvidence:
    """A collector that returned nothing must not produce findings."""

    def test_no_data_means_no_findings(self):
        from app.services.analyzers.base import AnalysisContext

        findings = analyze(AnalysisContext(collector_data={}), target="empty")
        assert findings == []

    def test_absent_value_is_not_treated_as_insecure(self):
        from app.services.analyzers.base import AnalysisContext

        # UAC data present but EnableLUA unreadable: no UAC-001 may be raised.
        context = AnalysisContext(
            collector_data={"uac": {"enabled": None, "enable_lua_raw": None}}
        )
        findings = analyze(context, target="partial")
        assert not any(f["rule_id"] == "UAC-001" for f in findings)


class TestTopology:
    def test_edges_carry_confidence(self):
        from app.scanner.network.topology import build_topology
        from tests.mock_data import ADAPTERS_DATA, ARP_DATA, DISCOVERY_DATA

        topology = build_topology(
            hosts=DISCOVERY_DATA["hosts"],
            adapters=ADAPTERS_DATA,
            arp_entries=ARP_DATA["neighbours"],
        )
        assert topology["edges"]
        for edge in topology["edges"]:
            assert edge["confidence"] in ("observed", "inferred", "unknown")
            assert edge["evidence"]

    def test_arp_entries_are_observed_and_subnets_inferred(self):
        from app.scanner.network.topology import build_topology
        from tests.mock_data import ADAPTERS_DATA, ARP_DATA, DISCOVERY_DATA

        topology = build_topology(
            hosts=DISCOVERY_DATA["hosts"],
            adapters=ADAPTERS_DATA,
            arp_entries=ARP_DATA["neighbours"],
        )
        by_type = {edge["type"]: edge for edge in topology["edges"]}
        assert by_type["layer2"]["confidence"] == "observed"
        assert by_type["subnet"]["confidence"] == "inferred"
        # The internet uplink is never claimed as verified.
        assert by_type["internet"]["confidence"] == "inferred"

    def test_multicast_addresses_are_not_hosts(self):
        from app.scanner.network.arp import is_host_address

        assert is_host_address("192.168.1.10") is True
        assert is_host_address("224.0.0.251") is False
        assert is_host_address("ff02::fb") is False
        assert is_host_address("255.255.255.255") is False


class TestAssessmentMode:
    """A target that cannot be authenticated to must still be assessed."""

    def _context(self, target: str, credential=None):
        from app.core.permissions import authorize_target
        from app.scanner.context import ScanContext

        return ScanContext(
            authorization=authorize_target(target), credential=credential
        )

    def test_remote_without_credentials_is_unauthenticated_not_unsupported(self):
        context = self._context("192.168.1.50")
        assert context.assessment_mode == "remote-unauthenticated"
        assert context.is_unauthenticated_remote is True
        assert context.is_windows_target is False

    def test_remote_with_credentials_is_authenticated(self):
        from app.scanner.runner import RemoteCredential

        context = self._context(
            "192.168.1.50", RemoteCredential(username="admin", password="x")
        )
        assert context.assessment_mode == "remote-authenticated"
        assert context.is_windows_target is True

    def test_network_scope_mode(self):
        assert self._context("192.168.1.0/24").assessment_mode == "network-discovery"

    def test_skip_reason_is_specific_and_actionable(self):
        """The generic 'requires a Windows target' told operators nothing."""
        reason = self._context("192.168.1.50").windows_collection_reason()
        assert "192.168.1.50" in reason
        assert "credentials" in reason.lower()
        assert "unauthenticated" in reason.lower()

    def test_scope_scan_reason_differs_from_credential_reason(self):
        scope_reason = self._context("192.168.1.0/24").windows_collection_reason()
        host_reason = self._context("192.168.1.50").windows_collection_reason()
        assert scope_reason != host_reason


class TestUnauthenticatedFindings:
    """An unauthenticated host assessment must produce evidence, not nothing."""

    def _analyze(self, discovery: dict):
        from app.services.analyzers.base import AnalysisContext

        return analyze(
            AnalysisContext(
                collector_data={},
                discovery=discovery,
                assessment_mode="remote-unauthenticated",
            ),
            target="192.0.2.50",
        )

    def _discovery(self, ports: list[dict]) -> dict:
        return {
            "scope": "192.0.2.50",
            "ports_probed": [80, 443, 3389],
            "hosts": [
                {
                    "ip_address": "192.0.2.50",
                    "hostname": "device.example",
                    "mac_address": "00:11:22:33:44:55",
                    "ports": ports,
                    "os_guess": "",
                    "os_confidence": "unknown",
                }
            ],
            "summary": {"high_risk_exposures": []},
        }

    def test_exposed_services_are_reported(self):
        findings = self._analyze(
            self._discovery([{"port": 80, "service": "http", "banner": "nginx"}])
        )
        assert any(f["rule_id"] == "UNAUTH-001" for f in findings)

    def test_cleartext_service_is_flagged(self):
        findings = self._analyze(
            self._discovery([{"port": 23, "service": "telnet", "banner": ""}])
        )
        telnet = next(f for f in findings if f["rule_id"] == "UNAUTH-002")
        assert telnet["severity"] in ("high", "critical")
        assert "Telnet" in telnet["title"]

    def test_unresponsive_host_is_recorded_rather_than_silently_empty(self):
        findings = self._analyze(
            {"scope": "192.0.2.50", "ports_probed": [80, 443], "hosts": [],
             "summary": {"high_risk_exposures": []}}
        )
        assert any(f["rule_id"] == "UNAUTH-000" for f in findings)

    def test_rules_do_not_fire_for_an_authenticated_scan(self):
        from app.services.analyzers.base import AnalysisContext

        findings = analyze(
            AnalysisContext(
                collector_data={},
                discovery=self._discovery([{"port": 23, "service": "telnet"}]),
                assessment_mode="local-authenticated",
            ),
            target="local",
        )
        assert not any(f["rule_id"].startswith("UNAUTH-") for f in findings)
