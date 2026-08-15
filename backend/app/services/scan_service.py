"""Scan orchestration: run the engine, analyse the results, persist everything.

This is the single path both the REST API and the CLI use, so a scan produces
identical data regardless of which interface started it.
"""

from __future__ import annotations

import threading
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import APP_VERSION, settings
from app.core.logging import get_logger
from app.core.permissions import AuthorizationError, authorize_target
from app.db.session import session_scope
from app.models.asset import Asset
from app.models.audit import AuditAction
from app.models.finding import Finding, FindingStatus, Severity
from app.models.network import NetworkConnection, NetworkEdge, NetworkHost, NetworkPort
from app.models.scan import Scan, ScanResult, ScanStatus
from app.models.target import Target
from app.models.vulnerability import CVE, Patch, Vulnerability
from app.scanner.engine import ScanEngine, ScanOutput, parse_port_range
from app.scanner.runner import RemoteCredential
from app.services import audit_service
from app.services.analyzers import AnalysisContext, analyze
from app.services.cve_service import cve_service
from app.services.patch_service import patch_service
from app.services.risk_engine import (
    ExposureLevel,
    RiskInputs,
    risk_engine,
    security_score,
    severity_for_cvss,
)

logger = get_logger(__name__)

# Stages surfaced to the UI and CLI, in order.
SCAN_STAGES = [
    {"key": "preflight", "label": "Preflight"},
    {"key": "collection", "label": "Windows & Network Collection"},
    {"key": "discovery", "label": "Network Discovery"},
    {"key": "topology", "label": "Network Topology"},
    {"key": "correlation", "label": "Vulnerability Correlation"},
    {"key": "analysis", "label": "Risk Analysis"},
    {"key": "persistence", "label": "Storing Results"},
    {"key": "complete", "label": "Complete"},
]


class ProgressBroker:
    """Fan-out of live scan progress to SSE/WebSocket subscribers."""

    def __init__(self) -> None:
        self._subscribers: dict[int, list[Callable[[dict], None]]] = defaultdict(list)
        self._latest: dict[int, dict] = {}
        self._lock = threading.Lock()

    def subscribe(self, scan_id: int, callback: Callable[[dict], None]) -> None:
        with self._lock:
            self._subscribers[scan_id].append(callback)

    def unsubscribe(self, scan_id: int, callback: Callable[[dict], None]) -> None:
        with self._lock:
            if callback in self._subscribers.get(scan_id, []):
                self._subscribers[scan_id].remove(callback)

    def publish(self, scan_id: int, event: dict) -> None:
        with self._lock:
            self._latest[scan_id] = event
            callbacks = list(self._subscribers.get(scan_id, []))
        for callback in callbacks:
            try:
                callback(event)
            except Exception:  # a dead subscriber must not break the scan
                logger.debug("Progress subscriber failed", exc_info=True)

    def latest(self, scan_id: int) -> dict | None:
        with self._lock:
            return self._latest.get(scan_id)


progress_broker = ProgressBroker()


class ScanService:
    """Creates, runs, tracks and cancels scans."""

    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(
            max_workers=max(1, settings.max_concurrent_scans),
            thread_name_prefix="vulscanner-scan",
        )
        self._running: dict[int, ScanEngine] = {}
        self._lock = threading.Lock()

    # -- creation ----------------------------------------------------------
    def authorized_scopes(self, db: Session) -> list[str]:
        """Scopes an operator has explicitly registered as authorized."""
        rows = db.scalars(select(Target).where(Target.authorized.is_(True))).all()
        return [row.value for row in rows]

    def create_scan(
        self,
        db: Session,
        *,
        name: str,
        target: str,
        profile: str = "standard",
        options: dict | None = None,
        user_id: int | None = None,
        actor_name: str = "system",
    ) -> Scan:
        """Validate authorization and queue a scan."""
        options = dict(options or {})
        try:
            authorization = authorize_target(target, self.authorized_scopes(db))
        except AuthorizationError as exc:
            audit_service.record(
                db,
                AuditAction.AUTHORIZATION_DENIED,
                actor_id=user_id,
                actor_name=actor_name,
                outcome="denied",
                entity_type="target",
                entity_id=target,
                message=str(exc),
            )
            raise

        if isinstance(options.get("ports"), str):
            options["ports"] = parse_port_range(options["ports"])

        target_row = db.scalar(select(Target).where(Target.value == target))

        scan = Scan(
            name=name or f"{profile.title()} scan of {target}",
            target=target,
            target_type=authorization.kind,
            target_id=target_row.id if target_row else None,
            profile=profile,
            status=ScanStatus.QUEUED.value,
            options=options,
            stages=[
                {**stage, "status": "pending"} for stage in SCAN_STAGES
            ],
            scanner_version=APP_VERSION,
            created_by_id=user_id,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        audit_service.record(
            db,
            AuditAction.SCAN_STARTED,
            actor_id=user_id,
            actor_name=actor_name,
            entity_type="scan",
            entity_id=scan.id,
            message=f"Scan queued for {target} using the {profile} profile.",
            details={
                "target": target,
                "target_type": authorization.kind,
                "profile": profile,
                "matched_authorized_scope": authorization.matched_scope,
            },
        )
        return scan

    # -- execution ---------------------------------------------------------
    def submit(self, scan_id: int, credential: RemoteCredential | None = None) -> None:
        """Queue the scan for background execution."""
        self._executor.submit(self.execute, scan_id, credential)

    def execute(
        self, scan_id: int, credential: RemoteCredential | None = None
    ) -> None:
        """Run a scan to completion. Safe to call from a worker thread."""
        try:
            with session_scope() as db:
                scan = db.get(Scan, scan_id)
                if scan is None:
                    logger.error("Scan %s not found", scan_id)
                    return
                if scan.status not in (ScanStatus.QUEUED.value, ScanStatus.RUNNING.value):
                    return
                target = scan.target
                profile = scan.profile
                options = dict(scan.options or {})
                authorized = self.authorized_scopes(db)
                scan.status = ScanStatus.RUNNING.value
                scan.started_at = datetime.now(tz=timezone.utc)
                scan.scanner_version = APP_VERSION
                db.commit()

            self._publish(scan_id, "preflight", 0.0, "Scan starting", "running")

            def on_progress(stage: str, percent: float, message: str) -> None:
                self._publish(scan_id, stage, percent, message, "running")
                self._persist_progress(scan_id, stage, percent)

            engine = ScanEngine.for_target(
                target,
                profile=profile,
                options=options,
                credential=credential,
                extra_authorized=authorized,
                scan_id=scan_id,
                progress_callback=on_progress,
            )
            with self._lock:
                self._running[scan_id] = engine

            output = engine.run()
            self._publish(scan_id, "correlation", 88.0, "Correlating vulnerabilities", "running")
            self.persist_results(scan_id, output)

        except AuthorizationError as exc:
            self._fail(scan_id, f"Authorization refused: {exc}")
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Scan %s failed", scan_id)
            self._fail(scan_id, f"{type(exc).__name__}: {exc}")
        finally:
            with self._lock:
                self._running.pop(scan_id, None)

    def run_sync(
        self,
        db: Session,
        *,
        name: str,
        target: str,
        profile: str = "standard",
        options: dict | None = None,
        credential: RemoteCredential | None = None,
        user_id: int | None = None,
        actor_name: str = "cli",
        progress_callback: Callable[[str, float, str], None] | None = None,
    ) -> Scan:
        """Create and run a scan inline. Used by the CLI."""
        scan = self.create_scan(
            db,
            name=name,
            target=target,
            profile=profile,
            options=options,
            user_id=user_id,
            actor_name=actor_name,
        )
        scan_id = scan.id

        def forward(stage: str, percent: float, message: str) -> None:
            self._publish(scan_id, stage, percent, message, "running")
            if progress_callback:
                progress_callback(stage, percent, message)

        scan.status = ScanStatus.RUNNING.value
        scan.started_at = datetime.now(tz=timezone.utc)
        db.commit()

        engine = ScanEngine.for_target(
            target,
            profile=profile,
            options=options or {},
            credential=credential,
            extra_authorized=self.authorized_scopes(db),
            scan_id=scan_id,
            progress_callback=forward,
        )
        with self._lock:
            self._running[scan_id] = engine
        try:
            output = engine.run()
            self.persist_results(scan_id, output)
        finally:
            with self._lock:
                self._running.pop(scan_id, None)

        db.expire_all()
        return db.get(Scan, scan_id)

    def cancel(self, scan_id: int) -> bool:
        with self._lock:
            engine = self._running.get(scan_id)
        if engine is None:
            return False
        engine.context.cancel()
        self._publish(scan_id, "cancelled", 100.0, "Cancellation requested", "cancelled")
        return True

    def is_running(self, scan_id: int) -> bool:
        with self._lock:
            return scan_id in self._running

    # -- persistence -------------------------------------------------------
    def persist_results(self, scan_id: int, output: ScanOutput) -> None:
        """Store collector results, findings, vulnerabilities and topology."""
        with session_scope() as db:
            scan = db.get(Scan, scan_id)
            if scan is None:
                return

            asset = self._upsert_asset(db, scan, output)

            for result in output.results:
                db.add(
                    ScanResult(
                        scan_id=scan.id,
                        asset_id=asset.id if asset else None,
                        collector=result.collector,
                        category=result.category,
                        status=result.status.value,
                        data=result.data,
                        warnings=result.warnings,
                        errors=result.errors,
                        collection_method=result.collection_method,
                        collected_at=result.collected_at,
                        duration_seconds=result.duration_seconds,
                    )
                )
            db.flush()

            context = AnalysisContext(
                collector_data={r.collector: r.data for r in output.results},
                collector_status={r.collector: r.status.value for r in output.results},
                discovery=output.discovery,
                topology=output.topology,
                profile=output.profile,
                elevated=output.elevated,
                asset_criticality=asset.criticality if asset else "normal",
            )
            findings = analyze(context, target=output.target)

            vulnerabilities = self._correlate_vulnerabilities(
                db, scan, asset, output, findings
            )
            self._persist_findings(db, scan, asset, findings)
            self._persist_patches(db, scan, asset, output)
            self._persist_network(db, scan, asset, output)

            db.flush()
            self._finalize(db, scan, asset, output, findings, vulnerabilities)
            db.commit()

            self._publish(
                scan_id,
                "complete",
                100.0,
                f"Scan complete: {len(findings)} findings, "
                f"{len(vulnerabilities)} vulnerabilities",
                scan.status,
            )
            audit_service.record(
                db,
                AuditAction.SCAN_COMPLETED,
                actor_id=scan.created_by_id,
                entity_type="scan",
                entity_id=scan.id,
                message=(
                    f"Scan of {scan.target} finished with status {scan.status}: "
                    f"{scan.critical_count} critical, {scan.high_count} high, "
                    f"{scan.medium_count} medium, {scan.low_count} low."
                ),
                details={
                    "profile": scan.profile,
                    "duration_seconds": scan.duration_seconds,
                    "finding_count": len(findings),
                    "vulnerability_count": len(vulnerabilities),
                },
            )

    # -- persistence helpers ----------------------------------------------
    def _upsert_asset(
        self, db: Session, scan: Scan, output: ScanOutput
    ) -> Asset | None:
        os_data = output.data("os")
        adapters = output.data("adapters")

        hostname = os_data.get("hostname") or ""
        addresses = adapters.get("ipv4_addresses", [])
        primary_ip = addresses[0] if addresses else None
        mac = next(
            (
                adapter.get("mac_address")
                for adapter in adapters.get("adapters", [])
                if adapter.get("mac_address") and adapter.get("status") == "Up"
            ),
            None,
        )

        if not hostname and not primary_ip:
            if output.target_type == "cidr":
                return None  # scope scans record hosts, not a single asset
            hostname = output.target

        asset = None
        if hostname:
            asset = db.scalar(select(Asset).where(Asset.hostname == hostname))
        if asset is None and primary_ip:
            asset = db.scalar(select(Asset).where(Asset.ip_address == primary_ip))

        now = datetime.now(tz=timezone.utc)
        if asset is None:
            asset = Asset(
                asset_uid=str(uuid.uuid4()),
                first_seen=now,
                target_id=scan.target_id,
            )
            db.add(asset)

        asset.hostname = hostname or asset.hostname
        asset.ip_address = primary_ip or asset.ip_address
        asset.ip_addresses = addresses or asset.ip_addresses
        asset.mac_address = mac or asset.mac_address
        asset.os_name = os_data.get("product_name") or asset.os_name
        asset.os_version = os_data.get("display_version") or asset.os_version
        asset.os_build = os_data.get("full_build") or asset.os_build
        asset.os_edition = os_data.get("edition") or asset.os_edition
        asset.architecture = os_data.get("architecture") or asset.architecture
        asset.domain = os_data.get("domain") or asset.domain
        asset.asset_type = "local" if output.target_type == "local" else "remote-windows"
        asset.os_confidence = "reported" if os_data else asset.os_confidence
        asset.last_seen = now
        db.flush()
        return asset

    def _persist_findings(
        self, db: Session, scan: Scan, asset: Asset | None, findings: list[dict]
    ) -> None:
        now = datetime.now(tz=timezone.utc)
        existing: dict[str, Finding] = {}
        if asset is not None:
            rows = db.scalars(
                select(Finding).where(Finding.asset_id == asset.id)
            ).all()
            existing = {row.finding_uid: row for row in rows}

        current_uids = set()
        for finding in findings:
            uid = finding["finding_uid"]
            current_uids.add(uid)
            previous = existing.get(uid)

            row = Finding(
                finding_uid=uid,
                rule_id=finding["rule_id"],
                title=finding["title"],
                category=finding["category"],
                severity=finding["severity"],
                risk_score=finding["risk_score"],
                cvss_score=finding.get("cvss_score"),
                confidence=finding["confidence"],
                description=finding["description"],
                impact=finding["impact"],
                evidence=finding["evidence"],
                evidence_summary=finding["evidence_summary"],
                detection_method=finding["detection_method"],
                remediation=finding["remediation"],
                remediation_command=finding["remediation_command"],
                references=finding["references"],
                risk_factors=finding["risk_factors"],
                scan_id=scan.id,
                asset_id=asset.id if asset else None,
                first_detected_at=previous.first_detected_at if previous else now,
                last_detected_at=now,
            )
            # A finding the operator had resolved but which is present again is
            # explicitly reopened rather than silently recreated as new.
            if previous and previous.status == FindingStatus.RESOLVED.value:
                row.status = FindingStatus.REOPENED.value
                row.status_note = (
                    f"Reopened: detected again by scan #{scan.id}."
                )
            elif previous and previous.status in (
                FindingStatus.RISK_ACCEPTED.value,
                FindingStatus.FALSE_POSITIVE.value,
            ):
                row.status = previous.status
                row.status_note = previous.status_note
            db.add(row)

        # Findings seen previously but absent now are marked resolved.
        for uid, previous in existing.items():
            if uid in current_uids:
                continue
            if previous.status in (
                FindingStatus.OPEN.value,
                FindingStatus.REOPENED.value,
            ):
                previous.status = FindingStatus.RESOLVED.value
                previous.resolved_at = now
                previous.status_note = (
                    f"No longer detected as of scan #{scan.id}."
                )

    def _correlate_vulnerabilities(
        self,
        db: Session,
        scan: Scan,
        asset: Asset | None,
        output: ScanOutput,
        findings: list[dict],
    ) -> list[Vulnerability]:
        software = output.data("software")
        updates = output.data("updates")
        ports = output.data("ports")

        if not scan.options.get("vulnerability_correlation", True):
            return []

        applications = software.get("correlation_candidates") or []
        limit = int(scan.options.get("cve_product_limit", 20))

        try:
            correlations = cve_service.correlate_software(applications, max_products=limit)
        except Exception as exc:  # intelligence failure must not fail a scan
            logger.warning("CVE correlation failed: %s", exc)
            scan.warnings = list(scan.warnings or []) + [
                f"Vulnerability correlation was incomplete: {exc}"
            ]
            correlations = []

        network_exposed = bool((ports.get("network_reachable_ports") or []))
        vulnerabilities: list[Vulnerability] = []

        for correlation in correlations:
            record = correlation["cve"]
            if record is None:
                continue
            cve_row = self._upsert_cve(db, record)

            exposure = (
                ExposureLevel.NETWORK
                if network_exposed and record.attack_vector == "NETWORK"
                else ExposureLevel.LOCAL
            )
            risk = risk_engine.score(
                RiskInputs(
                    cvss_score=record.cvss_v3_score,
                    exposure=exposure,
                    confidence=correlation["confidence"],
                    asset_criticality=asset.criticality if asset else "normal",
                    kev=record.kev,
                    kev_ransomware=record.kev_ransomware,
                    attack_vector=record.attack_vector,
                    exploitability_score=record.exploitability_score,
                    patch_available=True,
                )
            )

            vulnerability = Vulnerability(
                cve_id=record.cve_id,
                cve_ref_id=cve_row.id if cve_row else None,
                product=correlation["product"],
                vendor=correlation["vendor"],
                product_version=correlation["product_version"],
                affected_versions=correlation["affected_versions"],
                cvss_score=record.cvss_v3_score,
                cvss_vector=record.cvss_v3_vector,
                severity=severity_for_cvss(record.cvss_v3_score).value,
                risk_score=risk.score,
                risk_factors=risk.factors,
                kev=record.kev,
                confidence=correlation["confidence"],
                match_method=correlation["match_method"],
                evidence=correlation["evidence"],
                patch=f"Update {correlation['product']} beyond {correlation['affected_versions']}",
                remediation=(
                    f"Update {correlation['product']} from "
                    f"{correlation['product_version']} to a release outside the "
                    f"affected range ({correlation['affected_versions']})."
                ),
                references=record.references,
                scan_id=scan.id,
                asset_id=asset.id if asset else None,
            )
            db.add(vulnerability)
            vulnerabilities.append(vulnerability)

            findings.append(
                self._vulnerability_finding(vulnerability, record, risk, output.target)
            )

        # Missing security updates become vulnerability records with confirmed
        # evidence from the Windows Update agent.
        for entry in cve_service.correlate_missing_updates(
            updates.get("pending_updates") or []
        ):
            kb_label = ", ".join(entry["kbs"])
            risk = risk_engine.score(
                RiskInputs(
                    base_severity=(
                        Severity.CRITICAL.value
                        if entry["msrc_severity"].lower() == "critical"
                        else Severity.HIGH.value
                    ),
                    exposure=ExposureLevel.NETWORK if network_exposed else ExposureLevel.LOCAL,
                    confidence="confirmed",
                    asset_criticality=asset.criticality if asset else "normal",
                    patch_missing=True,
                    patch_available=True,
                )
            )
            vulnerability = Vulnerability(
                cve_id=kb_label,
                product="Microsoft Windows",
                vendor="microsoft",
                product_version=output.data("os").get("full_build", ""),
                affected_versions=f"builds without {kb_label}",
                severity=(
                    Severity.CRITICAL.value
                    if entry["msrc_severity"].lower() == "critical"
                    else Severity.HIGH.value
                ),
                risk_score=risk.score,
                risk_factors=risk.factors,
                confidence="confirmed",
                match_method="kb-missing",
                evidence=entry["evidence"],
                patch=kb_label,
                remediation=entry["remediation"],
                references=entry["references"],
                scan_id=scan.id,
                asset_id=asset.id if asset else None,
            )
            db.add(vulnerability)
            vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _upsert_cve(self, db: Session, record) -> CVE | None:
        existing = db.scalar(select(CVE).where(CVE.cve_id == record.cve_id))
        now = datetime.now(tz=timezone.utc)
        if existing is None:
            existing = CVE(cve_id=record.cve_id)
            db.add(existing)
        existing.description = record.description
        existing.cvss_v3_score = record.cvss_v3_score
        existing.cvss_v3_vector = record.cvss_v3_vector
        existing.cvss_v2_score = record.cvss_v2_score
        existing.cvss_severity = record.cvss_severity
        existing.attack_vector = record.attack_vector
        existing.exploitability_score = record.exploitability_score
        existing.impact_score = record.impact_score
        existing.cwe_ids = record.cwe_ids
        existing.cpe_matches = record.cpe_matches[:50]
        existing.references = record.references
        existing.kev = record.kev
        existing.kev_date_added = record.kev_date_added
        existing.kev_due_date = record.kev_due_date
        existing.kev_ransomware = record.kev_ransomware
        existing.fetched_at = now
        db.flush()
        return existing

    @staticmethod
    def _vulnerability_finding(
        vulnerability: Vulnerability, record, risk, target: str
    ) -> dict:
        from app.services.analyzers import finding_uid

        kev_note = (
            " This CVE is in the CISA Known Exploited Vulnerabilities catalogue"
            + (
                f" (added {record.kev_date_added})."
                if record.kev_date_added
                else "."
            )
            if record.kev
            else ""
        )
        return {
            "finding_uid": finding_uid(
                "CVE", f"{record.cve_id}:{vulnerability.product}", target
            ),
            "rule_id": "CVE-MATCH",
            "title": f"{record.cve_id} affects {vulnerability.product} {vulnerability.product_version}",
            "category": "vulnerability",
            "severity": risk.severity.value,
            "rule_severity": severity_for_cvss(record.cvss_v3_score).value,
            "risk_score": risk.score,
            "risk_factors": risk.factors,
            "cvss_score": record.cvss_v3_score,
            "confidence": vulnerability.confidence,
            "description": (
                f"{vulnerability.product} version {vulnerability.product_version} is "
                f"installed and falls inside the range affected by {record.cve_id} "
                f"({vulnerability.affected_versions}).{kev_note} "
                f"{record.description[:400]}"
            ),
            "impact": (
                f"Official CVSS v3 base score {record.cvss_v3_score} "
                f"({record.cvss_severity or 'unrated'}), attack vector "
                f"{record.attack_vector or 'unspecified'}."
            ),
            "evidence": vulnerability.evidence,
            "evidence_summary": (
                f"Installed {vulnerability.product} {vulnerability.product_version}; "
                f"affected range {vulnerability.affected_versions}"
            ),
            "detection_method": "NVD CPE correlation against the software inventory",
            "remediation": vulnerability.remediation,
            "remediation_command": "",
            "references": record.references,
            "source_collector": "software",
            "instance_key": f"{record.cve_id}:{vulnerability.product}",
        }

    def _persist_patches(
        self, db: Session, scan: Scan, asset: Asset | None, output: ScanOutput
    ) -> None:
        records = patch_service.build_inventory(
            output.data("hotfixes"), output.data("updates")
        )
        for record in records:
            db.add(
                Patch(
                    kb_id=record.kb_id,
                    title=record.title,
                    description=record.description,
                    classification=record.classification,
                    state=record.state,
                    installed_on=record.installed_on,
                    installed_by=record.installed_by,
                    severity=record.severity,
                    confidence=record.confidence,
                    evidence=record.evidence,
                    asset_id=asset.id if asset else None,
                    scan_id=scan.id,
                )
            )

    def _persist_network(
        self, db: Session, scan: Scan, asset: Asset | None, output: ScanOutput
    ) -> None:
        now = datetime.now(tz=timezone.utc)

        for port in output.data("ports").get("ports", []):
            db.add(
                NetworkPort(
                    port=port.get("local_port", 0),
                    protocol=port.get("protocol", "tcp"),
                    state="listen",
                    service=port.get("service"),
                    service_source=port.get("service_source", "well-known"),
                    local_address=port.get("local_address"),
                    process_id=port.get("process_id"),
                    process_name=port.get("process_name"),
                    process_path=port.get("process_path"),
                    owning_service=", ".join(port.get("services") or []) or None,
                    exposure=port.get("exposure", "unknown"),
                    risk_score=port.get("risk_score", 0.0),
                    asset_id=asset.id if asset else None,
                    scan_id=scan.id,
                )
            )

        for connection in output.data("connections").get("established", []):
            db.add(
                NetworkConnection(
                    protocol=connection.get("protocol", "tcp"),
                    local_address=connection.get("local_address", ""),
                    local_port=connection.get("local_port"),
                    remote_address=connection.get("remote_address"),
                    remote_port=connection.get("remote_port"),
                    state=connection.get("state"),
                    process_id=connection.get("process_id"),
                    process_name=connection.get("process_name"),
                    remote_scope=connection.get("remote_scope", "unknown"),
                    asset_id=asset.id if asset else None,
                    scan_id=scan.id,
                )
            )

        for host in output.discovery.get("hosts", []):
            network_host = NetworkHost(
                ip_address=host.get("ip_address", ""),
                mac_address=host.get("mac_address") or None,
                hostname=host.get("hostname") or None,
                vendor=host.get("vendor") or None,
                discovery_method=host.get("discovery_method", ""),
                is_up=bool(host.get("is_up", True)),
                latency_ms=host.get("latency_ms"),
                os_guess=host.get("os_guess") or None,
                os_confidence=host.get("os_confidence", "unknown"),
                os_evidence=host.get("os_evidence", []),
                is_gateway=bool(host.get("is_gateway")),
                is_local=bool(host.get("is_local")),
                scan_id=scan.id,
                first_seen=now,
                last_seen=now,
            )
            db.add(network_host)
            db.flush()
            for port in host.get("ports", []):
                db.add(
                    NetworkPort(
                        port=port.get("port", 0),
                        protocol=port.get("protocol", "tcp"),
                        state=port.get("state", "open"),
                        service=port.get("service"),
                        service_source=port.get("service_source", "well-known"),
                        banner=port.get("banner") or None,
                        exposure="network",
                        host_id=network_host.id,
                        scan_id=scan.id,
                    )
                )

        for edge in output.topology.get("edges", []):
            db.add(
                NetworkEdge(
                    source_node=edge.get("source", ""),
                    target_node=edge.get("target", ""),
                    edge_type=edge.get("type", "layer3"),
                    relationship_confidence=edge.get("confidence", "inferred"),
                    evidence=edge.get("evidence", {}),
                    label=edge.get("label", ""),
                    scan_id=scan.id,
                )
            )

    def _finalize(
        self,
        db: Session,
        scan: Scan,
        asset: Asset | None,
        output: ScanOutput,
        findings: list[dict],
        vulnerabilities: list[Vulnerability],
    ) -> None:
        counts = {level: 0 for level in ("critical", "high", "medium", "low", "informational")}
        for finding in findings:
            counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1

        scan.critical_count = counts["critical"]
        scan.high_count = counts["high"]
        scan.medium_count = counts["medium"]
        scan.low_count = counts["low"]
        scan.info_count = counts["informational"]
        scan.vulnerability_count = len(vulnerabilities)
        scan.asset_count = (
            len(output.discovery.get("hosts", [])) if output.discovery else (1 if asset else 0)
        )
        scan.security_score = security_score(
            counts["critical"], counts["high"], counts["medium"], counts["low"]
        )
        scan.risk_score = round(
            max([f["risk_score"] for f in findings], default=0.0), 1
        )
        scan.warnings = list(scan.warnings or []) + output.warnings
        scan.errors = output.errors
        scan.progress = 100.0
        scan.current_stage = "complete"
        scan.finished_at = output.finished_at or datetime.now(tz=timezone.utc)
        scan.duration_seconds = output.duration_seconds
        scan.scanner_host = output.scanner_host
        scan.status = {
            "completed": ScanStatus.COMPLETED.value,
            "partial": ScanStatus.PARTIAL.value,
            "failed": ScanStatus.FAILED.value,
            "cancelled": ScanStatus.CANCELLED.value,
        }.get(output.status, ScanStatus.COMPLETED.value)
        scan.stages = [
            {**stage, "status": "complete"} for stage in SCAN_STAGES
        ]

        if asset is not None:
            asset.finding_count = len(findings)
            asset.critical_count = counts["critical"]
            asset.high_count = counts["high"]
            asset.medium_count = counts["medium"]
            asset.low_count = counts["low"]
            asset.vulnerability_count = len(vulnerabilities)
            asset.open_port_count = len(
                output.data("ports").get("network_reachable_ports", [])
            )
            asset.risk_score = scan.risk_score or 0.0
            asset.severity = (
                "critical" if counts["critical"]
                else "high" if counts["high"]
                else "medium" if counts["medium"]
                else "low" if counts["low"]
                else "informational"
            )

    # -- progress ----------------------------------------------------------
    def _publish(
        self, scan_id: int, stage: str, percent: float, message: str, status: str
    ) -> None:
        progress_broker.publish(
            scan_id,
            {
                "scan_id": scan_id,
                "stage": stage,
                "progress": round(percent, 1),
                "message": message,
                "status": status,
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            },
        )

    def _persist_progress(self, scan_id: int, stage: str, percent: float) -> None:
        # Progress updates are frequent; keep the write cheap and non-fatal.
        try:
            with session_scope() as db:
                scan = db.get(Scan, scan_id)
                if scan and scan.status == ScanStatus.RUNNING.value:
                    scan.progress = round(percent, 1)
                    scan.current_stage = stage
        except Exception:  # pragma: no cover
            logger.debug("Could not persist progress for scan %s", scan_id, exc_info=True)

    def _fail(self, scan_id: int, message: str) -> None:
        with session_scope() as db:
            scan = db.get(Scan, scan_id)
            if scan is None:
                return
            scan.status = ScanStatus.FAILED.value
            scan.error_message = message
            scan.errors = list(scan.errors or []) + [message]
            scan.finished_at = datetime.now(tz=timezone.utc)
            scan.progress = 100.0
            scan.current_stage = "failed"
            audit_service.record(
                db,
                AuditAction.SCAN_FAILED,
                entity_type="scan",
                entity_id=scan_id,
                outcome="failure",
                message=message,
            )
        self._publish(scan_id, "failed", 100.0, message, ScanStatus.FAILED.value)


scan_service = ScanService()
