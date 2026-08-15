"""VulScanner Security Assessment Report generation.

Formats: HTML (Jinja2), PDF (ReportLab - pure Python, no external binary),
JSON and CSV. Every report carries the scan id, timestamp, target, scanner
version, profile and evidence timestamps so a reader can always establish
provenance.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import APP_VERSION, settings
from app.core.logging import get_logger
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.network import NetworkEdge, NetworkHost, NetworkPort
from app.models.scan import Scan, ScanResult
from app.models.vulnerability import Patch, Vulnerability
from app.services.patch_service import patch_service
from app.services.remediation_service import remediation_service

logger = get_logger(__name__)

SEVERITY_COLOURS = {
    "critical": "#b3123b",
    "high": "#d9480f",
    "medium": "#b58a00",
    "low": "#1c7ed6",
    "informational": "#5c7080",
}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]


class ReportService:
    """Builds report payloads and renders them."""

    def __init__(self) -> None:
        self.template_dir = Path(settings.report_template_dir)
        self.output_dir = Path(settings.report_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._env: Environment | None = None

    @property
    def env(self) -> Environment:
        if self._env is None:
            self._env = Environment(
                loader=FileSystemLoader(str(self.template_dir)),
                autoescape=select_autoescape(["html", "xml"]),
                trim_blocks=True,
                lstrip_blocks=True,
            )
            self._env.filters["severity_colour"] = lambda s: SEVERITY_COLOURS.get(
                s, "#5c7080"
            )
            self._env.filters["pretty_json"] = lambda v: json.dumps(
                v, indent=2, default=str
            )
        return self._env

    # -- data assembly -----------------------------------------------------
    def build_payload(self, db: Session, scan_id: int) -> dict[str, Any]:
        scan = db.get(Scan, scan_id)
        if scan is None:
            raise ValueError(f"Scan {scan_id} not found")

        findings = db.scalars(
            select(Finding).where(Finding.scan_id == scan.id)
        ).all()
        vulnerabilities = db.scalars(
            select(Vulnerability).where(Vulnerability.scan_id == scan.id)
        ).all()
        results = db.scalars(
            select(ScanResult).where(ScanResult.scan_id == scan.id)
        ).all()
        patches = db.scalars(select(Patch).where(Patch.scan_id == scan.id)).all()
        hosts = db.scalars(
            select(NetworkHost).where(NetworkHost.scan_id == scan.id)
        ).all()
        ports = db.scalars(
            select(NetworkPort).where(NetworkPort.scan_id == scan.id)
        ).all()
        edges = db.scalars(
            select(NetworkEdge).where(NetworkEdge.scan_id == scan.id)
        ).all()
        asset = db.get(Asset, findings[0].asset_id) if findings and findings[0].asset_id else None

        by_collector = {r.collector: r for r in results}
        collector_data = {name: (r.data or {}) for name, r in by_collector.items()}

        remediation_items = remediation_service.build_plan(
            [self._finding_dict(f) for f in findings]
        )

        patch_summary = patch_service.summarize(
            patch_service.build_inventory(
                collector_data.get("hotfixes", {}), collector_data.get("updates", {})
            ),
            collector_data.get("hotfixes", {}),
            collector_data.get("updates", {}),
            collector_data.get("os", {}),
        )

        severity_counts = {
            level: sum(1 for f in findings if f.severity == level)
            for level in SEVERITY_ORDER
        }
        category_counts: dict[str, int] = {}
        for finding in findings:
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1

        return {
            "meta": {
                "product": "VulScanner",
                "report_title": "VulScanner Security Assessment Report",
                "scanner_version": scan.scanner_version or APP_VERSION,
                "scanner_host": scan.scanner_host,
                "generated_at": datetime.now(tz=timezone.utc).isoformat(),
                "scan_id": scan.id,
                "scan_name": scan.name,
                "target": scan.target,
                "target_type": scan.target_type,
                "profile": scan.profile,
                "status": scan.status,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
                "duration_seconds": scan.duration_seconds,
                "evidence_timestamps": {
                    r.collector: (r.collected_at.isoformat() if r.collected_at else None)
                    for r in results
                },
            },
            "executive_summary": {
                "security_score": scan.security_score,
                "highest_risk_score": scan.risk_score,
                "severity_counts": severity_counts,
                "total_findings": len(findings),
                "vulnerability_count": len(vulnerabilities),
                "kev_vulnerability_count": sum(1 for v in vulnerabilities if v.kev),
                "asset_count": scan.asset_count,
                "patch_status": {
                    "installed": patch_summary["installed_count"],
                    "missing": patch_summary["missing_count"],
                    "missing_security": patch_summary["missing_security_count"],
                    "evidence_quality": patch_summary["evidence_quality"],
                    "pending_reboot": patch_summary["pending_reboot"],
                },
                "network_exposure": {
                    "listening_ports": len(ports),
                    "network_reachable_ports": len(
                        [p for p in ports if p.exposure in ("all-interfaces", "private", "public")]
                    ),
                    "discovered_hosts": len(hosts),
                },
                "top_findings": [
                    self._finding_dict(f) for f in sorted(
                        findings, key=lambda f: -f.risk_score
                    )[:10]
                ],
                "warnings": scan.warnings or [],
                "errors": scan.errors or [],
            },
            "asset": self._asset_dict(asset) if asset else None,
            "system_information": collector_data.get("os", {}),
            "software": collector_data.get("software", {}),
            "patches": {
                "summary": patch_summary,
                "records": [self._patch_dict(p) for p in patches],
            },
            "defender": collector_data.get("defender", {}),
            "antivirus": collector_data.get("antivirus", {}),
            "firewall": collector_data.get("firewall", {}),
            "rdp": collector_data.get("rdp", {}),
            "users_and_groups": {
                "users": collector_data.get("local_users", {}),
                "groups": collector_data.get("local_groups", {}),
            },
            "security_policies": {
                "uac": collector_data.get("uac", {}),
                "audit_policy": collector_data.get("audit_policy", {}),
                "group_policy": collector_data.get("group_policy", {}),
                "authentication": collector_data.get("ntlm", {}),
                "boot_integrity": collector_data.get("secure_boot", {}),
            },
            "network": {
                "adapters": collector_data.get("adapters", {}),
                "profiles": collector_data.get("profiles", {}),
                "shares": collector_data.get("shares", {}),
                "dns": collector_data.get("dns", {}),
                "arp": collector_data.get("arp", {}),
                "connections": collector_data.get("connections", {}),
            },
            "ports": [self._port_dict(p) for p in ports],
            "discovered_hosts": [self._host_dict(h) for h in hosts],
            "topology": {
                "edges": [
                    {
                        "source": e.source_node,
                        "target": e.target_node,
                        "type": e.edge_type,
                        "confidence": e.relationship_confidence,
                        "label": e.label,
                        "evidence": e.evidence,
                    }
                    for e in edges
                ],
                "observed_count": sum(
                    1 for e in edges if e.relationship_confidence == "observed"
                ),
                "inferred_count": sum(
                    1 for e in edges if e.relationship_confidence == "inferred"
                ),
            },
            "findings": [self._finding_dict(f) for f in findings],
            "findings_by_severity": {
                level: [self._finding_dict(f) for f in findings if f.severity == level]
                for level in SEVERITY_ORDER
            },
            "category_counts": category_counts,
            "vulnerabilities": [self._vulnerability_dict(v) for v in vulnerabilities],
            "remediation": {
                "items": [item.to_dict() for item in remediation_items],
                "summary": remediation_service.summarize_plan(remediation_items),
            },
            "collectors": [
                {
                    "collector": r.collector,
                    "category": r.category,
                    "status": r.status,
                    "collection_method": r.collection_method,
                    "collected_at": r.collected_at.isoformat() if r.collected_at else None,
                    "duration_seconds": r.duration_seconds,
                    "warnings": r.warnings,
                    "errors": r.errors,
                }
                for r in results
            ],
            "methodology": {
                "authorization": (
                    "This assessment ran only against targets inside the operator's "
                    "configured authorized scope."
                ),
                "techniques": (
                    "Read-only collection via PowerShell, CIM/WMI and the Windows "
                    "registry. Network discovery uses full TCP connect probes. No "
                    "exploit was executed and no credential or key material was read."
                ),
                "limitations": (
                    "Findings reflect the state of the target at the evidence "
                    "timestamps above. Collectors that could not read a value are "
                    "reported as warnings rather than assumed insecure."
                ),
            },
        }

    # -- record shaping ----------------------------------------------------
    @staticmethod
    def _finding_dict(finding: Finding) -> dict:
        return {
            "finding_uid": finding.finding_uid,
            "rule_id": finding.rule_id,
            "title": finding.title,
            "category": finding.category,
            "severity": finding.severity,
            "risk_score": finding.risk_score,
            "cvss_score": finding.cvss_score,
            "confidence": finding.confidence,
            "status": finding.status,
            "description": finding.description,
            "impact": finding.impact,
            "evidence": finding.evidence,
            "evidence_summary": finding.evidence_summary,
            "detection_method": finding.detection_method,
            "remediation": finding.remediation,
            "remediation_command": finding.remediation_command,
            "references": finding.references,
            "risk_factors": finding.risk_factors,
            "first_detected_at": finding.first_detected_at.isoformat()
            if finding.first_detected_at
            else None,
            "last_detected_at": finding.last_detected_at.isoformat()
            if finding.last_detected_at
            else None,
        }

    @staticmethod
    def _vulnerability_dict(vulnerability: Vulnerability) -> dict:
        return {
            "cve_id": vulnerability.cve_id,
            "product": vulnerability.product,
            "vendor": vulnerability.vendor,
            "product_version": vulnerability.product_version,
            "affected_versions": vulnerability.affected_versions,
            "cvss_score": vulnerability.cvss_score,
            "cvss_vector": vulnerability.cvss_vector,
            "severity": vulnerability.severity,
            "risk_score": vulnerability.risk_score,
            "risk_factors": vulnerability.risk_factors,
            "kev": vulnerability.kev,
            "confidence": vulnerability.confidence,
            "match_method": vulnerability.match_method,
            "evidence": vulnerability.evidence,
            "patch": vulnerability.patch,
            "remediation": vulnerability.remediation,
            "references": vulnerability.references,
        }

    @staticmethod
    def _asset_dict(asset: Asset) -> dict:
        return {
            "asset_uid": asset.asset_uid,
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
            "ip_addresses": asset.ip_addresses,
            "mac_address": asset.mac_address,
            "vendor": asset.vendor,
            "os_name": asset.os_name,
            "os_version": asset.os_version,
            "os_build": asset.os_build,
            "os_edition": asset.os_edition,
            "architecture": asset.architecture,
            "domain": asset.domain,
            "criticality": asset.criticality,
            "risk_score": asset.risk_score,
            "severity": asset.severity,
            "first_seen": asset.first_seen.isoformat() if asset.first_seen else None,
            "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
        }

    @staticmethod
    def _port_dict(port: NetworkPort) -> dict:
        return {
            "port": port.port,
            "protocol": port.protocol,
            "state": port.state,
            "service": port.service,
            "local_address": port.local_address,
            "process_name": port.process_name,
            "process_id": port.process_id,
            "owning_service": port.owning_service,
            "exposure": port.exposure,
            "risk_score": port.risk_score,
            "banner": port.banner,
        }

    @staticmethod
    def _host_dict(host: NetworkHost) -> dict:
        return {
            "ip_address": host.ip_address,
            "hostname": host.hostname,
            "mac_address": host.mac_address,
            "vendor": host.vendor,
            "discovery_method": host.discovery_method,
            "latency_ms": host.latency_ms,
            "os_guess": host.os_guess,
            "os_confidence": host.os_confidence,
            "os_evidence": host.os_evidence,
            "is_gateway": host.is_gateway,
            "is_local": host.is_local,
        }

    @staticmethod
    def _patch_dict(patch: Patch) -> dict:
        return {
            "kb_id": patch.kb_id,
            "title": patch.title,
            "classification": patch.classification,
            "state": patch.state,
            "installed_on": patch.installed_on,
            "severity": patch.severity,
            "confidence": patch.confidence,
            "evidence": patch.evidence,
        }

    # -- rendering ---------------------------------------------------------
    def render_html(self, payload: dict) -> str:
        template = self.env.get_template("report.html.j2")
        return template.render(
            report=payload, severity_order=SEVERITY_ORDER, colours=SEVERITY_COLOURS
        )

    def render_json(self, payload: dict) -> str:
        return json.dumps(payload, indent=2, default=str)

    def render_csv(self, payload: dict) -> str:
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(
            [
                "finding_id", "rule_id", "title", "category", "severity",
                "vulscanner_risk_score", "official_cvss", "confidence", "status",
                "evidence_summary", "detection_method", "remediation", "references",
            ]
        )
        for finding in payload["findings"]:
            writer.writerow(
                [
                    finding["finding_uid"], finding["rule_id"], finding["title"],
                    finding["category"], finding["severity"], finding["risk_score"],
                    finding["cvss_score"] if finding["cvss_score"] is not None else "",
                    finding["confidence"], finding["status"],
                    finding["evidence_summary"], finding["detection_method"],
                    finding["remediation"], "; ".join(finding["references"] or []),
                ]
            )

        if payload["vulnerabilities"]:
            writer.writerow([])
            writer.writerow(
                ["cve", "product", "installed_version", "affected_versions",
                 "official_cvss", "severity", "vulscanner_risk_score", "kev",
                 "confidence", "match_method", "patch"]
            )
            for vulnerability in payload["vulnerabilities"]:
                writer.writerow(
                    [
                        vulnerability["cve_id"], vulnerability["product"],
                        vulnerability["product_version"],
                        vulnerability["affected_versions"],
                        vulnerability["cvss_score"] if vulnerability["cvss_score"] is not None else "",
                        vulnerability["severity"], vulnerability["risk_score"],
                        "yes" if vulnerability["kev"] else "no",
                        vulnerability["confidence"], vulnerability["match_method"],
                        vulnerability["patch"],
                    ]
                )
        return buffer.getvalue()

    def render_pdf(self, payload: dict, destination: Path) -> Path:
        """Render a PDF with ReportLab (pure Python, no external binary)."""
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            KeepTogether,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        styles = getSampleStyleSheet()
        styles.add(
            ParagraphStyle(
                name="VSTitle", parent=styles["Title"], fontSize=22, spaceAfter=6,
                textColor=colors.HexColor("#0b3d63"),
            )
        )
        styles.add(
            ParagraphStyle(
                name="VSHeading", parent=styles["Heading2"], fontSize=13,
                textColor=colors.HexColor("#0b3d63"), spaceBefore=12, spaceAfter=6,
            )
        )
        styles.add(
            ParagraphStyle(
                name="VSBody", parent=styles["BodyText"], fontSize=9, leading=12,
                alignment=TA_LEFT,
            )
        )
        styles.add(
            ParagraphStyle(
                name="VSSmall", parent=styles["BodyText"], fontSize=7.5, leading=10,
                textColor=colors.HexColor("#4a5568"),
            )
        )

        meta = payload["meta"]
        summary = payload["executive_summary"]
        story: list = []

        story.append(Paragraph("VulScanner Security Assessment Report", styles["VSTitle"]))
        story.append(
            Paragraph(
                f"Target <b>{meta['target']}</b> &nbsp;|&nbsp; Scan #{meta['scan_id']} "
                f"&nbsp;|&nbsp; Profile {meta['profile']} &nbsp;|&nbsp; "
                f"VulScanner {meta['scanner_version']}",
                styles["VSBody"],
            )
        )
        story.append(
            Paragraph(
                f"Scan started {meta['started_at']} &nbsp;|&nbsp; finished "
                f"{meta['finished_at']} &nbsp;|&nbsp; report generated "
                f"{meta['generated_at']}",
                styles["VSSmall"],
            )
        )
        story.append(Spacer(1, 8 * mm))

        # Executive summary
        story.append(Paragraph("Executive summary", styles["VSHeading"]))
        counts = summary["severity_counts"]
        summary_table = Table(
            [
                ["Security score", "Critical", "High", "Medium", "Low", "Informational"],
                [
                    f"{summary['security_score']}/100",
                    counts["critical"], counts["high"], counts["medium"],
                    counts["low"], counts["informational"],
                ],
            ],
            colWidths=[38 * mm] + [24 * mm] * 5,
        )
        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b3d63")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("ALIGN", (1, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d5e0")),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(summary_table)
        story.append(Spacer(1, 4 * mm))

        patch_status = summary["patch_status"]
        exposure = summary["network_exposure"]
        story.append(
            Paragraph(
                f"Patches installed: {patch_status['installed']} &nbsp;|&nbsp; "
                f"missing: {patch_status['missing']} "
                f"({patch_status['missing_security']} security, evidence: "
                f"{patch_status['evidence_quality']}) &nbsp;|&nbsp; "
                f"listening ports: {exposure['listening_ports']} "
                f"({exposure['network_reachable_ports']} network reachable) "
                f"&nbsp;|&nbsp; vulnerabilities: {summary['vulnerability_count']} "
                f"({summary['kev_vulnerability_count']} in CISA KEV)",
                styles["VSBody"],
            )
        )
        story.append(Spacer(1, 4 * mm))

        if payload["asset"]:
            asset = payload["asset"]
            story.append(Paragraph("Assessed asset", styles["VSHeading"]))
            asset_rows = [
                ["Hostname", asset["hostname"] or "-", "IP address", asset["ip_address"] or "-"],
                ["Operating system", asset["os_name"] or "-", "Build", asset["os_build"] or "-"],
                ["Edition", asset["os_edition"] or "-", "Architecture", asset["architecture"] or "-"],
                ["Domain / workgroup", asset["domain"] or "-", "MAC", asset["mac_address"] or "-"],
            ]
            asset_table = Table(asset_rows, colWidths=[32 * mm, 58 * mm, 30 * mm, 52 * mm])
            asset_table.setStyle(
                TableStyle(
                    [
                        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dbe3ea")),
                        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f2f6f9")),
                        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#f2f6f9")),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ]
                )
            )
            story.append(asset_table)

        # Findings
        story.append(PageBreak())
        story.append(Paragraph("Findings", styles["VSHeading"]))
        story.append(
            Paragraph(
                "The <b>VulScanner risk score</b> reflects this weakness on this "
                "asset (exposure, exploitation intelligence, detection confidence). "
                "Where a CVE is involved, the official CVSS base score is shown "
                "separately.",
                styles["VSSmall"],
            )
        )
        story.append(Spacer(1, 3 * mm))

        for finding in payload["findings"]:
            colour = colors.HexColor(SEVERITY_COLOURS.get(finding["severity"], "#5c7080"))
            header = Table(
                [
                    [
                        Paragraph(
                            f"<b>{finding['severity'].upper()}</b>", styles["VSSmall"]
                        ),
                        Paragraph(f"<b>{finding['title']}</b>", styles["VSBody"]),
                        Paragraph(
                            f"Risk {finding['risk_score']}"
                            + (
                                f" | CVSS {finding['cvss_score']}"
                                if finding["cvss_score"] is not None
                                else ""
                            ),
                            styles["VSSmall"],
                        ),
                    ]
                ],
                colWidths=[22 * mm, 118 * mm, 32 * mm],
            )
            header.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, 0), colour),
                        ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
                        ("BACKGROUND", (1, 0), (-1, 0), colors.HexColor("#f2f6f9")),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )
            body = [
                header,
                Paragraph(
                    f"<b>ID</b> {finding['finding_uid']} &nbsp;|&nbsp; "
                    f"<b>Category</b> {finding['category']} &nbsp;|&nbsp; "
                    f"<b>Confidence</b> {finding['confidence']} &nbsp;|&nbsp; "
                    f"<b>Detection</b> {finding['detection_method']}",
                    styles["VSSmall"],
                ),
                Paragraph(finding["description"], styles["VSBody"]),
                Paragraph(f"<b>Impact.</b> {finding['impact']}", styles["VSBody"]),
                Paragraph(
                    f"<b>Evidence.</b> {finding['evidence_summary']}", styles["VSBody"]
                ),
                Paragraph(
                    f"<b>Remediation.</b> {finding['remediation']}", styles["VSBody"]
                ),
            ]
            if finding["remediation_command"]:
                body.append(
                    Paragraph(
                        f"<font face='Courier' size='7.5'>{finding['remediation_command']}</font>",
                        styles["VSSmall"],
                    )
                )
            body.append(Spacer(1, 4 * mm))
            story.append(KeepTogether(body))

        # Vulnerabilities
        if payload["vulnerabilities"]:
            story.append(PageBreak())
            story.append(Paragraph("Correlated vulnerabilities", styles["VSHeading"]))
            rows = [["CVE / KB", "Product", "Installed", "CVSS", "Risk", "KEV", "Confidence"]]
            for vulnerability in payload["vulnerabilities"]:
                rows.append(
                    [
                        vulnerability["cve_id"],
                        vulnerability["product"][:28],
                        vulnerability["product_version"][:16],
                        vulnerability["cvss_score"] if vulnerability["cvss_score"] is not None else "-",
                        vulnerability["risk_score"],
                        "yes" if vulnerability["kev"] else "no",
                        vulnerability["confidence"],
                    ]
                )
            table = Table(rows, colWidths=[34 * mm, 42 * mm, 24 * mm, 16 * mm, 16 * mm, 14 * mm, 24 * mm])
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b3d63")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dbe3ea")),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ]
                )
            )
            story.append(table)

        # Remediation plan
        story.append(PageBreak())
        story.append(Paragraph("Remediation plan", styles["VSHeading"]))
        story.append(
            Paragraph(
                "VulScanner never applies these changes. Each command is guidance "
                "for an authorized operator to review and execute.",
                styles["VSSmall"],
            )
        )
        story.append(Spacer(1, 3 * mm))
        remediation_rows = [["Priority", "Finding", "Fix within", "Effort", "Reboot"]]
        for item in payload["remediation"]["items"][:40]:
            remediation_rows.append(
                [
                    item["priority"],
                    Paragraph(item["title"], styles["VSSmall"]),
                    f"{item['sla_days']} days" if item["sla_days"] else "-",
                    item["effort"],
                    "yes" if item["requires_reboot"] else "no",
                ]
            )
        remediation_table = Table(
            remediation_rows, colWidths=[16 * mm, 100 * mm, 22 * mm, 18 * mm, 16 * mm]
        )
        remediation_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b3d63")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dbe3ea")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        story.append(remediation_table)

        # Methodology
        story.append(Spacer(1, 6 * mm))
        story.append(Paragraph("Methodology and limitations", styles["VSHeading"]))
        for key, text in payload["methodology"].items():
            story.append(
                Paragraph(f"<b>{key.replace('_', ' ').title()}.</b> {text}", styles["VSBody"])
            )

        def footer(canvas, doc) -> None:
            canvas.saveState()
            canvas.setFont("Helvetica", 7)
            canvas.setFillColor(colors.HexColor("#5c7080"))
            canvas.drawString(
                15 * mm, 10 * mm,
                f"VulScanner {meta['scanner_version']} | Scan #{meta['scan_id']} | "
                f"{meta['target']} | Authorized defensive assessment",
            )
            canvas.drawRightString(195 * mm, 10 * mm, f"Page {doc.page}")
            canvas.restoreState()

        destination.parent.mkdir(parents=True, exist_ok=True)
        document = SimpleDocTemplate(
            str(destination),
            pagesize=A4,
            leftMargin=15 * mm,
            rightMargin=15 * mm,
            topMargin=15 * mm,
            bottomMargin=18 * mm,
            title=f"VulScanner Security Assessment Report - Scan {meta['scan_id']}",
            author="VulScanner",
        )
        document.build(story, onFirstPage=footer, onLaterPages=footer)
        return destination

    # -- top level ---------------------------------------------------------
    def generate(
        self, db: Session, scan_id: int, fmt: str = "html"
    ) -> tuple[Path, dict]:
        """Generate a report file and return its path plus a summary."""
        fmt = fmt.lower()
        payload = self.build_payload(db, scan_id)
        stamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d-%H%M%S")
        filename = f"vulscanner-scan-{scan_id}-{stamp}.{fmt}"
        destination = self.output_dir / filename

        if fmt == "html":
            destination.write_text(self.render_html(payload), encoding="utf-8")
        elif fmt == "json":
            destination.write_text(self.render_json(payload), encoding="utf-8")
        elif fmt == "csv":
            destination.write_text(self.render_csv(payload), encoding="utf-8")
        elif fmt == "pdf":
            self.render_pdf(payload, destination)
        else:
            raise ValueError(f"Unsupported report format: {fmt}")

        summary = {
            "scan_id": scan_id,
            "format": fmt,
            "security_score": payload["executive_summary"]["security_score"],
            "severity_counts": payload["executive_summary"]["severity_counts"],
            "total_findings": payload["executive_summary"]["total_findings"],
            "vulnerability_count": payload["executive_summary"]["vulnerability_count"],
        }
        logger.info("Generated %s report for scan %s at %s", fmt, scan_id, destination)
        return destination, summary


report_service = ReportService()
