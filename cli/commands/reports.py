"""``vulscanner report`` and ``vulscanner reports`` - report generation."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import desc, select

from app.db.init_db import init_db
from app.db.session import SessionLocal
from app.models.report import Report
from app.models.scan import Scan
from app.services.report_service import report_service
from cli.output import Console


def register(subparsers: argparse._SubParsersAction, common: argparse.ArgumentParser) -> None:
    report = subparsers.add_parser(
        "report",
        parents=[common],
        help="Generate a VulScanner Security Assessment Report for a scan.",
    )
    report.add_argument("--scan-id", type=int, help="Scan to report on (default: latest).")
    report.add_argument(
        "--format", choices=["html", "pdf", "json", "csv"],
        help="Report format. Equivalent to --html/--pdf/--json/--csv.",
    )
    report.add_argument("--open", action="store_true", help="Open the report when done.")
    report.set_defaults(handler=handle_report)

    reports = subparsers.add_parser(
        "reports", parents=[common], help="Manage generated reports."
    )
    report_subparsers = reports.add_subparsers(dest="reports_command", metavar="<action>")

    listing = report_subparsers.add_parser(
        "list", parents=[common], help="List generated reports."
    )
    listing.add_argument("--scan-id", type=int)
    listing.set_defaults(handler=handle_list)

    scans = report_subparsers.add_parser(
        "scans", parents=[common], help="List scans available for reporting."
    )
    scans.set_defaults(handler=handle_scans)

    reports.set_defaults(handler=lambda args, console: _help(reports, console))


def _help(parser: argparse.ArgumentParser, console: Console) -> int:
    parser.print_help()
    return 1


def handle_report(args: argparse.Namespace, console: Console) -> int:
    init_db()
    db = SessionLocal()

    scan_id = args.scan_id
    if scan_id is None:
        latest = db.scalar(select(Scan).order_by(desc(Scan.created_at)).limit(1))
        if latest is None:
            console.error("No scans found. Run 'vulscanner scan local' first.")
            return 1
        scan_id = latest.id
        console.info(f"No --scan-id supplied; using the most recent scan #{scan_id}.")

    scan = db.get(Scan, scan_id)
    if scan is None:
        console.error(f"Scan #{scan_id} not found.")
        return 1
    if scan.status in ("queued", "running"):
        console.error(f"Scan #{scan_id} is still {scan.status}.")
        return 1

    fmt = (
        args.format
        or ("pdf" if args.pdf else None)
        or ("json" if args.json else None)
        or ("csv" if args.csv else None)
        or ("html" if args.html else None)
        or "html"
    )

    console.header(f"Generating {fmt.upper()} report for scan #{scan_id}")
    path, summary = report_service.generate(db, scan_id, fmt)

    if args.output:
        destination = Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(path.read_bytes())
        path = destination

    record = Report(
        title="VulScanner Security Assessment Report",
        format=fmt,
        status="ready",
        file_path=str(path),
        file_name=path.name,
        size_bytes=path.stat().st_size,
        scan_id=scan_id,
        generated_at=datetime.now(tz=timezone.utc),
        summary=summary,
    )
    db.add(record)
    db.commit()

    console.success(f"Report written to {path}")
    console.key_values(
        [
            ("Format", fmt.upper()),
            ("Size", f"{path.stat().st_size:,} bytes"),
            ("Security score", f"{summary['security_score']}/100"),
            ("Findings", summary["total_findings"]),
            ("Vulnerabilities", summary["vulnerability_count"]),
            (
                "Severity",
                ", ".join(
                    f"{level}: {count}"
                    for level, count in summary["severity_counts"].items()
                    if count
                )
                or "none",
            ),
        ]
    )

    if args.open:
        import webbrowser

        webbrowser.open(path.resolve().as_uri())
    return 0


def handle_list(args: argparse.Namespace, console: Console) -> int:
    init_db()
    db = SessionLocal()
    query = select(Report).order_by(desc(Report.created_at))
    if args.scan_id:
        query = query.where(Report.scan_id == args.scan_id)
    reports = list(db.scalars(query.limit(200)).all())

    console.header(f"Generated reports ({len(reports)})")
    console.table(
        ["ID", "Scan", "Format", "Status", "Size", "Generated", "File"],
        [
            [
                report.id, f"#{report.scan_id}", report.format.upper(), report.status,
                f"{report.size_bytes:,}",
                report.generated_at.strftime("%Y-%m-%d %H:%M") if report.generated_at else "-",
                report.file_name,
            ]
            for report in reports
        ],
        max_widths=[5, 7, 7, 10, 12, 18, 46],
    )
    if not reports:
        console.info("No reports yet. Generate one with: vulscanner report --scan-id <ID>")
    return 0


def handle_scans(args: argparse.Namespace, console: Console) -> int:
    init_db()
    db = SessionLocal()
    scans = list(db.scalars(select(Scan).order_by(desc(Scan.created_at)).limit(100)).all())

    console.header(f"Scans ({len(scans)})")
    console.table(
        ["ID", "Target", "Profile", "Status", "Score", "C", "H", "M", "L", "Finished"],
        [
            [
                scan.id, scan.target, scan.profile, scan.status,
                scan.security_score if scan.security_score is not None else "-",
                scan.critical_count, scan.high_count, scan.medium_count, scan.low_count,
                scan.finished_at.strftime("%Y-%m-%d %H:%M") if scan.finished_at else "-",
            ]
            for scan in scans
        ],
        max_widths=[5, 26, 11, 10, 6, 3, 3, 3, 3, 18],
    )
    return 0
