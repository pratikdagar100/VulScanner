"""``vulscanner findings`` - review stored findings and remediation guidance."""

from __future__ import annotations

import argparse
import csv
import io
import json
from pathlib import Path

from sqlalchemy import desc, select

from app.db.init_db import init_db
from app.db.session import SessionLocal
from app.models.finding import Finding, FindingStatus
from app.services.remediation_service import remediation_service
from app.services.report_service import report_service
from cli.output import Console

SEVERITIES = ["critical", "high", "medium", "low", "informational"]


def register(subparsers: argparse._SubParsersAction, common: argparse.ArgumentParser) -> None:
    parser = subparsers.add_parser(
        "findings", parents=[common], help="List and filter stored findings."
    )
    parser.add_argument("--scan-id", type=int, help="Restrict to one scan.")
    parser.add_argument("--asset-id", type=int, help="Restrict to one asset.")
    parser.add_argument("--severity", choices=SEVERITIES, help="Filter by severity.")
    parser.add_argument("--category", help="Filter by finding category.")
    parser.add_argument(
        "--status", choices=[s.value for s in FindingStatus], help="Filter by status."
    )
    parser.add_argument("--search", help="Match text in the title or description.")
    parser.add_argument("--limit", type=int, default=100, help="Maximum rows (default 100).")
    parser.add_argument("--detail", action="store_true", help="Show full finding detail.")
    parser.add_argument(
        "--remediation", action="store_true",
        help="Show the ordered remediation plan instead of the finding list.",
    )
    parser.set_defaults(handler=handle)


def handle(args: argparse.Namespace, console: Console) -> int:
    init_db()
    db = SessionLocal()

    query = select(Finding)
    if args.scan_id:
        query = query.where(Finding.scan_id == args.scan_id)
    if args.asset_id:
        query = query.where(Finding.asset_id == args.asset_id)
    if args.severity:
        query = query.where(Finding.severity == args.severity)
    if args.category:
        query = query.where(Finding.category == args.category)
    if args.status:
        query = query.where(Finding.status == args.status)
    if args.search:
        pattern = f"%{args.search}%"
        query = query.where(
            Finding.title.ilike(pattern) | Finding.description.ilike(pattern)
        )

    findings = list(
        db.scalars(query.order_by(desc(Finding.risk_score)).limit(args.limit)).all()
    )
    findings.sort(key=lambda f: (SEVERITIES.index(f.severity) if f.severity in SEVERITIES else 9,
                                 -f.risk_score))

    records = [report_service._finding_dict(finding) for finding in findings]

    if args.remediation:
        return _render_remediation(records, args, console)

    if args.json:
        _emit(json.dumps(records, indent=2, default=str), args, console)
        return 0
    if args.csv:
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(
            ["finding_id", "rule_id", "severity", "vulscanner_risk_score",
             "official_cvss", "category", "confidence", "status", "title",
             "evidence_summary", "remediation"]
        )
        for record in records:
            writer.writerow(
                [record["finding_uid"], record["rule_id"], record["severity"],
                 record["risk_score"],
                 record["cvss_score"] if record["cvss_score"] is not None else "",
                 record["category"], record["confidence"], record["status"],
                 record["title"], record["evidence_summary"], record["remediation"]]
            )
        _emit(buffer.getvalue(), args, console)
        return 0

    console.header(f"Findings ({len(findings)})")
    if not findings:
        console.info("No findings match the filter. Run a scan first if the database is empty.")
        return 0

    if args.detail:
        for record in records:
            console.write("")
            console.write(
                f"  {console.severity(record['severity'])}"
                f"{console.paint(str(record['risk_score']).rjust(5), 'bold')}  "
                f"{record['title']}"
            )
            console.key_values(
                [
                    ("ID", record["finding_uid"]),
                    ("Rule", record["rule_id"]),
                    ("Category", record["category"]),
                    ("Confidence", record["confidence"]),
                    ("Official CVSS", record["cvss_score"] if record["cvss_score"] is not None else "n/a"),
                    ("Status", record["status"]),
                    ("Detection", record["detection_method"]),
                    ("Evidence", record["evidence_summary"]),
                    ("Impact", record["impact"]),
                    ("Remediation", record["remediation"]),
                ],
                indent="      ",
            )
            if record["remediation_command"]:
                console.write(
                    f"      {console.paint('$ ' + record['remediation_command'], 'cyan')}"
                )
    else:
        console.table(
            ["Severity", "Risk", "CVSS", "ID", "Category", "Title"],
            [
                [
                    record["severity"], record["risk_score"],
                    record["cvss_score"] if record["cvss_score"] is not None else "-",
                    record["finding_uid"], record["category"], record["title"],
                ]
                for record in records
            ],
            max_widths=[14, 6, 6, 22, 16, 62],
        )

    counts = {level: sum(1 for r in records if r["severity"] == level) for level in SEVERITIES}
    console.write("")
    console.info(
        "  ".join(
            f"{console.severity(level).strip()}: {counts[level]}"
            for level in SEVERITIES
            if counts[level]
        )
        or "No findings."
    )
    return 0


def _render_remediation(records: list[dict], args: argparse.Namespace, console: Console) -> int:
    items = remediation_service.build_plan(records)
    summary = remediation_service.summarize_plan(items)

    if args.json:
        _emit(
            json.dumps(
                {"items": [item.to_dict() for item in items], "summary": summary},
                indent=2,
                default=str,
            ),
            args,
            console,
        )
        return 0

    console.header(f"Remediation plan ({len(items)} items)")
    console.info(console.paint(summary["policy"], "grey"))
    console.write("")

    for item in items:
        data = item.to_dict()
        console.write(
            f"  {console.paint('P' + str(data['priority']), 'bold')} "
            f"{console.severity(data['severity'])} {data['title']}"
        )
        console.key_values(
            [
                ("What is wrong", data["what_is_wrong"][:300]),
                ("Why it matters", data["why_it_matters"][:300]),
                ("Recommended fix", data["recommended_fix"][:300]),
                ("Patch / KB", data["patch_reference"] or "n/a"),
                ("Verification", data["verification"]),
                ("Fix within", f"{data['sla_days']} days" if data["sla_days"] else "n/a"),
                ("Effort", data["effort"]),
                ("Requires reboot", "yes" if data["requires_reboot"] else "no"),
            ],
            indent="      ",
        )
        if data["command"]:
            console.write(f"      {console.paint('$ ' + data['command'], 'cyan')}")
        console.write("")

    return 0


def _emit(content: str, args: argparse.Namespace, console: Console) -> None:
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        console.success(f"Written to {path}")
    else:
        console.always(content)
