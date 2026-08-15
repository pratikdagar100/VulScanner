"""``vulscanner scan`` - run an assessment against an authorized target."""

from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path

from app.core.permissions import AuthorizationError
from app.db.init_db import init_db
from app.db.session import SessionLocal
from app.models.finding import Finding
from app.scanner.runner import RemoteCredential
from app.services.report_service import report_service
from app.services.scan_service import SCAN_STAGES, scan_service
from cli.output import Console

PROFILES = ["quick", "standard", "full", "network", "compliance", "custom"]


def register(subparsers: argparse._SubParsersAction, common: argparse.ArgumentParser) -> None:
    parser = subparsers.add_parser(
        "scan",
        parents=[common],
        help="Assess this machine, an authorized host or an authorized network.",
        description=(
            "Run a VulScanner assessment. The target must be inside the configured "
            "authorized scope or registered as an authorized target."
        ),
    )
    parser.add_argument(
        "target_positional",
        nargs="?",
        metavar="TARGET",
        help="Target to assess. Use 'local' for this machine.",
    )
    parser.add_argument("--target", "-t", help="Target IP, hostname or CIDR.")
    parser.add_argument(
        "--profile", "-p", choices=PROFILES, default="standard",
        help="Scan profile (default: standard).",
    )
    parser.add_argument("--name", help="Friendly name for this scan.")
    parser.add_argument(
        "--ports", help="Port range for discovery, e.g. '22,80,443,8000-8100'."
    )
    parser.add_argument(
        "--discover", action="store_true",
        help="Also discover other hosts on the locally attached subnet.",
    )
    parser.add_argument("--scope", help="Explicit discovery scope (CIDR).")
    parser.add_argument(
        "--no-cve", action="store_true", help="Skip CVE correlation (offline mode)."
    )
    parser.add_argument(
        "--banner", action="store_true",
        help="Read service banners during discovery.",
    )
    parser.add_argument(
        "--include", metavar="COLLECTORS",
        help="Comma separated collectors to add to the profile.",
    )
    parser.add_argument(
        "--exclude", metavar="COLLECTORS",
        help="Comma separated collectors to skip.",
    )
    parser.add_argument(
        "--username", help="Username for an authorized remote (WinRM) assessment."
    )
    parser.add_argument(
        "--ask-password", action="store_true",
        help="Prompt for the remote password (never accepted as an argument).",
    )
    parser.add_argument(
        "--report", choices=["html", "pdf", "json", "csv"],
        help="Generate a report when the scan finishes.",
    )
    parser.set_defaults(handler=handle)


def handle(args: argparse.Namespace, console: Console) -> int:
    from app.core.config import APP_VERSION

    target = args.target or args.target_positional or "local"
    console.banner(APP_VERSION)

    credential = None
    if args.username:
        if not args.ask_password:
            console.error(
                "A remote assessment needs a password. Re-run with --ask-password; "
                "VulScanner never accepts a password as a command-line argument."
            )
            return 2
        password = getpass.getpass(f"Password for {args.username}: ")
        credential = RemoteCredential(username=args.username, password=password)

    options = {
        "network_discovery": bool(args.discover or args.scope),
        "discovery_scope": args.scope,
        "ports": args.ports,
        "banner_grab": bool(args.banner),
        "vulnerability_correlation": not args.no_cve,
        "include_collectors": _split(args.include),
        "exclude_collectors": _split(args.exclude),
    }
    options = {key: value for key, value in options.items() if value not in (None, [])}

    init_db()
    db = SessionLocal()

    stage_state = {stage["key"]: "pending" for stage in SCAN_STAGES}

    def on_progress(stage: str, percent: float, message: str) -> None:
        if stage in stage_state:
            for key in stage_state:
                if key == stage:
                    stage_state[key] = "running"
                    break
                stage_state[key] = "done"
        console.progress(percent, stage, message)

    console.header(f"VulScanner scan of {target}")
    console.key_values(
        [
            ("Target", target),
            ("Profile", args.profile),
            ("CVE correlation", "disabled" if args.no_cve else "enabled"),
            ("Discovery", options.get("discovery_scope") or ("enabled" if args.discover else "disabled")),
            ("Remote", args.username or "local collection"),
        ]
    )
    console.write("")

    try:
        scan = scan_service.run_sync(
            db,
            name=args.name or f"{args.profile.title()} scan of {target}",
            target=target,
            profile=args.profile,
            options=options,
            credential=credential,
            actor_name="cli",
            progress_callback=on_progress,
        )
    except AuthorizationError as exc:
        console.end_progress()
        console.error(str(exc))
        console.info(
            "Add the target to VULSCANNER_AUTHORIZED_SCOPES in .env, or register it "
            "as an authorized target, before scanning."
        )
        return 3

    console.end_progress()
    return _render(db, scan, args, console)


def _render(db, scan, args: argparse.Namespace, console: Console) -> int:
    from sqlalchemy import select

    findings = list(
        db.scalars(
            select(Finding).where(Finding.scan_id == scan.id).order_by(
                Finding.risk_score.desc()
            )
        ).all()
    )

    machine_readable = args.json or args.csv or args.html or args.pdf
    fmt = (
        "json" if args.json else "csv" if args.csv
        else "html" if args.html else "pdf" if args.pdf else None
    )

    if machine_readable or args.report:
        report_format = args.report or fmt
        path, summary = report_service.generate(db, scan.id, report_format)
        if args.output:
            destination = Path(args.output)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(path.read_bytes())
            path = destination
        if fmt in ("json", "csv") and not args.output:
            # Machine-readable output goes to stdout so it can be piped.
            console.always(path.read_text(encoding="utf-8"))
        else:
            console.success(f"Report written to {path}")
        if machine_readable and fmt in ("json", "csv"):
            return _exit_code(scan)

    console.header("Scan summary")
    console.key_values(
        [
            ("Scan ID", f"#{scan.id}"),
            ("Status", scan.status),
            ("Duration", f"{scan.duration_seconds:.1f}s" if scan.duration_seconds else "-"),
            ("Security score", f"{scan.security_score}/100"),
            ("Highest risk score", scan.risk_score),
            ("Findings", len(findings)),
            ("Vulnerabilities", scan.vulnerability_count),
            ("Scanner", f"VulScanner {scan.scanner_version}"),
        ]
    )

    counts = [
        ("Critical", scan.critical_count, "critical"),
        ("High", scan.high_count, "high"),
        ("Medium", scan.medium_count, "medium"),
        ("Low", scan.low_count, "low"),
        ("Informational", scan.info_count, "informational"),
    ]
    console.write("")
    for label, count, level in counts:
        bar = console.glyphs["bar"] * min(count, 40)
        console.write(
            f"  {console.severity(level)} {str(count).rjust(3)}  "
            f"{console.paint(bar, 'grey')}"
        )

    if findings:
        console.header("Findings")
        for finding in findings:
            console.write(
                f"  {console.severity(finding.severity)}"
                f"{console.paint(str(finding.risk_score).rjust(5), 'bold')}  "
                f"{finding.finding_uid}  {finding.title}"
            )
            if console.verbose:
                console.detail(finding.evidence_summary)
                console.detail(f"Fix: {finding.remediation}")

    if scan.warnings:
        console.header("Collection warnings")
        for warning in scan.warnings[:15]:
            console.warn(warning)
    if scan.errors:
        console.header("Collector errors")
        for error in scan.errors[:15]:
            console.error(error)

    console.write("")
    console.info(
        console.paint(
            f"Full detail: vulscanner report --scan-id {scan.id} --html", "grey"
        )
    )
    return _exit_code(scan)


def _exit_code(scan) -> int:
    """Non-zero when critical or high findings exist, so CI can gate on it."""
    if scan.status in ("failed",):
        return 1
    if scan.critical_count:
        return 2
    return 0


def _split(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [part.strip() for part in value.split(",") if part.strip()]
