#!/usr/bin/env python
"""VulScanner command-line interface.

    vulscanner --help
    vulscanner scan local --profile full
    vulscanner network discover --scope 192.168.1.0/24

The CLI drives the same scanning engine and services as the web application, so
results are identical regardless of the interface used.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running directly from a source checkout without installation.
_REPO_ROOT = Path(__file__).resolve().parents[1]
_BACKEND = _REPO_ROOT / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from cli.commands import findings as findings_cmd  # noqa: E402
from cli.commands import network as network_cmd  # noqa: E402
from cli.commands import reports as reports_cmd  # noqa: E402
from cli.commands import scan as scan_cmd  # noqa: E402
from cli.commands import version as version_cmd  # noqa: E402
from cli.output import Console  # noqa: E402

PROGRAM = "vulscanner"

EPILOG = """
examples:
  vulscanner scan local                         quick posture check of this machine
  vulscanner scan local --profile full          full security audit
  vulscanner scan --target 192.168.1.25 --profile standard
  vulscanner network discover --scope 192.168.1.0/24
  vulscanner findings --severity high
  vulscanner report --scan-id 12 --pdf
  vulscanner reports list

VulScanner assesses only targets inside the configured authorized scope
(VULSCANNER_AUTHORIZED_SCOPES). It performs no exploitation, collects no
credentials and applies no remediation.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description=(
            "VulScanner - agent-less Windows vulnerability, security posture and "
            "network assessment platform. Authorized defensive use only."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Global output options apply to every subcommand.
    common = argparse.ArgumentParser(add_help=False)
    output = common.add_argument_group("output options")
    output.add_argument("--output", "-o", metavar="PATH", help="Write output to a file.")
    output.add_argument("--json", action="store_true", help="Emit JSON.")
    output.add_argument("--csv", action="store_true", help="Emit CSV.")
    output.add_argument("--html", action="store_true", help="Emit HTML.")
    output.add_argument("--pdf", action="store_true", help="Emit PDF.")
    output.add_argument("--quiet", "-q", action="store_true", help="Suppress progress output.")
    output.add_argument("--verbose", "-v", action="store_true", help="Show detailed output.")
    output.add_argument("--no-colour", "--no-color", dest="no_colour", action="store_true",
                        help="Disable ANSI colour.")

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    scan_cmd.register(subparsers, common)
    network_cmd.register(subparsers, common)
    findings_cmd.register(subparsers, common)
    reports_cmd.register(subparsers, common)
    version_cmd.register(subparsers, common)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return 0

    console = Console(
        quiet=getattr(args, "quiet", False),
        verbose=getattr(args, "verbose", False),
        colour=not getattr(args, "no_colour", False),
    )

    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 1

    try:
        return handler(args, console)
    except KeyboardInterrupt:
        console.warn("\nInterrupted by user.")
        return 130
    except PermissionError as exc:
        console.error(str(exc))
        return 3
    except Exception as exc:  # top-level guard so the CLI never dumps a traceback
        console.error(f"{type(exc).__name__}: {exc}")
        if getattr(args, "verbose", False):
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
