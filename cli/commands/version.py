"""``vulscanner version`` - build, environment and capability information."""

from __future__ import annotations

import argparse
import json
import platform
import sys

from cli.output import Console


def register(subparsers: argparse._SubParsersAction, common: argparse.ArgumentParser) -> None:
    parser = subparsers.add_parser(
        "version", parents=[common], help="Show version and environment capability."
    )
    parser.set_defaults(handler=handle)


def handle(args: argparse.Namespace, console: Console) -> int:
    from app.core.config import APP_VERSION, settings
    from app.scanner.network.oui import registry_size
    from app.scanner.registry import COLLECTORS
    from app.scanner.runner import find_powershell
    from app.services.cve_service import cve_service

    shell = find_powershell()
    elevated = _is_elevated()

    payload = {
        "product": "VulScanner",
        "version": APP_VERSION,
        "python": sys.version.split()[0],
        "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "windows_collection_available": platform.system() == "Windows" and bool(shell),
        "powershell": shell or "not found",
        "elevated": elevated,
        "collectors": len(COLLECTORS),
        "database": settings.database_url.split("://")[0],
        "authorized_scopes": settings.authorized_scopes,
        "oui_entries": registry_size(),
    }

    if args.json:
        console.always(json.dumps(payload | {"intelligence": cve_service.status()}, indent=2))
        return 0

    console.banner(APP_VERSION)
    console.key_values(
        [
            ("Version", f"VulScanner {payload['version']}"),
            ("Python", payload["python"]),
            ("Platform", payload["platform"]),
            ("PowerShell", payload["powershell"]),
            (
                "Windows collection",
                "available" if payload["windows_collection_available"] else "unavailable",
            ),
            (
                "Privileges",
                "administrator" if elevated
                else "standard user (some collectors will be partial)",
            ),
            ("Collectors registered", payload["collectors"]),
            ("Database", payload["database"]),
            ("MAC vendor entries", f"{payload['oui_entries']:,}"),
            ("Authorized scopes", ", ".join(payload["authorized_scopes"]) or "(none)"),
        ]
    )

    if console.verbose:
        console.header("Vulnerability intelligence")
        status = cve_service.status()
        console.key_values(
            [
                ("Online lookups", "enabled" if status["online"] else "disabled"),
                ("NVD API key", "configured" if status["nvd_api_key_configured"] else "not set"),
                ("CISA KEV entries", f"{status['kev_entries']:,}"),
                ("Cache directory", status["cache_directory"]),
                ("Cache TTL", f"{status['cache_ttl_hours']}h"),
            ]
        )

    console.write("")
    console.info(
        console.paint(
            "VulScanner performs authorized, read-only defensive assessment. It "
            "executes no exploits, collects no credentials and applies no changes.",
            "grey",
        )
    )
    return 0


def _is_elevated() -> bool:
    if platform.system() != "Windows":
        try:
            import os

            return os.geteuid() == 0  # type: ignore[attr-defined]
        except AttributeError:
            return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False
