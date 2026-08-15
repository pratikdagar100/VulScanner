"""PowerShell console history secret-exposure analysis.

The collector reports *that* a credential-shaped value was found, where, and on
which line. The value itself is redacted at the point of detection and never
stored, logged or included in a report.
"""

from __future__ import annotations

import hashlib
import re

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import dicts, get, integer, iso, text

SCRIPT = r"""
$files = @()
$roots = @(
  (Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine'),
  (Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell')
)
foreach ($root in $roots) {
  if (Test-Path -LiteralPath $root) {
    Get-ChildItem -LiteralPath $root -Filter '*history*.txt' -File -ErrorAction SilentlyContinue |
      ForEach-Object {
        $lines = @()
        try { $lines = Get-Content -LiteralPath $_.FullName -Tail __TAIL__ -ErrorAction Stop } catch {}
        $files += [pscustomobject]@{
          Path=$_.FullName; Size=$_.Length; Modified=$_.LastWriteTimeUtc
          LineCount=$lines.Count; Lines=$lines
        }
      }
  }
}
,@($files)
"""

# Each pattern captures the secret in group 1 so it can be redacted immediately.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "plaintext-password-parameter",
        re.compile(r"(?i)-(?:password|pwd)\s+(?:'([^']+)'|\"([^\"]+)\"|(\S+))"),
        "A password was supplied as a plaintext command-line parameter.",
    ),
    (
        "convertto-securestring-plaintext",
        re.compile(
            r"(?i)ConvertTo-SecureString\s+(?:'([^']+)'|\"([^\"]+)\"|(\S+))[^\n]*-AsPlainText"
        ),
        "A plaintext string was converted to a SecureString, exposing the secret in history.",
    ),
    (
        "api-key-assignment",
        re.compile(
            r"(?i)\$?\w*(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key)\w*\s*=\s*"
            r"(?:'([^']+)'|\"([^\"]+)\"|(\S+))"
        ),
        "An API or access key was assigned in the shell.",
    ),
    (
        "bearer-token",
        re.compile(r"(?i)(?:bearer|authorization:\s*bearer)\s+([A-Za-z0-9._\-]{20,})"),
        "A bearer token appears in the command history.",
    ),
    (
        "connection-string",
        re.compile(
            r"(?i)((?:server|data source|host)=[^;\s]+;[^\n]*?(?:password|pwd)=[^;\s]+)"
        ),
        "A database connection string containing credentials was used.",
    ),
    (
        "url-embedded-credentials",
        re.compile(r"(?i)[a-z][a-z0-9+.-]*://[^\s:@/]+:([^\s@/]+)@"),
        "A URL embedding a username and password was used.",
    ),
    (
        "private-key-material",
        re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----)"),
        "Private key material appears in the command history.",
    ),
    (
        "aws-access-key",
        re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
        "An AWS access key identifier appears in the command history.",
    ),
    (
        "github-token",
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,})\b"),
        "A GitHub token appears in the command history.",
    ),
    (
        "net-user-password",
        re.compile(r"(?i)net\s+user\s+\S+\s+(?!/)(\S+)"),
        "A local account password was set on the command line.",
    ),
]

# Commands worth flagging for review even though they carry no secret.
RISKY_COMMAND_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "execution-policy-bypass",
        re.compile(r"(?i)-ExecutionPolicy\s+(Bypass|Unrestricted)"),
        "PowerShell execution policy was bypassed.",
    ),
    (
        "encoded-command",
        re.compile(r"(?i)-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}"),
        "A base64 encoded command was executed.",
    ),
    (
        "download-and-execute",
        re.compile(
            r"(?i)(iex|invoke-expression)[^\n]{0,80}(downloadstring|invoke-webrequest|iwr|curl|wget)"
        ),
        "Remote content was downloaded and executed in one statement.",
    ),
    (
        "defender-exclusion-added",
        re.compile(r"(?i)Add-MpPreference\s+-Exclusion"),
        "A Microsoft Defender exclusion was added from the shell.",
    ),
    (
        "firewall-disabled",
        re.compile(r"(?i)Set-NetFirewallProfile[^\n]*-Enabled\s+False"),
        "A firewall profile was disabled from the shell.",
    ),
]

REDACTED = "[REDACTED]"


def redact_line(line: str, matches: list[re.Match[str]]) -> str:
    """Blank out every captured secret in ``line``."""
    redacted = line
    for match in matches:
        for group in match.groups():
            if group and len(group) >= 3:
                redacted = redacted.replace(group, REDACTED)
    return redacted


def fingerprint(value: str) -> str:
    """Stable, non-reversible identifier so repeat findings can be deduplicated."""
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:16]


class PowerShellHistoryCollector(BaseCollector):
    name = "powershell_history"
    category = "windows"
    description = "PowerShell history analysis for exposed credentials (values redacted)"
    profiles = ("standard", "full")

    def collect(self, result: CollectorResult) -> None:
        tail = int(self.context.option("history_tail_lines", 5000))
        records, ps = self.context.runner.run_list(
            SCRIPT.replace("__TAIL__", str(tail)), depth=4
        )
        result.collection_method = self.context.runner.describe_method(
            "PSReadLine ConsoleHost_history.txt (pattern analysis only; matched "
            "values are redacted before storage)"
        )
        if not ps.ok:
            result.fail(ps.friendly_error())
            return

        files_meta: list[dict] = []
        secret_findings: list[dict] = []
        risky_findings: list[dict] = []
        total_lines = 0

        for record in dicts(records):
            path = text(get(record, "Path"))
            lines = [text(line) for line in (get(record, "Lines") or [])]
            total_lines += len(lines)
            files_meta.append(
                {
                    "path": path,
                    "size_bytes": integer(get(record, "Size"), 0),
                    "modified": iso(get(record, "Modified")),
                    "lines_analyzed": len(lines),
                }
            )

            for index, line in enumerate(lines, start=1):
                if not line.strip():
                    continue
                matched: list[re.Match[str]] = []
                kinds: list[tuple[str, str]] = []
                for kind, pattern, explanation in SECRET_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        matched.append(match)
                        kinds.append((kind, explanation))
                if matched:
                    safe_line = redact_line(line, matched)
                    for kind, explanation in kinds:
                        secret_findings.append(
                            {
                                "type": kind,
                                "explanation": explanation,
                                "file": path,
                                "line_number": index,
                                # Redacted command retained for context only.
                                "redacted_line": safe_line[:300],
                                "fingerprint": fingerprint(f"{kind}:{path}:{index}"),
                            }
                        )

                for kind, pattern, explanation in RISKY_COMMAND_PATTERNS:
                    if pattern.search(line):
                        risky_findings.append(
                            {
                                "type": kind,
                                "explanation": explanation,
                                "file": path,
                                "line_number": index,
                                "redacted_line": redact_line(line, matched)[:300],
                            }
                        )

        result.data = {
            "history_files": files_meta,
            "history_file_count": len(files_meta),
            "lines_analyzed": total_lines,
            "secret_exposures": secret_findings,
            "secret_exposure_count": len(secret_findings),
            "secret_types": sorted({f["type"] for f in secret_findings}),
            "risky_commands": risky_findings,
            "risky_command_count": len(risky_findings),
            "redaction_note": (
                "All matched credential values were replaced with [REDACTED] at "
                "detection time. VulScanner never stores or displays the secret."
            ),
        }

        if not files_meta:
            result.warn(
                "No PowerShell history files were found for the scanning user "
                "context. History is per-user, so other users' history is not read."
            )
