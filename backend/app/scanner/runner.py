"""PowerShell / CIM execution layer.

All Windows data collection funnels through :class:`PowerShellRunner`, which

* executes read-only PowerShell against the local machine, or a remote,
  explicitly authorized host over WinRM (``Invoke-Command``);
* passes scripts as base64 ``-EncodedCommand`` so quoting can never break;
* forces JSON output and parses it into Python structures;
* never places credentials on a command line - a remote password is handed to
  the child process through its environment block only.

The runner is deliberately incapable of running arbitrary operator-supplied
strings from the API: scripts come from VulScanner's own collector modules and
the bundled ``backend/powershell`` library.
"""

from __future__ import annotations

import base64
import json
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

IS_WINDOWS = platform.system() == "Windows"

_JSON_PREAMBLE = (
    "$ProgressPreference='SilentlyContinue';"
    "$ErrorActionPreference='Stop';"
    "$WarningPreference='SilentlyContinue';"
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
)

# Marker framing lets us discard any stray host output that precedes the JSON.
_BEGIN = "<<<VULSCANNER-JSON>>>"
_END = "<<<END-VULSCANNER-JSON>>>"


class PowerShellUnavailable(RuntimeError):
    """Raised when no PowerShell host can be located."""


@dataclass(slots=True)
class RemoteCredential:
    """Credentials for an authorized remote assessment.

    Held in memory for the duration of a single scan and never persisted,
    logged or included in a report.
    """

    username: str
    password: str = field(repr=False, default="")
    auth: str = "negotiate"  # negotiate | kerberos | credssp
    port: int | None = None
    use_ssl: bool = False

    def __str__(self) -> str:  # pragma: no cover - keeps secrets out of logs
        return f"RemoteCredential(username={self.username!r}, password=[REDACTED])"


@dataclass(slots=True)
class PSResult:
    ok: bool
    data: Any = None
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: str = ""

    @property
    def is_permission_error(self) -> bool:
        text = f"{self.stderr} {self.error}".lower()
        return any(
            token in text
            for token in (
                "access is denied",
                "accessdenied",
                "unauthorizedaccess",
                "requires elevation",
                "administrator privilege",
                "privilege not held",
            )
        )

    @property
    def is_not_found(self) -> bool:
        text = f"{self.stderr} {self.error}".lower()
        return any(
            token in text
            for token in (
                "is not recognized as the name of a cmdlet",
                "commandnotfoundexception",
                "cannot find path",
                "objectnotfound",
                "does not exist",
            )
        )

    def friendly_error(self) -> str:
        if self.error:
            return self.error
        stderr = (self.stderr or "").strip()
        if not stderr:
            return f"PowerShell exited with code {self.returncode}"
        # Collapse multi-line PowerShell error records to the first useful line.
        for line in stderr.splitlines():
            line = line.strip()
            if line and not line.startswith("+"):
                return line[:400]
        return stderr[:400]


@lru_cache(maxsize=1)
def find_powershell() -> str | None:
    """Locate a PowerShell host, preferring Windows PowerShell 5.1."""
    candidates = ["powershell.exe", "powershell", "pwsh.exe", "pwsh"]
    if not IS_WINDOWS:
        candidates = ["pwsh"]
    for candidate in candidates:
        path = shutil.which(candidate)
        if path:
            return path
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    fallback = Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    return str(fallback) if fallback.exists() else None


def _encode_command(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def _extract_json_block(stdout: str) -> str:
    start = stdout.find(_BEGIN)
    end = stdout.rfind(_END)
    if start == -1 or end == -1 or end < start:
        return stdout.strip()
    return stdout[start + len(_BEGIN) : end].strip()


class PowerShellRunner:
    """Executes read-only PowerShell locally or against an authorized host."""

    def __init__(
        self,
        computer_name: str | None = None,
        credential: RemoteCredential | None = None,
        timeout: int | None = None,
    ) -> None:
        self.computer_name = computer_name
        self.credential = credential
        self.timeout = timeout or settings.collector_timeout
        self._shell = find_powershell()
        self._admin: bool | None = None

    # -- capabilities ------------------------------------------------------
    @property
    def available(self) -> bool:
        return self._shell is not None

    @property
    def is_remote(self) -> bool:
        return bool(self.computer_name)

    def describe_method(self, detail: str) -> str:
        where = f"WinRM/{self.computer_name}" if self.is_remote else "local"
        return f"PowerShell ({where}): {detail}"

    # -- script assembly ---------------------------------------------------
    def _wrap(self, script: str, depth: int) -> str:
        body = (
            f"{_JSON_PREAMBLE}"
            "$__vsOut = & { " + script + " } ;"
            f"Write-Output '{_BEGIN}';"
            f"if ($null -eq $__vsOut) {{ Write-Output 'null' }} else {{ "
            f"$__vsOut | ConvertTo-Json -Depth {depth} -Compress }};"
            f"Write-Output '{_END}';"
        )
        if not self.is_remote:
            return body

        # Remote execution: build the credential inside the child process from
        # its environment so the password never appears in a command line or
        # process listing.
        cred = self.credential
        port = (cred.port if cred and cred.port else settings.winrm_default_port)
        auth = (cred.auth if cred else "negotiate").capitalize()
        ssl_flag = "-UseSSL " if (cred and cred.use_ssl) else ""
        remote = (
            f"{_JSON_PREAMBLE}"
            "$__vsPwd = ConvertTo-SecureString $env:VULSCANNER_REMOTE_SECRET "
            "-AsPlainText -Force;"
            "$__vsCred = New-Object System.Management.Automation.PSCredential("
            "$env:VULSCANNER_REMOTE_USER, $__vsPwd);"
            f"$__vsOut = Invoke-Command -ComputerName '{self.computer_name}' "
            f"-Port {port} -Authentication {auth} {ssl_flag}"
            "-Credential $__vsCred -ScriptBlock { "
            f"{_JSON_PREAMBLE} " + script + " };"
            f"Write-Output '{_BEGIN}';"
            f"if ($null -eq $__vsOut) {{ Write-Output 'null' }} else {{ "
            f"$__vsOut | ConvertTo-Json -Depth {depth} -Compress }};"
            f"Write-Output '{_END}';"
        )
        return remote

    # -- execution ---------------------------------------------------------
    def run(
        self, script: str, depth: int = 5, timeout: int | None = None
    ) -> PSResult:
        """Execute ``script`` and parse its JSON output."""
        if not self.available:
            return PSResult(
                ok=False,
                error=(
                    "PowerShell was not found on this machine. VulScanner "
                    "requires Windows PowerShell 5.1 or PowerShell 7+."
                ),
            )

        wrapped = self._wrap(script, depth)
        argv = [
            self._shell,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-OutputFormat",
            "Text",
            "-EncodedCommand",
            _encode_command(wrapped),
        ]

        env = os.environ.copy()
        if self.is_remote and self.credential:
            env["VULSCANNER_REMOTE_USER"] = self.credential.username
            env["VULSCANNER_REMOTE_SECRET"] = self.credential.password

        try:
            completed = subprocess.run(  # noqa: S603 - argv is fully controlled
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout or self.timeout,
                env=env,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except subprocess.TimeoutExpired:
            return PSResult(
                ok=False,
                error=f"PowerShell timed out after {timeout or self.timeout}s",
            )
        except OSError as exc:
            return PSResult(ok=False, error=f"Failed to start PowerShell: {exc}")
        finally:
            env.pop("VULSCANNER_REMOTE_SECRET", None)

        stdout = completed.stdout or ""
        stderr = completed.stderr or ""

        if completed.returncode != 0 and _BEGIN not in stdout:
            return PSResult(
                ok=False, stdout=stdout, stderr=stderr, returncode=completed.returncode
            )

        payload = _extract_json_block(stdout)
        if not payload or payload == "null":
            return PSResult(
                ok=True, data=None, stdout=stdout, stderr=stderr,
                returncode=completed.returncode,
            )
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            return PSResult(
                ok=False,
                stdout=stdout,
                stderr=stderr,
                returncode=completed.returncode,
                error=f"Could not parse PowerShell JSON output: {exc}",
            )
        return PSResult(
            ok=True, data=data, stdout=stdout, stderr=stderr,
            returncode=completed.returncode,
        )

    def run_list(self, script: str, depth: int = 5) -> tuple[list[dict], PSResult]:
        """Run a script expected to emit objects; always returns a list."""
        result = self.run(script, depth=depth)
        if not result.ok or result.data is None:
            return [], result
        data = result.data
        if isinstance(data, dict):
            return [data], result
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)], result
        return [], result

    def run_script_file(self, relative_path: str, depth: int = 6) -> PSResult:
        """Execute a script from the bundled ``backend/powershell`` library."""
        path = (settings.powershell_dir / relative_path).resolve()
        library = settings.powershell_dir.resolve()
        if library not in path.parents:
            return PSResult(ok=False, error="Script path escapes the script library")
        if not path.exists():
            return PSResult(ok=False, error=f"Script not found: {relative_path}")
        return self.run(path.read_text(encoding="utf-8"), depth=depth)

    # -- privilege ---------------------------------------------------------
    def is_elevated(self) -> bool:
        """Whether the scanning session has administrative rights on the target."""
        if self._admin is not None:
            return self._admin
        script = (
            "$id=[Security.Principal.WindowsIdentity]::GetCurrent();"
            "$p=New-Object Security.Principal.WindowsPrincipal($id);"
            "[pscustomobject]@{Elevated="
            "$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}"
        )
        result = self.run(script, depth=2, timeout=30)
        self._admin = bool(
            result.ok and isinstance(result.data, dict) and result.data.get("Elevated")
        )
        return self._admin
