"""Per-scan execution context handed to every collector."""

from __future__ import annotations

import platform
import socket
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from app.core.config import settings
from app.core.permissions import TargetAuthorization
from app.scanner.runner import PowerShellRunner, RemoteCredential

ProgressCallback = Callable[[str, float, str], None]


class ScanCancelled(Exception):
    """Raised inside the engine when an operator cancels a running scan."""


@dataclass
class ScanContext:
    """Everything a collector needs to know about the current assessment."""

    authorization: TargetAuthorization
    profile: str = "standard"
    options: dict[str, Any] = field(default_factory=dict)
    credential: RemoteCredential | None = None
    scan_id: int | None = None

    _runner: PowerShellRunner | None = field(default=None, init=False, repr=False)
    _cancel: threading.Event = field(default_factory=threading.Event, init=False, repr=False)
    progress_callback: ProgressCallback | None = None

    # -- target shape ------------------------------------------------------
    @property
    def target(self) -> str:
        return self.authorization.target

    @property
    def target_kind(self) -> str:
        return self.authorization.kind

    @property
    def is_local(self) -> bool:
        return self.authorization.kind == "local"

    @property
    def is_network_scope(self) -> bool:
        return self.authorization.kind == "cidr"

    @property
    def is_windows_target(self) -> bool:
        """Whether Windows collectors can run against this target."""
        if self.is_network_scope:
            return False
        if self.is_local:
            return platform.system() == "Windows"
        # Remote host collection needs WinRM credentials.
        return self.credential is not None

    @property
    def computer_name(self) -> str | None:
        return None if self.is_local else self.authorization.normalized

    @property
    def runner(self) -> PowerShellRunner:
        if self._runner is None:
            self._runner = PowerShellRunner(
                computer_name=self.computer_name,
                credential=self.credential,
                timeout=int(self.options.get("collector_timeout", settings.collector_timeout)),
            )
        return self._runner

    @property
    def scanner_host(self) -> str:
        try:
            return socket.gethostname()
        except OSError:  # pragma: no cover
            return "unknown"

    # -- options -----------------------------------------------------------
    def option(self, key: str, default: Any = None) -> Any:
        return self.options.get(key, default)

    # -- cancellation ------------------------------------------------------
    def cancel(self) -> None:
        self._cancel.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def raise_if_cancelled(self) -> None:
        if self._cancel.is_set():
            raise ScanCancelled(f"Scan {self.scan_id} was cancelled by an operator")

    # -- progress ----------------------------------------------------------
    def report_progress(self, stage: str, percent: float, message: str = "") -> None:
        if self.progress_callback:
            try:
                self.progress_callback(stage, percent, message)
            except Exception:  # progress must never break a scan
                pass
