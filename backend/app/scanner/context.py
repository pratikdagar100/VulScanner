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
        """Whether authenticated Windows collection can run against this target."""
        if self.is_network_scope:
            return False
        if self.is_local:
            return platform.system() == "Windows"
        # Remote host collection needs WinRM credentials.
        return self.credential is not None

    @property
    def assessment_mode(self) -> str:
        """How this target is being assessed.

        ``local-authenticated``     full collection on this machine
        ``remote-authenticated``    full collection over WinRM
        ``remote-unauthenticated``  no credentials, so the host is assessed from
                                    the outside only - ports, services, banners
        ``network-discovery``       a scope rather than a single host
        ``unsupported-platform``    local target, but not running on Windows
        """
        if self.is_network_scope:
            return "network-discovery"
        if self.is_local:
            return (
                "local-authenticated"
                if platform.system() == "Windows"
                else "unsupported-platform"
            )
        return (
            "remote-authenticated"
            if self.credential
            else "remote-unauthenticated"
        )

    @property
    def is_unauthenticated_remote(self) -> bool:
        return self.assessment_mode == "remote-unauthenticated"

    def windows_collection_reason(self) -> str:
        """Why authenticated Windows collection is unavailable, specifically.

        A generic "requires a Windows target" tells an operator nothing about
        what to change, so each case explains itself and what to do next.
        """
        mode = self.assessment_mode
        if mode == "network-discovery":
            return (
                "Not applicable to a network scope scan: VulScanner assesses the "
                "hosts it discovers from the outside, and does not log in to them."
            )
        if mode == "unsupported-platform":
            return (
                f"Windows collection requires a Windows host; VulScanner is "
                f"running on {platform.system()}. Network assessment is unaffected."
            )
        if mode == "remote-unauthenticated":
            return (
                f"No credentials were supplied for {self.target}, so VulScanner "
                "performed an unauthenticated assessment (ports, services and "
                "banners) instead. Supply WinRM credentials to collect Windows "
                "configuration, patches and accounts."
            )
        return "Collector is unavailable for this target."

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
