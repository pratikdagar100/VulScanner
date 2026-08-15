"""VulScanner scanning engine.

The engine is independent of any user interface: the REST API, the web
application and the CLI all drive the same collectors through
:class:`~app.scanner.engine.ScanEngine`.
"""

from app.scanner.base import BaseCollector, CollectorResult, CollectorStatus
from app.scanner.context import ScanCancelled, ScanContext
from app.scanner.engine import ScanEngine, ScanOutput, parse_port_range
from app.scanner.registry import (
    COLLECTORS,
    COLLECTORS_BY_NAME,
    PROFILE_DESCRIPTIONS,
    collectors_for_profile,
    describe_collectors,
)
from app.scanner.runner import PowerShellRunner, RemoteCredential

__all__ = [
    "BaseCollector",
    "COLLECTORS",
    "COLLECTORS_BY_NAME",
    "CollectorResult",
    "CollectorStatus",
    "PROFILE_DESCRIPTIONS",
    "PowerShellRunner",
    "RemoteCredential",
    "ScanCancelled",
    "ScanContext",
    "ScanEngine",
    "ScanOutput",
    "collectors_for_profile",
    "describe_collectors",
    "parse_port_range",
]
