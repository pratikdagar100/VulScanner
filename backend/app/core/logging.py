"""Structured logging for VulScanner.

Emits human readable logs to the console and JSON lines to disk. A redaction
filter strips credential-like values so secrets never reach a log file.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.config import settings

_SENSITIVE_KEYS = re.compile(
    r"(?i)(\b(?:pass(?:word|wd)?|secret|token|api[_-]?key|credential|authorization|"
    r"connectionstring|private[_-]?key|bearer)\b\s*[:=]\s*)"
    r"(\"[^\"]*\"|'[^']*'|\S+)"
)
_REDACTED = "[REDACTED]"


def redact(text: str) -> str:
    """Replace credential-looking values inside free text."""
    if not text:
        return text
    return _SENSITIVE_KEYS.sub(lambda m: f"{m.group(1)}{_REDACTED}", text)


class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact(str(record.msg))
        except Exception:  # never let logging break a scan
            pass
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in ("scan_id", "target", "collector", "user"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


_CONFIGURED = False


def configure_logging(log_dir: Path | None = None, level: str | None = None) -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return

    directory = Path(log_dir or settings.log_dir)
    directory.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(getattr(logging, (level or settings.log_level).upper(), logging.INFO))

    console = logging.StreamHandler()
    console.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
    )
    console.addFilter(RedactionFilter())
    root.addHandler(console)

    file_handler = logging.handlers.RotatingFileHandler(
        directory / "vulscanner.jsonl",
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(JsonFormatter())
    file_handler.addFilter(RedactionFilter())
    root.addHandler(file_handler)

    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    configure_logging()
    return logging.getLogger(name)
