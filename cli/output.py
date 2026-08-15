"""Terminal output helpers: colour, tables, progress and severity formatting."""

from __future__ import annotations

import os
import sys
from typing import Any, Iterable, Sequence

ANSI = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "bright_red": "\033[91m", "green": "\033[32m",
    "yellow": "\033[33m", "blue": "\033[34m", "magenta": "\033[35m",
    "cyan": "\033[36m", "grey": "\033[90m", "white": "\033[97m",
}

SEVERITY_COLOURS = {
    "critical": "bright_red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "informational": "grey",
}

BANNER = r"""
 __     __    _ ____
 \ \   / /   | / ___|  ___ __ _ _ __  _ __   ___ _ __
  \ \ / / | | | \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
   \ V /| |_| |  ___) | (_| (_| | | | | | | |  __/ |
    \_/  \__,_| |____/ \___\__,_|_| |_|_| |_|\___|_|
"""


def _supports_colour() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        # Windows Terminal and PowerShell 7 set this; enable VT otherwise.
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return bool(os.environ.get("WT_SESSION"))
    return True


def _supports_unicode() -> bool:
    """Whether the active stdout encoding can render box-drawing characters."""
    encoding = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        "█░→✓○…".encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


class Console:
    """Small dependency-free console renderer."""

    def __init__(self, quiet: bool = False, verbose: bool = False, colour: bool = True):
        self.quiet = quiet
        self.verbose = verbose
        self.colour = colour and _supports_colour()
        self._last_progress_length = 0

        # Redirected output on Windows defaults to the legacy ANSI codepage,
        # which cannot encode the block characters used by the progress bar.
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError, OSError):
            pass
        self.unicode = _supports_unicode()

        self.glyphs = (
            {"full": "█", "empty": "░", "done": "✓", "running": "→",
             "pending": "○", "ellipsis": "…", "bar": "█"}
            if self.unicode
            else {"full": "#", "empty": ".", "done": "[x]", "running": "[>]",
                  "pending": "[ ]", "ellipsis": "...", "bar": "#"}
        )

    # -- primitives --------------------------------------------------------
    def paint(self, text: str, *styles: str) -> str:
        if not self.colour or not styles:
            return text
        prefix = "".join(ANSI.get(style, "") for style in styles)
        return f"{prefix}{text}{ANSI['reset']}"

    def write(self, text: str = "") -> None:
        if not self.quiet:
            print(text)

    def always(self, text: str = "") -> None:
        print(text)

    def banner(self, version: str) -> None:
        if self.quiet:
            return
        self.write(self.paint(BANNER, "cyan"))
        self.write(
            self.paint(
                f"  VulScanner {version} - agent-less Windows security assessment",
                "bold",
            )
        )
        self.write(
            self.paint(
                "  Authorized defensive use only. No exploitation, no credential "
                "collection.\n",
                "grey",
            )
        )

    def header(self, text: str) -> None:
        self.write("")
        self.write(self.paint(text, "bold", "cyan"))
        self.write(self.paint("-" * min(len(text), 78), "grey"))

    def info(self, text: str) -> None:
        self.write(f"  {text}")

    def detail(self, text: str) -> None:
        if self.verbose:
            self.write(self.paint(f"    {text}", "grey"))

    def success(self, text: str) -> None:
        self.write(self.paint(f"  [ok] {text}", "green"))

    def warn(self, text: str) -> None:
        self.write(self.paint(f"  [!]  {text}", "yellow"))

    def error(self, text: str) -> None:
        print(self.paint(f"  [x]  {text}", "bright_red"), file=sys.stderr)

    def severity(self, level: str) -> str:
        return self.paint(level.upper().ljust(13), SEVERITY_COLOURS.get(level, "grey"), "bold")

    # -- progress ----------------------------------------------------------
    def progress(self, percent: float, stage: str, message: str = "") -> None:
        """Render an in-place progress bar."""
        if self.quiet:
            return
        width = 28
        filled = int(width * max(0.0, min(100.0, percent)) / 100)
        bar = self.glyphs["full"] * filled + self.glyphs["empty"] * (width - filled)
        label = f"{stage}: {message}" if message else stage
        line = f"  [{self.paint(bar, 'cyan')}] {percent:5.1f}%  {label}"
        clean = f"  [{bar}] {percent:5.1f}%  {label}"
        padding = max(0, self._last_progress_length - len(clean))
        self._last_progress_length = len(clean)
        sys.stdout.write("\r" + line + " " * padding)
        sys.stdout.flush()

    def end_progress(self) -> None:
        if self.quiet or not self._last_progress_length:
            return
        sys.stdout.write("\r" + " " * (self._last_progress_length + 2) + "\r")
        sys.stdout.flush()
        self._last_progress_length = 0

    def stage_list(self, stages: Sequence[tuple[str, str]]) -> None:
        """Render the stage checklist (done / running / pending)."""
        if self.quiet:
            return
        marks = {
            "done": (self.glyphs["done"], "green"),
            "running": (self.glyphs["running"], "cyan"),
            "pending": (self.glyphs["pending"], "grey"),
        }
        for label, state in stages:
            mark, colour = marks.get(state, ("○", "grey"))
            self.write(f"  {self.paint(mark, colour)} {label}")

    # -- tables ------------------------------------------------------------
    def table(
        self,
        headers: Sequence[str],
        rows: Iterable[Sequence[Any]],
        max_widths: Sequence[int] | None = None,
    ) -> None:
        rows = [[("" if cell is None else str(cell)) for cell in row] for row in rows]
        if not rows:
            self.info(self.paint("(no rows)", "grey"))
            return

        widths = [len(header) for header in headers]
        for row in rows:
            for index, cell in enumerate(row):
                if index < len(widths):
                    widths[index] = max(widths[index], len(cell))
        if max_widths:
            widths = [
                min(width, max_widths[index]) if index < len(max_widths) else width
                for index, width in enumerate(widths)
            ]

        def render(cells: Sequence[str]) -> str:
            parts = []
            for index, cell in enumerate(cells):
                width = widths[index] if index < len(widths) else len(cell)
                text = (
                    cell
                    if len(cell) <= width
                    else cell[: max(0, width - len(self.glyphs["ellipsis"]))]
                    + self.glyphs["ellipsis"]
                )
                parts.append(text.ljust(width))
            return "  " + "  ".join(parts).rstrip()

        self.write(self.paint(render(list(headers)), "bold"))
        self.write(self.paint("  " + "-" * (sum(widths) + 2 * (len(widths) - 1)), "grey"))
        for row in rows:
            self.write(render(row))

    def key_values(self, pairs: Sequence[tuple[str, Any]], indent: str = "  ") -> None:
        width = max((len(str(key)) for key, _ in pairs), default=0)
        for key, value in pairs:
            self.write(f"{indent}{self.paint(str(key).ljust(width), 'grey')}  {value}")
