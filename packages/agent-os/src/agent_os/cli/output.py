# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Terminal output helpers for the Agent OS CLI.

Provides ANSI colour formatting, error/warning formatters, and the
module-level ``Colors`` singleton used across all CLI sub-commands.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import traceback
from typing import Any

logger = logging.getLogger(__name__)

# ============================================================================
# Terminal Colour Support
# ============================================================================


def supports_color() -> bool:
    """Check if terminal supports colors."""
    if os.environ.get('NO_COLOR') or os.environ.get('CI'):
        return False
    return sys.stdout.isatty()


class Colors:
    """ANSI color codes for terminal output.

    Uses instance attributes so that ``disable()`` does not mutate shared
    class state.  A module-level singleton is created below; import and use
    that instead of the class directly.
    """

    _DEFAULTS: dict[str, str] = {
        'RED': '\033[91m',
        'GREEN': '\033[92m',
        'YELLOW': '\033[93m',
        'BLUE': '\033[94m',
        'MAGENTA': '\033[95m',
        'CYAN': '\033[96m',
        'WHITE': '\033[97m',
        'BOLD': '\033[1m',
        'DIM': '\033[2m',
        'RESET': '\033[0m',
    }

    def __init__(self, enabled: bool | None = None) -> None:
        if enabled is None:
            enabled = supports_color()
        self._enabled = enabled
        self._apply(enabled)

    def _apply(self, enabled: bool) -> None:
        for name, code in self._DEFAULTS.items():
            setattr(self, name, code if enabled else '')

    def disable(self) -> None:
        """Disable colors on *this* instance."""
        self._enabled = False
        self._apply(False)

    def enable(self) -> None:
        """Enable colors on *this* instance."""
        self._enabled = True
        self._apply(True)

    @property
    def enabled(self) -> bool:
        return self._enabled


# Module-level singleton – every import shares this instance.
Colors = Colors()  # type: ignore[misc]


# ============================================================================
# Output Format
# ============================================================================


def get_output_format(args: argparse.Namespace) -> str:
    """Determine the output format from CLI arguments."""
    if getattr(args, "json", False):
        return "json"
    return getattr(args, "format", "text")


def get_config_path(args_path: str | None = None) -> "Path":
    """Resolve the config path from args or AGENTOS_CONFIG env var."""
    from pathlib import Path as _Path

    if args_path:
        return _Path(args_path)
    env_config = os.environ.get("AGENTOS_CONFIG")
    if env_config:
        return _Path(env_config)
    return _Path(".")


# ============================================================================
# CLI Error Formatting
# ============================================================================

DOCS_URL = "https://github.com/microsoft/agent-governance-toolkit/blob/main/docs"

AVAILABLE_POLICIES = ("strict", "permissive", "audit")


def _difflib_best_match(word: str, candidates: list[str]) -> str | None:
    """Return the closest match from *candidates*, or ``None``."""
    import difflib

    matches = difflib.get_close_matches(word, candidates, n=1, cutoff=0.5)
    return matches[0] if matches else None


def format_error(message: str, suggestion: str | None = None,
                 docs_path: str | None = None) -> str:
    """Return a colorized error string with an optional suggestion and docs link."""
    parts = [f"{Colors.RED}{Colors.BOLD}Error:{Colors.RESET} {message}"]
    if suggestion:
        parts.append(f"  {Colors.GREEN}💡 Suggestion:{Colors.RESET} {suggestion}")
    if docs_path:
        parts.append(f"  {Colors.DIM}📖 Docs: {DOCS_URL}/{docs_path}{Colors.RESET}")
    return "\n".join(parts)


def handle_cli_error(e: Exception, args: argparse.Namespace) -> int:
    """Centralized error handler for Agent OS CLI."""
    # Sanitize exception message to avoid leaking internal details
    is_known_error = isinstance(e, (FileNotFoundError, ValueError, PermissionError))
    error_msg = "A file, value, or permission error occurred." if is_known_error else "An internal error occurred."

    if getattr(args, "json", False) or (hasattr(args, "format") and args.format == "json"):
        print(json.dumps({
            "status": "error",
            "message": error_msg,
            "error_type": "ValidationError" if is_known_error else "InternalError"
        }, indent=2))
    else:
        print(format_error(error_msg))
        if os.environ.get("AGENTOS_DEBUG"):
            traceback.print_exc()
    return 1


def handle_missing_config(path: str = ".") -> str:
    """Error message for a missing ``.agents/`` config directory."""
    return format_error(
        f"Config directory not found: {path}/.agents/",
        suggestion="Did you mean to create one? Run: agentos init",
        docs_path="getting-started.md",
    )


def handle_invalid_policy(name: str) -> str:
    """Error message for an unrecognised policy template name."""
    available = ", ".join(AVAILABLE_POLICIES)
    suggestion = f"Available policies: {available}"
    match = _difflib_best_match(name, list(AVAILABLE_POLICIES))
    if match:
        suggestion += f". Did you mean '{match}'?"
    return format_error(
        f"Unknown policy template: '{name}'",
        suggestion=suggestion,
        docs_path="security-spec.md",
    )


def handle_missing_dependency(package: str, extra: str = "") -> str:
    """Error message when an optional dependency is missing."""
    install_cmd = f"pip install agent-os-kernel[{extra}]" if extra else f"pip install {package}"
    return format_error(
        f"Required package not installed: {package}",
        suggestion=f"Install with: {install_cmd}",
        docs_path="installation.md",
    )


def handle_connection_error(host: str, port: int) -> str:
    """Error message for a connection failure."""
    return format_error(
        f"Could not connect to {host}:{port}",
        suggestion=f"Check that the service is running on {host}:{port}",
    )
