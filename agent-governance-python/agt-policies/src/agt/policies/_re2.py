# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Go RE2 compatibility helpers for policy-authored patterns."""

from __future__ import annotations

import fnmatch
import json
import os
import shutil
import subprocess
from pathlib import Path


def glob_to_re2(pattern: str, *, require_opa: bool = False) -> str:
    """Translate a Python glob to RE2 and validate the emitted expression."""
    translated = fnmatch.translate(pattern)
    if translated.endswith(r"\Z"):
        translated = translated[:-2] + r"\z"
    validate_re2(translated, require_opa=require_opa)
    return translated


def validate_re2(pattern: str, *, require_opa: bool = False) -> None:
    """Validate one pattern with OPA's Go RE2 engine when available."""
    opa = _opa_path()
    if opa is None:
        if require_opa:
            raise ValueError(
                "OPA is required to validate REGEX and GLOB patterns safely"
            )
        return
    try:
        proc = subprocess.run(
            [
                str(opa),
                "eval",
                "--format=json",
                "--stdin-input",
                "regex.is_valid(input.pattern)",
            ],
            input=json.dumps({"pattern": pattern}),
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"OPA regex validation failed: {exc}") from exc
    if proc.returncode != 0:
        detail = proc.stderr.strip() or "OPA regex validation failed"
        raise ValueError(detail)
    try:
        payload = json.loads(proc.stdout)
        valid = payload["result"][0]["expressions"][0]["value"]
    except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
        raise ValueError("OPA returned an invalid regex validation response") from exc
    if valid is not True:
        raise ValueError("pattern is not valid Go RE2 syntax")


def _opa_path() -> Path | None:
    configured = os.environ.get("ACS_OPA_PATH")
    if configured:
        path = Path(configured).expanduser()
        if path.is_file():
            return path
        raise ValueError(f"ACS_OPA_PATH does not name a file: {path}")
    discovered = shutil.which("opa")
    return Path(discovered) if discovered else None


__all__ = ["glob_to_re2", "validate_re2"]
