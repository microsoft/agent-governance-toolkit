# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Regression test for issue #3933: credential boundary anchors.

The credential redaction patterns for GitHub, OpenAI, AWS, and Google tokens
in all four SDKs (.NET, TypeScript, Rust, Python) previously included ``_``
in their boundary-anchor exclusion sets, so a secret glued to ``_`` was
silently missed. This test inspects the source files themselves to verify the
patterns use alphanumeric-only anchors (``[A-Za-z0-9]`` without ``_``) and
that no ``\\b`` word boundary is used on a bounded-token pattern.

This is a **source-level** guard. The per-SDK unit tests verify runtime
behaviour; this test catches an accidental revert in any SDK without
building that SDK's toolchain.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# ---------------------------------------------------------------
# Files carrying bounded-token credential patterns.
# Each entry maps a file to the regex fragment that should NOT
# appear in any bounded-token pattern line.
# ---------------------------------------------------------------
BOUNDED_TOKEN_FILES = [
    # C#
    REPO_ROOT
    / "agent-governance-dotnet"
    / "src"
    / "AgentGovernance"
    / "Mcp"
    / "McpCredentialRedactor.cs",
    # TypeScript
    REPO_ROOT
    / "agent-governance-python"
    / "agent-mesh"
    / "packages"
    / "mcp-proxy"
    / "src"
    / "audit.ts",
    # Rust
    REPO_ROOT
    / "agent-governance-rust"
    / "agentmesh-mcp"
    / "src"
    / "mcp"
    / "redactor.rs",
    # Python
    REPO_ROOT
    / "agent-governance-python"
    / "agent-os"
    / "src"
    / "agent_os"
    / "credential_redactor.py",
]

# Pattern names that are bounded-token patterns (not keyword-anchored).
BOUNDED_PREFIXES = [
    "AKIA",       # AWS access key
    "AIza",       # Google API key
    "gh[psour]_", # GitHub token (regex form)
    "ghp_",       # GitHub token (literal form)
    "ghs_",
    "gho_",
    "ghu_",
    "ghr_",
    "github_pat_",
    "sk-",        # OpenAI token
]

# This regex matches a \b that sits on the same line as one of the
# bounded-token prefixes. It catches both ``\b`` and ``\\b`` forms.
_WB_NEAR_TOKEN = re.compile(
    r"(?:"
    + "|".join(re.escape(p) for p in BOUNDED_PREFIXES)
    + r")"
    r".*\\b"
    r"|\\b.*(?:"
    + "|".join(re.escape(p) for p in BOUNDED_PREFIXES)
    + r")"
)

# This regex matches a lookaround that includes _ in its character class,
# which is the core defect in #3933.
_UNDERSCORE_IN_LOOKAROUND = re.compile(
    r"\(\?[<>!]=?\[A-Za-z0-9[^\]]*_[^\]]*\]"
)


@pytest.mark.parametrize(
    "filepath",
    BOUNDED_TOKEN_FILES,
    ids=lambda p: "/".join(p.relative_to(REPO_ROOT).parts[-3:]),
)
def test_no_word_boundary_on_bounded_token_patterns(filepath: Path) -> None:
    """Bounded-token patterns must not use ``\\b``; they should use
    ``(?<![A-Za-z0-9])`` / ``(?![A-Za-z0-9])`` instead."""
    if not filepath.exists():
        pytest.skip(f"{filepath} not found")

    text = filepath.read_text(encoding="utf-8")
    # Only check lines that mention a bounded token prefix.
    for i, line in enumerate(text.splitlines(), 1):
        for prefix in BOUNDED_PREFIXES:
            if prefix in line and r"\b" in line:
                # Exclude comment lines
                stripped = line.strip()
                if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                    continue
                pytest.fail(
                    f"{filepath.name}:{i}: bounded-token pattern line "
                    f"contains \\b (word boundary) near '{prefix}'. "
                    f"Use lookaround anchors instead.\n  {line.strip()}"
                )


@pytest.mark.parametrize(
    "filepath",
    BOUNDED_TOKEN_FILES,
    ids=lambda p: "/".join(p.relative_to(REPO_ROOT).parts[-3:]),
)
def test_no_underscore_in_bounded_token_lookaround(filepath: Path) -> None:
    """Bounded-token pattern lookarounds must not include ``_`` in the
    character class — it blocks detection of secrets glued to ``_``."""
    if not filepath.exists():
        pytest.skip(f"{filepath} not found")

    text = filepath.read_text(encoding="utf-8")
    for i, line in enumerate(text.splitlines(), 1):
        has_bounded_prefix = any(prefix in line for prefix in BOUNDED_PREFIXES)
        if not has_bounded_prefix:
            continue
        # Skip Slack — its value class includes - and that's correct
        if "xox" in line or "Slack" in line:
            continue
        # Skip comments
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
            continue
        if _UNDERSCORE_IN_LOOKAROUND.search(line):
            pytest.fail(
                f"{filepath.name}:{i}: bounded-token lookaround "
                f"includes '_' in character class.\n  {line.strip()}"
            )


# ---------------------------------------------------------------
# SSN pattern parity: content_scanner must match the separator
# forms that credential_redactor already accepts.
# ---------------------------------------------------------------

_CONTENT_SCANNER = (
    REPO_ROOT
    / "agent-governance-python"
    / "agent-rag-governance"
    / "src"
    / "agent_rag_governance"
    / "content_scanner.py"
)


def test_content_scanner_ssn_accepts_space_and_dot_separators() -> None:
    """The SSN pattern must accept space and dot separators, not only dash."""
    if not _CONTENT_SCANNER.exists():
        pytest.skip("content_scanner.py not found")

    text = _CONTENT_SCANNER.read_text(encoding="utf-8")
    # The pattern should use a character class like [\s.-] for separators.
    # A dash-only pattern would be \d{3}-\d{2}-\d{4}.
    if r"\d{3}-\d{2}-\d{4}" in text and r"[\s.-]" not in text:
        pytest.fail(
            "content_scanner.py SSN pattern only matches dash-separated form; "
            "it should match space and dot separators too (issue #3815)."
        )
