# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Regression test for issue #3933: credential boundary anchors.

The credential redaction patterns for GitHub, OpenAI, AWS, and Google tokens
in three SDKs (TypeScript, Rust, Python; C# is in #3934) previously included
``_`` in their boundary-anchor exclusion sets, so a secret glued to ``_`` was
silently missed. This test inspects the source files themselves to verify the
patterns use alphanumeric-only anchors (``[A-Za-z0-9]`` without ``_``) and
that no ``\\b`` word boundary is used on a bounded-token pattern.

This is a **source-level** guard. The per-SDK unit tests verify runtime
behaviour; this test catches an accidental revert without building that
SDK's toolchain.
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
    # TypeScript
    REPO_ROOT
    / "agent-governance-python"
    / "agent-mesh"
    / "packages"
    / "mcp-proxy"
    / "src"
    / "audit.ts",
    # Python
    REPO_ROOT
    / "agent-governance-python"
    / "agent-os"
    / "src"
    / "agent_os"
    / "credential_redactor.py",
]

# Rust uses procedural boundary functions (match arms), not regex strings.
# A separate test below checks the Rust source directly.
_RUST_REDACTOR = (
    REPO_ROOT
    / "agent-governance-rust"
    / "agentmesh-mcp"
    / "src"
    / "mcp"
    / "redactor.rs"
)

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

# This regex matches a lookaround that includes _ in its character class,
# which is the core defect in #3933. It handles both lookbehind ``(?<!``
# / ``(?<=`` and lookahead ``(?!`` / ``(?=`` forms.
_UNDERSCORE_IN_LOOKAROUND = re.compile(
    r"\(\?<?[!=]\[A-Za-z0-9[^\]]*_[^\]]*\]"
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


# ---------------------------------------------------------------
# Rust boundary functions: procedural match-arm checks.
#
# Rust uses is_left_boundary_char / is_right_boundary_char with
# match arms instead of regex strings.  The regex-scanning guard
# above cannot inspect these, so we check them separately.
# ---------------------------------------------------------------

def _extract_fn_body(source: str, fn_name: str) -> tuple[str, int]:
    """Extract a Rust function body and its starting line number."""
    lines = source.splitlines()
    start = -1
    depth = 0
    body_lines: list[str] = []
    for i, line in enumerate(lines):
        if fn_name in line and start < 0:
            start = i + 1  # 1-indexed
            depth = 0
        if start < 0:
            continue
        depth += line.count("{") - line.count("}")
        body_lines.append(line)
        if depth <= 0 and len(body_lines) > 1:
            break
    return "\n".join(body_lines), start


def _split_match_arms(body: str) -> list[tuple[str, str]]:
    """Split a Rust match body into (kind, arm_body) pairs.

    Handles multi-line block arms ``Kind => { ... }`` by tracking braces.
    """
    arms: list[tuple[str, str]] = []
    current_kind = ""
    current_body_parts: list[str] = []
    depth = 0
    in_arm = False
    for line in body.splitlines():
        stripped = line.strip()
        # Detect arm start: ``SomeKind => ...`` or ``_ => ...``
        if "=>" in stripped and not in_arm:
            kind_part = stripped.split("=>")[0].strip().split("::")[-1]
            current_kind = kind_part
            current_body_parts = [stripped]
            # Check if this arm opens a block
            depth = stripped.count("{") - stripped.count("}")
            in_arm = depth > 0
            if not in_arm:
                arms.append((current_kind, stripped))
            continue
        if in_arm:
            current_body_parts.append(stripped)
            depth += stripped.count("{") - stripped.count("}")
            if depth <= 0:
                arms.append((current_kind, "\n".join(current_body_parts)))
                in_arm = False
    return arms


def test_rust_left_boundary_non_slack_rejects_only_alphanumeric() -> None:
    """Non-Slack match arms in is_left_boundary_char must reject only
    ASCII alphanumerics.  If an arm for a non-Slack kind includes '_'
    or blocks '-', a secret prefixed with underscore or dash would be
    missed (regression for #3933)."""
    if not _RUST_REDACTOR.exists():
        pytest.skip("redactor.rs not found")

    text = _RUST_REDACTOR.read_text(encoding="utf-8")
    body, start_line = _extract_fn_body(text, "fn is_left_boundary_char")
    arms = _split_match_arms(body)
    assert start_line > 0 and arms, "is_left_boundary_char not found in redactor.rs"
    for kind, arm_body in arms:
        if "SlackToken" in kind:
            continue
        if "'_'" in arm_body:
            pytest.fail(
                f"redactor.rs: is_left_boundary_char arm for {kind} "
                f"blocks '_', which would miss underscore-prefixed secrets.\n"
                f"  {arm_body}"
            )
        if "'-'" in arm_body and "false" not in arm_body:
            pytest.fail(
                f"redactor.rs: is_left_boundary_char arm for {kind} "
                f"blocks '-', which would miss dash-prefixed secrets.\n"
                f"  {arm_body}"
            )


def test_rust_right_boundary_non_slack_rejects_alphanumeric() -> None:
    """Non-Slack match arms in is_right_boundary_char must reject ASCII
    alphanumerics (not return false unconditionally).  An unconditional
    false means right boundary is never enforced (#3933 review)."""
    if not _RUST_REDACTOR.exists():
        pytest.skip("redactor.rs not found")

    text = _RUST_REDACTOR.read_text(encoding="utf-8")
    body, start_line = _extract_fn_body(text, "fn is_right_boundary_char")
    arms = _split_match_arms(body)
    assert start_line > 0 and arms, "is_right_boundary_char not found in redactor.rs"
    for kind, arm_body in arms:
        if "SlackToken" in kind:
            continue
        # The catch-all or any non-Slack arm must not unconditionally return false
        if "false" in arm_body and "is_ascii" not in arm_body and "last_consumed" not in arm_body:
            pytest.fail(
                f"redactor.rs: is_right_boundary_char arm for {kind} "
                f"returns false without checking is_ascii_alphanumeric, "
                f"so right boundary is never enforced.\n  {arm_body}"
            )
        # No non-Slack arm should contain '_'
        if "'_'" in arm_body:
            pytest.fail(
                f"redactor.rs: is_right_boundary_char arm for {kind} "
                f"blocks '_', which would miss underscore-suffixed secrets.\n"
                f"  {arm_body}"
            )
