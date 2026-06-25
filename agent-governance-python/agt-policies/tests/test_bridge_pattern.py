# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Unit tests for ``agt.policies.bridge`` pattern translation and bundle safety.

These avoid the v4 ``agent_os`` dependency (unlike ``test_bridge.py``) by
exercising the bridge's pattern translation directly and by driving
:func:`governance_to_acs_manifest` with a duck-typed policy fixture. They pin
the fix for the ``GLOB`` fail-open: ``fnmatch.translate`` emits Python-only
``(?s:...)`` / ``\\Z`` constructs that Go RE2 (OPA) rejects, so a ``GLOB``
blocked pattern silently never matched.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import types
from pathlib import Path

import pytest

from agt.policies.bridge import (
    _glob_to_re2,
    _pattern_to_regex,
    governance_to_acs_manifest,
)


def _opa_regex_match(pattern: str, subject: str, opa: str) -> bool | None:
    """Evaluate ``regex.match(pattern, subject)`` under real OPA / Go RE2.

    Returns the boolean result, or ``None`` when RE2 rejects the pattern
    (which is exactly what the old ``fnmatch.translate`` output triggered:
    the deny rule went undefined and a GLOB pattern silently failed open).
    """
    rego = "package c\nimport rego.v1\nm := regex.match(input.p, input.s)\n"
    with tempfile.TemporaryDirectory() as d:
        rego_path = Path(d) / "c.rego"
        rego_path.write_text(rego, encoding="utf-8")
        proc = subprocess.run(
            [opa, "eval", "--stdin-input", "--data", str(rego_path),
             "--format", "json", "data.c.m"],
            input=json.dumps({"p": pattern, "s": subject}),
            capture_output=True,
            text=True,
            timeout=10,
        )
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError, ValueError):
        return None


def _glob(value: str) -> tuple[str, types.SimpleNamespace]:
    return (value, types.SimpleNamespace(name="GLOB"))


@pytest.mark.parametrize(
    "glob, subject, expect",
    [
        ("*.exe", "payload.exe", True),
        ("*.exe", "payload.txt", False),
        ("secret?.log", "secret1.log", True),
        ("secret?.log", "secret12.log", False),
        ("[ab]*.sh", "a_run.sh", True),
        ("[ab]*.sh", "c_run.sh", False),
    ],
)
def test_glob_to_re2_matches_like_fnmatch(glob: str, subject: str, expect: bool) -> None:
    assert bool(re.match(_glob_to_re2(glob), subject)) is expect


@pytest.mark.parametrize(
    "glob, subject",
    [
        ("[!ab]x", "cx"),          # negated class matches
        ("[!ab]x", "ax"),          # negated class excludes
        ("a.c", "a.c"),            # '.' is a literal in a glob (escaped)
        ("a.c", "axc"),            # ...so it must NOT match any char
        ("a+b*", "a+bcd"),         # '+' is a literal, escaped
        ("f[oo", "f[oo"),          # unclosed '[' is a literal
        ("f[oo", "fXoo"),
        ("*.tar.gz", "archive.tar.gz"),
        ("data_?.csv", "data_9.csv"),
        ("data_?.csv", "data_99.csv"),
    ],
)
def test_glob_to_re2_agrees_with_fnmatchcase(glob: str, subject: str) -> None:
    # Cross-check the translator against Python's reference matcher (the
    # case-sensitive variant, matching our whole-string anchoring). RE2-safe
    # output that still mirrors glob semantics for every edge case.
    import fnmatch

    assert bool(re.match(_glob_to_re2(glob), subject)) is fnmatch.fnmatchcase(
        subject, glob
    )


def test_glob_output_is_re2_safe() -> None:
    # Go RE2 rejects ``\Z`` and the inline ``(?s:...)`` flag group that
    # ``fnmatch.translate`` produces; the translator must emit neither.
    rx = _glob_to_re2("*.exe")
    assert "\\Z" not in rx
    assert "(?s:" not in rx
    assert rx.startswith("(?s)^") and rx.endswith("$")


def test_pattern_to_regex_dispatches_glob_to_re2() -> None:
    assert _pattern_to_regex(_glob("*.exe")) == _glob_to_re2("*.exe")


@pytest.mark.parametrize(
    "subject, expect",
    [("payload.exe", True), ("payload.txt", False), ("dir/app.exe", True)],
)
def test_glob_re2_compiles_and_matches_under_opa(subject: str, expect: bool) -> None:
    """Regression guard: the GLOB regex must compile AND match under Go RE2.

    The previous ``fnmatch.translate`` output (``(?s:.*\\.exe)\\Z``) is rejected
    by RE2, so ``regex.match`` returned undefined (``None`` here) and the deny
    rule silently failed open. The existing suite never compiled a GLOB pattern
    under OPA, which is how the bug slipped through.
    """
    opa = shutil.which("opa") or str(Path.home() / ".local" / "bin" / "opa")
    if not Path(opa).exists():
        pytest.skip("opa binary required for RE2 compatibility check")
    rx = _glob_to_re2("*.exe")
    result = _opa_regex_match(rx, subject, opa)
    assert result is expect, f"regex.match({rx!r}, {subject!r}) -> {result!r}"


def test_substring_and_regex_patterns_unchanged() -> None:
    assert _pattern_to_regex("a.b/c") == re.escape("a.b/c")
    regex_entry = ("rm\\s+-rf", types.SimpleNamespace(name="REGEX"))
    assert _pattern_to_regex(regex_entry) == "rm\\s+-rf"


class _Policy:
    name = "p"
    version = "1.0.0"
    max_tokens = 100
    max_tool_calls = 5
    allowed_tools: list[str] = []
    blocked_patterns: list = []
    require_human_approval = False
    confidence_threshold = 0.0


@pytest.mark.parametrize("bad", [float("inf"), float("nan")])
def test_non_finite_confidence_threshold_rejected(tmp_path: Path, bad: float) -> None:
    pol = _Policy()
    pol.confidence_threshold = bad
    with pytest.raises(ValueError):
        governance_to_acs_manifest(
            pol, bundle_dir=tmp_path / "bundle", stock_rego_root=tmp_path / "stock"
        )


def test_created_bundle_dir_cleaned_up_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "agt_bridge_leak"
    monkeypatch.setattr(
        "agt.policies.bridge.tempfile.mkdtemp", lambda *a, **k: str(target)
    )
    pol = _Policy()
    # Non-string GLOB value makes _pattern_to_regex raise after the temp dir
    # was created and stock libs (none here) were processed.
    pol.blocked_patterns = [(123, types.SimpleNamespace(name="GLOB"))]
    with pytest.raises(ValueError):
        governance_to_acs_manifest(pol, stock_rego_root=tmp_path / "stock")
    assert not target.exists(), "self-created bundle dir must be removed on failure"
