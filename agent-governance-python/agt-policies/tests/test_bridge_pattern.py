# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for bridge blocked-pattern translation (GLOB/REGEX to RE2) and bundle hygiene."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
import pytest
from agent_os.integrations.base import GovernancePolicy, PatternType
from dataclasses import dataclass, field

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agt.policies.bridge import _pattern_to_regex, governance_to_acs_manifest  # noqa: E402
from agt.policies import bridge as bridge_module  # noqa: E402

pytest.importorskip("agent_os")


_PACKAGE_SRC = Path(__file__).resolve().parents[1] / "src"

class _PolicyFixture:
    name = "non_finite_threshold"
    max_tokens = 4096
    max_tool_calls = 10
    allowed_tools: list[str] = []
    blocked_patterns: list[Any] = []
    require_human_approval = False
    confidence_threshold = float("inf")
    version = "1.0.0"


def _opa() -> Path:
    return Path.home() / ".local" / "bin" / "opa"


@dataclass
class _CleanupPolicyFixture:
    name: str = "bridge_cleanup"
    max_tokens: int = 4096
    max_tool_calls: int = 10
    allowed_tools: list[str] = field(default_factory=list)
    blocked_patterns: list[Any] = field(default_factory=list)
    require_human_approval: bool = False
    confidence_threshold: float = 0.0
    version: str = "1.0.0"


def _stock_rego_root(tmp_path: Path) -> Path:
    stock_root = tmp_path / "stock"
    stock_root.mkdir()
    (stock_root / "budgets.rego").write_text(
        "# Copyright (c) Microsoft Corporation.\n"
        "# Licensed under the MIT License.\n"
        "package agt.budgets\n",
        encoding="utf-8",
    )
    return stock_root


def _capture_bridge_temp_dirs(
    monkeypatch: pytest.MonkeyPatch,
    temp_root: Path,
) -> list[Path]:
    created: list[Path] = []

    def fake_mkdtemp(
        suffix: str | None = None,
        prefix: str | None = None,
        dir: str | None = None,
    ) -> str:
        del dir
        path = temp_root / f"{prefix or ''}{len(created)}{suffix or ''}"
        path.mkdir(parents=True)
        created.append(path)
        return str(path)

    monkeypatch.setattr(bridge_module.tempfile, "mkdtemp", fake_mkdtemp)
    return created


def test_glob_pattern_to_regex_is_re2_safe() -> None:
    pattern = _pattern_to_regex(("*.txt", PatternType.GLOB))

    assert "\\Z" not in pattern
    assert "\\z" not in pattern
    assert "(?s:" not in pattern
    re.compile(pattern)
    assert re.fullmatch(pattern, "a.txt")
    assert re.fullmatch(pattern, "dir/a.txt")
    assert not re.fullmatch(pattern, "a.tx")
    assert not re.fullmatch(pattern, "a.txt.bak")

    opa = _opa()
    if not opa.exists():
        pytest.skip("opa binary required for RE2 regex validation")

    expression = (
        f"[regex.match({json.dumps(pattern)}, {json.dumps('a.txt')}), "
        f"regex.match({json.dumps(pattern)}, {json.dumps('dir/a.txt')}), "
        f"regex.match({json.dumps(pattern)}, {json.dumps('a.tx')}), "
        f"regex.match({json.dumps(pattern)}, {json.dumps('a.txt.bak')})]"
    )
    completed = subprocess.run(
        [str(opa), "eval", "-f", "values", expression],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(completed.stdout)[0] == [True, True, False, False]


def test_glob_matches_multiline_values_under_opa() -> None:
    # A `*secret*` blocked pattern must match content where the hit is on a
    # non-first line; without (?s) the deny silently fails to fire (fail-open).
    pattern = _pattern_to_regex(("*secret*", PatternType.GLOB))
    assert pattern.startswith("(?s)")

    opa = _opa()
    if not opa.exists():
        pytest.skip("opa binary required for RE2 regex validation")

    multiline = "harmless first line\nembedded secret value\ntrailing"
    expression = (
        f"[regex.match({json.dumps(pattern)}, {json.dumps(multiline)}), "
        f"regex.match({json.dumps(pattern)}, {json.dumps('inline secret')}), "
        f"regex.match({json.dumps(pattern)}, {json.dumps('nothing here')})]"
    )
    completed = subprocess.run(
        [str(opa), "eval", "-f", "values", expression],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(completed.stdout)[0] == [True, True, False]


def test_glob_blocked_pattern_denies_through_generated_rego(tmp_path: Path) -> None:
    opa = _opa()
    if not opa.exists():
        pytest.skip("opa binary required for bridge Rego validation")

    manifest = governance_to_acs_manifest(
        GovernancePolicy(
            blocked_patterns=[("*.txt", PatternType.GLOB)],
            confidence_threshold=0.0,
        ),
        bundle_dir=tmp_path / "bundle",
    )
    bundle = Path(manifest["policies"]["agt_governance_policy"]["bundle"])
    input_path = tmp_path / "input.json"
    input_path.write_text(
        json.dumps({"policy_target": {"value": "a.txt"}}),
        encoding="utf-8",
    )

    completed = subprocess.run(
        [
            str(opa),
            "eval",
            "-f",
            "values",
            "-d",
            str(bundle),
            "-i",
            str(input_path),
            "data.agt.governance_policy.verdict",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    verdict = json.loads(completed.stdout)[0]
    assert verdict["decision"] == "deny"
    assert verdict["reason"] == "blocked_pattern_input"


def test_non_finite_confidence_threshold_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(
        ValueError,
        match=r"confidence_threshold must be finite, got inf",
    ):
        governance_to_acs_manifest(_PolicyFixture(), bundle_dir=tmp_path / "bundle")


def test_self_created_temp_bundle_dir_is_removed_on_render_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    temp_root = tmp_path / "temp-root"
    temp_root.mkdir()
    created = _capture_bridge_temp_dirs(monkeypatch, temp_root)

    with pytest.raises(ValueError, match="pattern value must be a string"):
        governance_to_acs_manifest(
            _CleanupPolicyFixture(blocked_patterns=[(123, "REGEX")]),
            stock_rego_root=_stock_rego_root(tmp_path),
        )

    assert len(created) == 1
    assert not created[0].exists()
    assert list(temp_root.glob("agt_bridge_*")) == []


def test_caller_supplied_bundle_dir_is_not_deleted_on_render_failure(
    tmp_path: Path,
) -> None:
    bundle_dir = tmp_path / "caller-bundle"
    bundle_dir.mkdir()
    sentinel = bundle_dir / "caller-owned.txt"
    sentinel.write_text("keep", encoding="utf-8")

    with pytest.raises(ValueError, match="pattern value must be a string"):
        governance_to_acs_manifest(
            _CleanupPolicyFixture(blocked_patterns=[(123, "REGEX")]),
            bundle_dir=bundle_dir,
            stock_rego_root=_stock_rego_root(tmp_path),
        )

    assert bundle_dir.exists()
    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert (bundle_dir / "budgets.rego").exists()
