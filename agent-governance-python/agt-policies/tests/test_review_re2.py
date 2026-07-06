# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression coverage for RE2 validation and OPA fail-closed handling."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

_PACKAGE_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_PACKAGE_SRC) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_SRC))

from agt._harness import opa_runner  # noqa: E402
from agt.manifest_resolution import ResolutionError, resolve_manifest  # noqa: E402
from agt.manifest_resolution import build as build_module  # noqa: E402
from agt.manifest_resolution.build import (  # noqa: E402
    _rego_op_clause,
    _validate_re2_regex,
)
from agt.policies.bridge import _pattern_to_regex  # noqa: E402


OPA = Path.home() / ".local" / "bin" / "opa"


class _Kind:
    def __init__(self, name: str) -> None:
        self.name = name


def _legacy_binding() -> dict[str, dict[str, Any]]:
    return {
        "pre_tool_call": {
            "policy_target": "$.tool_call.args",
            "policy_target_kind": "tool_args",
            "tool_name_from": "$.tool_call.name",
            "policy": {"id": "agt_legacy_rules"},
        }
    }


def _write_governance(root: Path, condition: dict[str, Any]) -> None:
    (root / "governance.yaml").write_text(
        yaml.safe_dump(
            {
                "rules": [
                    {
                        "name": "deny-invalid-regex",
                        "condition": condition,
                        "action": "deny",
                        "priority": 10,
                    }
                ],
                "intervention_points": _legacy_binding(),
            }
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    "pattern",
    [
        "a++",
        "a*+",
        "a?+",
        "a{2,3}+",
        "(?(1)b|c)",
        "(?P<x>a)(?P=x)",
    ],
)
def test_re2_validator_rejects_python_only_regex_constructs(pattern: str) -> None:
    with pytest.raises(ResolutionError):
        _validate_re2_regex(pattern)


@pytest.mark.parametrize(
    "pattern",
    ["a+", "a*", "a{2,3}", "(?P<x>a)x", "[a+]", "foo.*bar"],
)
def test_re2_validator_allows_re2_safe_regex_constructs(pattern: str) -> None:
    _validate_re2_regex(pattern)


def test_regex_validation_errors_do_not_echo_pattern() -> None:
    with pytest.raises(ResolutionError) as exc:
        _validate_re2_regex("secret-token(?=suffix)")

    # The invalid pattern (which may carry secrets) must not be echoed into the
    # error detail (errors.py no-leak contract).
    assert "secret-token" not in str(exc.value)
    assert "suffix" not in str(exc.value)
    assert "invalid" in str(exc.value).lower() or "not a valid" in str(exc.value).lower()


def test_valid_re2_octal_and_unicode_property_are_accepted() -> None:
    # RE2 supports octal escapes and Unicode-property classes that Python `re`
    # rejects; the faithful google-re2 validator must NOT over-deny these. The
    # conservative fallback (no google-re2 wheel) legitimately cannot, so this
    # property is only asserted when the real RE2 engine is available.
    if build_module._re2 is None:
        pytest.skip("google-re2 not installed; conservative fallback over-denies")
    for pattern in (r"\101", r"\123", r"\p{L}", r"\pL", r"\p{Lu}", r"\p{L}+\d"):
        _validate_re2_regex(pattern)  # must not raise


def test_bridge_regex_kind_uses_shared_re2_validation() -> None:
    with pytest.raises(ResolutionError):
        _pattern_to_regex(("a(?=b)", _Kind("REGEX")))


def test_bridge_glob_character_classes_match_under_opa() -> None:
    if not OPA.exists():
        pytest.skip("opa binary required for RE2 regex validation")

    pattern = _pattern_to_regex(("secret[0-9]*", _Kind("GLOB")))
    negated = _pattern_to_regex(("secret[!0-9]", _Kind("GLOB")))
    slash_pattern = _pattern_to_regex(("*.txt", _Kind("GLOB")))

    expression = (
        "["
        f"regex.match({json.dumps(pattern)}, {json.dumps('secret5')}), "
        f"regex.match({json.dumps(pattern)}, {json.dumps('secretX')}), "
        f"regex.match({json.dumps(negated)}, {json.dumps('secretX')}), "
        f"regex.match({json.dumps(negated)}, {json.dumps('secret5')}), "
        f"regex.match({json.dumps(slash_pattern)}, {json.dumps('a.txt')}), "
        f"regex.match({json.dumps(slash_pattern)}, {json.dumps('a/b.txt')})"
        "]"
    )

    completed = subprocess.run(
        [str(OPA), "eval", "-f", "values", expression],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert json.loads(completed.stdout)[0] == [
        True,
        False,
        True,
        False,
        True,
        True,
    ]


def test_non_finite_condition_values_are_rejected_without_echoing_value() -> None:
    with pytest.raises(ResolutionError) as exc:
        _rego_op_clause("eq", "input.snapshot.value", float("nan"))

    assert "nan" not in exc.value.detail.lower()
    assert "finite JSON primitive" in exc.value.detail
    assert _rego_op_clause("eq", "input.snapshot.value", 1.25)


def test_deny_rule_with_invalid_regex_raises_at_resolve_time(tmp_path: Path) -> None:
    _write_governance(
        tmp_path,
        {"field": "tool_call.args.q", "operator": "matches", "value": "a++"},
    )

    with pytest.raises(ResolutionError):
        resolve_manifest(tmp_path, tmp_path)


def test_opa_strict_builtin_errors_make_invalid_regex_fatal() -> None:
    if not OPA.exists():
        pytest.skip("opa binary required for strict builtin error validation")

    loose = subprocess.run(
        [str(OPA), "eval", "-f", "json", 'regex.match("a++", "aaa")'],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    strict = subprocess.run(
        [
            str(OPA),
            "eval",
            "-f",
            "json",
            "--strict-builtin-errors",
            'regex.match("a++", "aaa")',
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert json.loads(loose.stdout) == {}
    assert strict.returncode != 0
    assert "eval_builtin_error" in strict.stdout


def test_opa_runner_eval_command_enables_strict_builtin_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def resolve_manifest_stub(*_args: object, **_kwargs: object) -> dict[str, Any]:
        return {
            "intervention_points": {
                "pre_prompt": {
                    "policy_target": "$",
                    "policy_target_kind": "user_input",
                    "policy": {"id": "agt_legacy_rules"},
                }
            },
            "policies": {
                "agt_legacy_rules": {
                    "bundle": str(Path.cwd()),
                    "query": "data.agt.legacy.verdict",
                }
            },
        }

    captured: dict[str, list[str]] = {}

    def run_stub(cmd: list[str], **_kwargs: object) -> SimpleNamespace:
        captured["cmd"] = cmd
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {"result": [{"expressions": [{"value": {"decision": "allow"}}]}]}
            ),
            stderr="",
        )

    monkeypatch.setattr(opa_runner.shutil, "which", lambda _name: "/usr/bin/opa")
    monkeypatch.setattr(opa_runner, "_find_stock_rego_root", lambda: Path.cwd())
    monkeypatch.setattr(opa_runner, "resolve_manifest", resolve_manifest_stub)
    monkeypatch.setattr(opa_runner.subprocess, "run", run_stub)

    result = opa_runner.run_scenario(
        workspace_root=Path.cwd(),
        governance_yaml={},
        intervention_point="pre_prompt",
        snapshot={"value": "anything"},
    )

    assert result.is_allow
    assert "--strict-builtin-errors" in captured["cmd"]


def test_materialize_rego_write_failure_preserves_previous_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_rules = [
        {
            "name": "old-rule",
            "condition": {"field": "tool_call.args.q", "operator": "eq", "value": "old"},
            "action": "deny",
        }
    ]
    new_rules = [
        {
            "name": "new-rule",
            "condition": {"field": "tool_call.args.q", "operator": "eq", "value": "new"},
            "action": "deny",
        }
    ]
    build_module._materialize_rego_bundle(tmp_path, old_rules)
    rego_file = tmp_path / "policy" / "agt_legacy.rego"
    sidecar_file = tmp_path / "policy" / "agt_legacy.rego.sha256"
    previous_rego = rego_file.read_text(encoding="utf-8")
    previous_sidecar = sidecar_file.read_text(encoding="utf-8")
    assert previous_sidecar == hashlib.sha256(
        previous_rego.encode("utf-8")
    ).hexdigest()

    original_atomic_write_text = build_module._atomic_write_text

    def fail_rego_write(path: Path, body: str) -> None:
        if path.name == "agt_legacy.rego":
            raise OSError("simulated rego write failure")
        original_atomic_write_text(path, body)

    monkeypatch.setattr(build_module, "_atomic_write_text", fail_rego_write)

    with pytest.raises(ResolutionError):
        build_module._materialize_rego_bundle(tmp_path, new_rules)

    assert rego_file.read_text(encoding="utf-8") == previous_rego
    assert sidecar_file.read_text(encoding="utf-8") == previous_sidecar
    assert "new-rule" not in rego_file.read_text(encoding="utf-8")
