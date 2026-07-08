# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for manifest_resolution.build: fail-closed rendering, RE2 validation, atomic IO."""

from __future__ import annotations

from datetime import date
import json
import subprocess
from pathlib import Path
from typing import Any
import pytest
import yaml
import hashlib
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agt.manifest_resolution import ResolutionError, ResolutionReason, resolve_manifest  # noqa: E402
from agt._harness import opa_runner  # noqa: E402
from agt.manifest_resolution import build  # noqa: E402
from agt.manifest_resolution.build import (
    _rego_op_clause,
    _validate_re2_regex,
)  # noqa: E402
from agt.policies.bridge import _pattern_to_regex  # noqa: E402


OPA = Path.home() / ".local" / "bin" / "opa"


def _legacy_binding() -> dict[str, dict[str, Any]]:
    return {
        "pre_tool_call": {
            "policy_target": "$.tool_call.args",
            "policy_target_kind": "tool_args",
            "tool_name_from": "$.tool_call.name",
            "policy": {"id": "agt_legacy_rules"},
        }
    }


def _rule_with_condition(name: str, condition: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "condition": condition,
        "action": "deny",
        "priority": 10,
        "message": "blocked",
    }


def _write_rules_governance(root: Path, rules: list[dict[str, Any]]) -> None:
    (root / "governance.yaml").write_text(
        yaml.safe_dump(
            {
                "rules": rules,
                "intervention_points": _legacy_binding(),
            }
        ),
        encoding="utf-8",
    )


def _assert_invalid_governance(exc: pytest.ExceptionInfo[ResolutionError]) -> None:
    assert exc.value.reason == ResolutionReason.INVALID_GOVERNANCE


def _deny_rule() -> dict[str, Any]:
    return {
        "name": "deny-bash",
        "condition": {"field": "tool_name", "operator": "eq", "value": "bash"},
        "action": "deny",
        "priority": 10,
        "message": "blocked",
    }


def _write_deny_governance(
    root: Path,
    rules: list[dict[str, Any]],
    intervention_points: dict[str, Any] | None,
) -> None:
    doc: dict[str, Any] = {"rules": rules}
    if intervention_points is not None:
        doc["intervention_points"] = intervention_points
    (root / "governance.yaml").write_text(
        yaml.safe_dump(doc),
        encoding="utf-8",
    )


class _Kind:
    def __init__(self, name: str) -> None:
        self.name = name


def _write_condition_governance(root: Path, condition: dict[str, Any]) -> None:
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


def test_regex_lookbehind_rejected_before_render(tmp_path: Path) -> None:
    root = tmp_path
    _write_rules_governance(
        root,
        [
            _rule_with_condition(
                "bad-regex",
                {"field": "tool_call.args.q", "operator": "matches", "value": "(?<=a)b"},
            )
        ],
    )

    with pytest.raises(ResolutionError) as exc:
        resolve_manifest(root, root)

    _assert_invalid_governance(exc)


def test_opa_treats_python_valid_lookbehind_as_undefined() -> None:
    if not OPA.exists():
        pytest.skip("OPA binary not available at /home/liamcrumm/.local/bin/opa")

    proc = subprocess.run(  # noqa: S603 — trusted checked-in test harness
        [str(OPA), "eval", "-f", "json", 'regex.match("(?<=a)b", "ab")'],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert json.loads(proc.stdout) == {}


def test_unknown_operator_rejected_before_render(tmp_path: Path) -> None:
    root = tmp_path
    _write_rules_governance(
        root,
        [
            _rule_with_condition(
                "unknown-op",
                {"field": "tool_call.args.q", "operator": "glob", "value": "secret*"},
            )
        ],
    )

    with pytest.raises(ResolutionError) as exc:
        resolve_manifest(root, root)

    _assert_invalid_governance(exc)


def test_date_condition_value_raises_resolution_error_not_type_error(tmp_path: Path) -> None:
    root = tmp_path
    _write_rules_governance(
        root,
        [
            _rule_with_condition(
                "date-value",
                {"field": "tool_call.args.q", "operator": "eq", "value": date(2026, 7, 2)},
            )
        ],
    )

    with pytest.raises(ResolutionError) as exc:
        resolve_manifest(root, root)

    _assert_invalid_governance(exc)


def test_valid_regex_deny_rule_renders_and_denies_with_opa(tmp_path: Path) -> None:
    root = tmp_path
    _write_rules_governance(
        root,
        [
            _rule_with_condition(
                "valid-regex",
                {"field": "tool_call.args.q", "operator": "regex", "value": "sec.*"},
            )
        ],
    )

    manifest = resolve_manifest(root, root)
    bundle = Path(manifest["policies"]["agt_legacy_rules"]["bundle"])
    rego = (bundle / "agt_legacy.rego").read_text(encoding="utf-8")
    assert 'regex.match("sec.*", _v)' in rego

    if not OPA.exists():
        pytest.skip("OPA binary not available at /home/liamcrumm/.local/bin/opa")

    policy_input = {"snapshot": {"tool_call": {"args": {"q": "secret"}}}}
    proc = subprocess.run(  # noqa: S603 — trusted checked-in test harness
        [
            str(OPA),
            "eval",
            "--format",
            "json",
            "--stdin-input",
            "--data",
            str(bundle),
            "data.agt.legacy.verdict",
        ],
        input=json.dumps(policy_input),
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )

    body = json.loads(proc.stdout)
    verdict = body["result"][0]["expressions"][0]["value"]
    assert verdict["decision"] == "deny"
    assert verdict["reason"] == "valid-regex"


def test_load_yaml_wraps_os_errors(tmp_path: Path) -> None:
    with pytest.raises(ResolutionError) as exc:
        build._load_yaml(tmp_path)

    _assert_invalid_governance(exc)
    assert "failed to read/parse" in exc.value.detail


def test_load_yaml_wraps_unicode_decode_errors(tmp_path: Path) -> None:
    governance = tmp_path / "governance.yaml"
    governance.write_bytes(b"\xff\xfe\x80")

    with pytest.raises(ResolutionError) as exc:
        build._load_yaml(governance)

    _assert_invalid_governance(exc)
    assert "failed to read/parse" in exc.value.detail


def test_materialize_rego_bundle_wraps_replace_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_replace(source: str | Path, destination: str | Path) -> None:
        raise OSError(f"cannot replace {source} -> {destination}")

    monkeypatch.setattr(os, "replace", raise_replace)

    with pytest.raises(ResolutionError) as exc:
        build._materialize_rego_bundle(tmp_path / "bundle", [_deny_rule()])

    _assert_invalid_governance(exc)
    assert "failed to materialize bundle in" in exc.value.detail


def test_materialize_rego_bundle_writes_matching_sha256(tmp_path: Path) -> None:
    policy_dir = build._materialize_rego_bundle(tmp_path / "bundle", [_deny_rule()])

    rego_file = policy_dir / "agt_legacy.rego"
    sidecar = policy_dir / "agt_legacy.rego.sha256"

    assert rego_file.is_file()
    assert sidecar.is_file()

    body = rego_file.read_text(encoding="utf-8")
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    assert sidecar.read_text(encoding="utf-8") == digest


def test_resolve_manifest_defers_bundle_creation_until_binding_validated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    _write_deny_governance(root, [_deny_rule()], intervention_points=None)
    created_dirs: list[Path] = []

    def fake_mkdtemp(prefix: str) -> str:
        path = tmp_path / f"{prefix}{len(created_dirs)}"
        path.mkdir()
        created_dirs.append(path)
        return str(path)

    monkeypatch.setattr(build.tempfile, "mkdtemp", fake_mkdtemp)

    with pytest.raises(ResolutionError) as exc:
        build.resolve_manifest(root, root)

    _assert_invalid_governance(exc)
    assert created_dirs == []
    assert not list(tmp_path.glob("agt_resolved_bundle_*"))


def test_resolve_manifest_removes_owned_bundle_when_materialize_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    _write_deny_governance(root, [_deny_rule()], intervention_points=_legacy_binding())
    created_dirs: list[Path] = []

    def fake_mkdtemp(prefix: str) -> str:
        path = tmp_path / f"{prefix}{len(created_dirs)}"
        path.mkdir()
        created_dirs.append(path)
        return str(path)

    def raise_materialize(bundle_root: Path, rules: list[dict[str, Any]]) -> Path:
        assert rules == [_deny_rule()]
        partial = bundle_root / "policy"
        partial.mkdir(parents=True)
        (partial / "partial.txt").write_text("partial\n", encoding="utf-8")
        raise ResolutionError.invalid_governance("materialization failed")

    monkeypatch.setattr(build.tempfile, "mkdtemp", fake_mkdtemp)
    monkeypatch.setattr(build, "_materialize_rego_bundle", raise_materialize)

    with pytest.raises(ResolutionError) as exc:
        build.resolve_manifest(root, root)

    _assert_invalid_governance(exc)
    assert created_dirs
    assert not created_dirs[0].exists()


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
    if build._re2 is None:
        pytest.skip("google-re2 not installed; conservative fallback over-denies")
    for pattern in (r"\101", r"\123", r"\p{L}", r"\pL", r"\p{Lu}", r"\p{L}+\d"):
        _validate_re2_regex(pattern)


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
    _write_condition_governance(
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
    build._materialize_rego_bundle(tmp_path, old_rules)
    rego_file = tmp_path / "policy" / "agt_legacy.rego"
    sidecar_file = tmp_path / "policy" / "agt_legacy.rego.sha256"
    previous_rego = rego_file.read_text(encoding="utf-8")
    previous_sidecar = sidecar_file.read_text(encoding="utf-8")
    assert previous_sidecar == hashlib.sha256(
        previous_rego.encode("utf-8")
    ).hexdigest()

    original_atomic_write_text = build._atomic_write_text

    def fail_rego_write(path: Path, body: str) -> None:
        if path.name == "agt_legacy.rego":
            raise OSError("simulated rego write failure")
        original_atomic_write_text(path, body)

    monkeypatch.setattr(build, "_atomic_write_text", fail_rego_write)

    with pytest.raises(ResolutionError):
        build._materialize_rego_bundle(tmp_path, new_rules)

    assert rego_file.read_text(encoding="utf-8") == previous_rego
    assert sidecar_file.read_text(encoding="utf-8") == previous_sidecar
    assert "new-rule" not in rego_file.read_text(encoding="utf-8")
