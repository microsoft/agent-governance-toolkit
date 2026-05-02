# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# cspell:words cedarpy startswith
"""
Tests for the AEGIS governance profile compiler.

Three test layers:

* **Structural** — load profiles, validate the compiler rejects bad inputs,
  check the emitted Cedar and Rego contain expected statements / rules /
  identifiers. Always runs.

* **Oracle equivalence** — declare the intended authorization semantics
  once (the AEGIS oracle), sweep a fixed input matrix against both
  profiles, and verify the emitted Cedar and Rego policies encode the
  oracle's decisions. This catches drift between ``compile_to_cedar`` and
  ``compile_to_rego``: if one ever diverges from the profile semantics
  without the other, the matrix sweep fails. Always runs.

* **Integration** — if ``cedarpy`` is importable and / or ``opa`` is on
  ``$PATH``, run the emitted policies through the real engines on the
  same input matrix and verify decision agreement with the oracle. Skipped
  with an informative message when tools are absent — never fails CI for
  unavailable optional dependencies.

The test file deliberately does not import ``agent_os.policies`` or any
other AGT internal module. The compiler emits standalone policy text;
these tests verify that text on its own merits.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

EXAMPLE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(EXAMPLE_DIR))

from compile import (  # noqa: E402  — sys.path insertion above
    Profile,
    ProfileError,
    compile_to_cedar,
    compile_to_rego,
    load_profile,
    snake_to_pascal,
)


PROFILE_PATHS: tuple[Path, ...] = (
    EXAMPLE_DIR / "profile-research-agent.yaml",
    EXAMPLE_DIR / "profile-customer-support-agent.yaml",
)


# ── Fixtures ──────────────────────────────────────────────────


@pytest.fixture(params=PROFILE_PATHS, ids=lambda p: p.stem)
def profile(request: pytest.FixtureRequest) -> Profile:
    return load_profile(request.param)


@pytest.fixture
def cedar_text(profile: Profile) -> str:
    return compile_to_cedar(profile)


@pytest.fixture
def rego_text(profile: Profile) -> str:
    return compile_to_rego(profile)


# ── Loader / validator tests ──────────────────────────────────


class TestLoader:
    def test_loads_research_profile(self) -> None:
        p = load_profile(EXAMPLE_DIR / "profile-research-agent.yaml")
        assert p.metadata.profile_id == "research-agent-standard"
        assert p.principal.role == "researcher"
        assert "web_search" in p.capabilities.allowed_actions
        assert "file_write" in p.capabilities.denied_actions
        assert "public/*" in p.resource_scopes.allowed_patterns
        assert "customer/pii/*" in p.resource_scopes.denied_patterns

    def test_loads_customer_support_profile(self) -> None:
        p = load_profile(EXAMPLE_DIR / "profile-customer-support-agent.yaml")
        assert p.metadata.profile_id == "customer-support-agent-standard"
        assert p.principal.role == "support_agent"
        assert "ticket_update" in p.capabilities.allowed_actions
        assert "billing_modify" in p.capabilities.denied_actions

    def test_rejects_missing_top_level_key(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text('profile:\n  id: x\n  version: "1.0"\n  description: x\n')
        with pytest.raises(ProfileError, match="missing required key 'principal'"):
            load_profile(bad)

    def test_rejects_invalid_yaml(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("profile: [unclosed\n")
        with pytest.raises(ProfileError, match="invalid YAML"):
            load_profile(bad)

    def test_rejects_overlapping_actions(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            "profile:\n"
            "  id: x\n"
            '  version: "1.0"\n'
            "  description: x\n"
            "principal:\n"
            "  role: r\n"
            "capabilities:\n"
            "  allowed_actions: [a]\n"
            "  denied_actions: [a]\n"
            "resource_scopes:\n"
            "  allowed_patterns: ['p/*']\n"
            "  denied_patterns: ['q/*']\n"
        )
        with pytest.raises(ProfileError, match="overlap"):
            load_profile(bad)

    def test_rejects_non_snake_case_action(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            "profile:\n"
            "  id: x\n"
            '  version: "1.0"\n'
            "  description: x\n"
            "principal:\n"
            "  role: r\n"
            "capabilities:\n"
            "  allowed_actions: [WebSearch]\n"
            "  denied_actions: [b]\n"
            "resource_scopes:\n"
            "  allowed_patterns: ['p/*']\n"
            "  denied_patterns: ['q/*']\n"
        )
        with pytest.raises(ProfileError, match="snake_case"):
            load_profile(bad)

    def test_rejects_pattern_without_glob_suffix(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            "profile:\n"
            "  id: x\n"
            '  version: "1.0"\n'
            "  description: x\n"
            "principal:\n"
            "  role: r\n"
            "capabilities:\n"
            "  allowed_actions: [a]\n"
            "  denied_actions: [b]\n"
            "resource_scopes:\n"
            "  allowed_patterns: ['public']\n"
            "  denied_patterns: ['q/*']\n"
        )
        with pytest.raises(ProfileError, match="prefix glob"):
            load_profile(bad)


# ── Helper-function tests ─────────────────────────────────────


class TestSnakeToPascal:
    @pytest.mark.parametrize(
        "snake,pascal",
        [
            ("web_search", "WebSearch"),
            ("file_read", "FileRead"),
            ("send_external_email", "SendExternalEmail"),
            ("a", "A"),
            ("a_b_c", "ABC"),
        ],
    )
    def test_round_trip(self, snake: str, pascal: str) -> None:
        assert snake_to_pascal(snake) == pascal


# ── Cedar structural tests ────────────────────────────────────


class TestCedarStructure:
    def test_header_includes_profile_metadata(
        self, profile: Profile, cedar_text: str
    ) -> None:
        assert profile.metadata.profile_id in cedar_text
        assert profile.metadata.version in cedar_text
        assert "DO NOT EDIT BY HAND" in cedar_text

    def test_each_allowed_action_appears_as_pascal_case(
        self, profile: Profile, cedar_text: str
    ) -> None:
        for action in profile.capabilities.allowed_actions:
            pascal = snake_to_pascal(action)
            assert f'Action::"{pascal}"' in cedar_text, (
                f"missing permit for allowed action {action!r} ({pascal!r})"
            )

    def test_each_denied_action_appears_in_forbid(
        self, profile: Profile, cedar_text: str
    ) -> None:
        statements = _parse_cedar_statements(cedar_text)
        forbidden = _collect_constrained_actions(statements, "forbid")
        for action in profile.capabilities.denied_actions:
            assert snake_to_pascal(action) in forbidden, (
                f"denied action {action!r} missing from any forbid statement"
            )

    def test_each_allowed_pattern_in_permit_when(
        self, profile: Profile, cedar_text: str
    ) -> None:
        permit_when = _extract_when_clause(cedar_text, "permit")
        for pattern in profile.resource_scopes.allowed_patterns:
            assert pattern in permit_when

    def test_each_denied_pattern_in_forbid_when(
        self, profile: Profile, cedar_text: str
    ) -> None:
        forbid_clauses = _extract_all_when_clauses(cedar_text, "forbid")
        joined = "\n".join(forbid_clauses)
        for pattern in profile.resource_scopes.denied_patterns:
            assert pattern in joined

    def test_principal_role_in_permit_when(
        self, profile: Profile, cedar_text: str
    ) -> None:
        permit_when = _extract_when_clause(cedar_text, "permit")
        assert f'context.principal_role == "{profile.principal.role}"' in permit_when

    def test_no_disallowed_constructs(self, cedar_text: str) -> None:
        # Defensive: emitted Cedar should not contain implementation-specific
        # placeholders that would leak from a half-finished change.
        assert "TODO" not in cedar_text
        assert "FIXME" not in cedar_text
        assert "<" not in cedar_text or "<=" in cedar_text  # no template markers


# ── Rego structural tests ─────────────────────────────────────


class TestRegoStructure:
    def test_header_includes_profile_metadata(
        self, profile: Profile, rego_text: str
    ) -> None:
        assert profile.metadata.profile_id in rego_text
        assert profile.metadata.version in rego_text
        assert "DO NOT EDIT BY HAND" in rego_text

    def test_package_declared(self, rego_text: str) -> None:
        assert re.search(r"^package agentos\.aegis$", rego_text, re.MULTILINE)

    def test_default_allow_false(self, rego_text: str) -> None:
        assert re.search(r"^default allow := false$", rego_text, re.MULTILINE)

    def test_imports_rego_v1(self, rego_text: str) -> None:
        assert re.search(r"^import rego\.v1$", rego_text, re.MULTILINE)

    def test_allowed_actions_set_complete(
        self, profile: Profile, rego_text: str
    ) -> None:
        emitted = _extract_rego_set(rego_text, "allowed_actions")
        assert emitted == set(profile.capabilities.allowed_actions)

    def test_denied_actions_set_complete(
        self, profile: Profile, rego_text: str
    ) -> None:
        emitted = _extract_rego_set(rego_text, "denied_actions")
        assert emitted == set(profile.capabilities.denied_actions)

    def test_allowed_resource_patterns_array(
        self, profile: Profile, rego_text: str
    ) -> None:
        emitted = _extract_rego_array(rego_text, "allowed_resource_patterns")
        expected = [p[:-1] for p in profile.resource_scopes.allowed_patterns]
        assert emitted == expected

    def test_denied_resource_patterns_array(
        self, profile: Profile, rego_text: str
    ) -> None:
        emitted = _extract_rego_array(rego_text, "denied_resource_patterns")
        expected = [p[:-1] for p in profile.resource_scopes.denied_patterns]
        assert emitted == expected

    def test_required_rules_present(self, rego_text: str) -> None:
        for rule in (
            "allow if {",
            "in_allowed_scope if {",
            "in_denied_scope if {",
            "in_denied_action if {",
        ):
            assert rule in rego_text, f"missing rule head: {rule!r}"

    def test_principal_role_check_in_allow(
        self, profile: Profile, rego_text: str
    ) -> None:
        assert f'input.principal_role == "{profile.principal.role}"' in rego_text


# ── Determinism ───────────────────────────────────────────────


class TestDeterminism:
    @pytest.mark.parametrize("path", PROFILE_PATHS, ids=lambda p: p.stem)
    def test_cedar_output_is_byte_identical(self, path: Path) -> None:
        a = compile_to_cedar(load_profile(path))
        b = compile_to_cedar(load_profile(path))
        assert a == b

    @pytest.mark.parametrize("path", PROFILE_PATHS, ids=lambda p: p.stem)
    def test_rego_output_is_byte_identical(self, path: Path) -> None:
        a = compile_to_rego(load_profile(path))
        b = compile_to_rego(load_profile(path))
        assert a == b


# ── Oracle equivalence (in-test interpreters) ─────────────────


def _oracle_decision(profile: Profile, request: dict[str, str]) -> bool:
    """The single source of truth for AEGIS profile semantics.

    A request is allowed iff:
      * principal_role matches the profile's role, AND
      * tool_name is in allowed_actions and not in denied_actions, AND
      * resource_path matches an allowed prefix and no denied prefix.

    Cedar and Rego output must agree with this decision on every input.
    """
    if request["principal_role"] != profile.principal.role:
        return False
    if request["tool_name"] not in profile.capabilities.allowed_actions:
        return False
    if request["tool_name"] in profile.capabilities.denied_actions:
        return (
            False  # defensive — load_profile rejects overlap, but oracle is independent
        )
    if not _matches_any(
        request["resource_path"], profile.resource_scopes.allowed_patterns
    ):
        return False
    if _matches_any(request["resource_path"], profile.resource_scopes.denied_patterns):
        return False
    return True


def _matches_any(value: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(value, pat) for pat in patterns)


def _build_input_matrix(profile: Profile) -> list[dict[str, str]]:
    """Cross product of role / action / resource_path covering edge cases."""
    roles = [profile.principal.role, "intruder", "admin"]
    actions = (
        list(profile.capabilities.allowed_actions[:2])
        + list(profile.capabilities.denied_actions[:2])
        + ["unknown_action"]
    )
    paths = [
        profile.resource_scopes.allowed_patterns[0].replace("*", "doc-1"),
        profile.resource_scopes.denied_patterns[0].replace("*", "doc-2"),
        "unscoped/zone/doc-3",
    ]
    matrix: list[dict[str, str]] = []
    for role in roles:
        for action in actions:
            for path in paths:
                matrix.append(
                    {
                        "principal_role": role,
                        "tool_name": action,
                        "resource_path": path,
                    }
                )
    return matrix


# ── Cedar simulator (subset matching our emitted shape) ───────


def _cedar_decide(cedar_text: str, request: dict[str, str]) -> bool:
    """Simulate Cedar's `default deny; forbid overrides permit` semantics
    against the specific shape compile.py emits.

    Supports:
      * permit / forbid blocks with `action in [Action::"X", ...]` constraints
      * `when` clauses combining `context.field == "value"`,
        `context.field like "pattern"`, `&&`, `||`, parentheses
    """
    statements = _parse_cedar_statements(cedar_text)
    cedar_action = snake_to_pascal(request["tool_name"])
    has_permit = False
    for stmt in statements:
        if stmt.actions and cedar_action not in stmt.actions:
            continue
        if not _eval_cedar_condition(stmt.when, request):
            continue
        if stmt.effect == "forbid":
            return False
        has_permit = True
    return has_permit


class _CedarStatement:
    __slots__ = ("effect", "actions", "when")

    def __init__(self, effect: str, actions: tuple[str, ...] | None, when: str) -> None:
        self.effect = effect
        self.actions = actions  # None means "any action"
        self.when = when  # may be empty


def _parse_cedar_statements(cedar_text: str) -> list[_CedarStatement]:
    body = re.sub(r"//[^\n]*", "", cedar_text)  # strip comments
    pattern = re.compile(
        r"(permit|forbid)\s*\((.*?)\)\s*(when\s*\{(.*?)\}\s*)?;",
        re.DOTALL,
    )
    out: list[_CedarStatement] = []
    for match in pattern.finditer(body):
        effect = match.group(1)
        head = match.group(2)
        when = (match.group(4) or "").strip()
        actions = _parse_cedar_action_constraint(head)
        out.append(_CedarStatement(effect=effect, actions=actions, when=when))
    return out


def _parse_cedar_action_constraint(head: str) -> tuple[str, ...] | None:
    """Extract Action::"X" identifiers from a permit/forbid head, or None for catch-all."""
    in_match = re.search(r"action\s+in\s*\[(.*?)\]", head, re.DOTALL)
    if in_match:
        return tuple(re.findall(r'Action::"([^"]+)"', in_match.group(1)))
    eq_match = re.search(r'action\s*==\s*Action::"([^"]+)"', head)
    if eq_match:
        return (eq_match.group(1),)
    if re.search(r"\baction\b", head):
        return None  # catch-all
    return None


def _eval_cedar_condition(condition: str, request: dict[str, str]) -> bool:
    if not condition.strip():
        return True
    return _eval_or(condition.strip(), request)


def _eval_or(expr: str, request: dict[str, str]) -> bool:
    parts = _split_top_level(expr, "||")
    return any(_eval_and(p, request) for p in parts)


def _eval_and(expr: str, request: dict[str, str]) -> bool:
    parts = _split_top_level(expr, "&&")
    return all(_eval_atom(p, request) for p in parts)


def _eval_atom(expr: str, request: dict[str, str]) -> bool:
    expr = expr.strip()
    while expr.startswith("(") and expr.endswith(")") and _balanced(expr[1:-1]):
        expr = expr[1:-1].strip()
    # After unwrapping, the expression may still be a compound — recurse.
    if _split_top_level(expr, "||") != [expr]:
        return _eval_or(expr, request)
    if _split_top_level(expr, "&&") != [expr]:
        return _eval_and(expr, request)
    eq_match = re.fullmatch(r'context\.(\w+)\s*==\s*"([^"]+)"', expr, re.DOTALL)
    if eq_match:
        field, value = eq_match.group(1), eq_match.group(2)
        return request.get(field, "") == value
    like_match = re.fullmatch(r'context\.(\w+)\s+like\s+"([^"]+)"', expr, re.DOTALL)
    if like_match:
        field, pattern = like_match.group(1), like_match.group(2)
        return fnmatch.fnmatchcase(request.get(field, ""), pattern)
    raise AssertionError(f"unsupported Cedar atom: {expr!r}")


def _split_top_level(expr: str, op: str) -> list[str]:
    out: list[str] = []
    depth = 0
    last = 0
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0 and expr[i : i + len(op)] == op:
            out.append(expr[last:i].strip())
            last = i + len(op)
            i += len(op)
            continue
        i += 1
    tail = expr[last:].strip()
    if tail:
        out.append(tail)
    return out or [expr.strip()]


def _balanced(expr: str) -> bool:
    depth = 0
    for ch in expr:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


# ── Rego simulator (subset matching our emitted shape) ────────


def _rego_decide(rego_text: str, request: dict[str, str]) -> bool:
    """Simulate the emitted Rego allow rule against a request.

    The emitted Rego is a fixed shape:
      allow {
          input.principal_role == "<role>"
          allowed_actions[input.tool_name]
          in_allowed_scope
          not in_denied_action
          not in_denied_scope
      }
    plus the four supporting rules. We re-implement the membership and
    prefix checks in Python against the request.
    """
    role_match = re.search(r'input\.principal_role\s*==\s*"([^"]+)"', rego_text)
    assert role_match, "expected principal_role check in emitted Rego"
    expected_role = role_match.group(1)
    if request["principal_role"] != expected_role:
        return False

    allowed = _extract_rego_set(rego_text, "allowed_actions")
    denied = _extract_rego_set(rego_text, "denied_actions")
    allowed_prefixes = _extract_rego_array(rego_text, "allowed_resource_patterns")
    denied_prefixes = _extract_rego_array(rego_text, "denied_resource_patterns")

    if request["tool_name"] in denied:
        return False
    if request["tool_name"] not in allowed:
        return False
    if any(request["resource_path"].startswith(p) for p in denied_prefixes):
        return False
    if not any(request["resource_path"].startswith(p) for p in allowed_prefixes):
        return False
    return True


def _extract_rego_set(rego_text: str, name: str) -> set[str]:
    match = re.search(rf"{re.escape(name)}\s*:=\s*\{{(.*?)\}}", rego_text, re.DOTALL)
    assert match, f"missing Rego set: {name}"
    return set(re.findall(r'"([^"]+)"', match.group(1)))


def _extract_rego_array(rego_text: str, name: str) -> list[str]:
    match = re.search(rf"{re.escape(name)}\s*:=\s*\[(.*?)\]", rego_text, re.DOTALL)
    assert match, f"missing Rego array: {name}"
    return re.findall(r'"([^"]+)"', match.group(1))


def _collect_constrained_actions(
    statements: list[_CedarStatement], effect: str
) -> set[str]:
    out: set[str] = set()
    for stmt in statements:
        if stmt.effect == effect and stmt.actions:
            out.update(stmt.actions)
    return out


def _extract_when_clause(cedar_text: str, effect: str) -> str:
    statements = _parse_cedar_statements(cedar_text)
    for stmt in statements:
        if stmt.effect == effect and stmt.when:
            return stmt.when
    raise AssertionError(f"no {effect} statement with when clause")


def _extract_all_when_clauses(cedar_text: str, effect: str) -> list[str]:
    return [
        s.when
        for s in _parse_cedar_statements(cedar_text)
        if s.effect == effect and s.when
    ]


# ── Oracle equivalence tests ──────────────────────────────────


class TestOracleEquivalence:
    """Both emitted policies must agree with the oracle on every input."""

    @pytest.mark.parametrize("path", PROFILE_PATHS, ids=lambda p: p.stem)
    def test_cedar_matches_oracle(self, path: Path) -> None:
        prof = load_profile(path)
        cedar_text = compile_to_cedar(prof)
        for request in _build_input_matrix(prof):
            expected = _oracle_decision(prof, request)
            actual = _cedar_decide(cedar_text, request)
            assert actual == expected, (
                f"Cedar disagreed with oracle for {request}: "
                f"oracle={expected}, cedar={actual}"
            )

    @pytest.mark.parametrize("path", PROFILE_PATHS, ids=lambda p: p.stem)
    def test_rego_matches_oracle(self, path: Path) -> None:
        prof = load_profile(path)
        rego_text = compile_to_rego(prof)
        for request in _build_input_matrix(prof):
            expected = _oracle_decision(prof, request)
            actual = _rego_decide(rego_text, request)
            assert actual == expected, (
                f"Rego disagreed with oracle for {request}: "
                f"oracle={expected}, rego={actual}"
            )

    @pytest.mark.parametrize("path", PROFILE_PATHS, ids=lambda p: p.stem)
    def test_cedar_and_rego_agree(self, path: Path) -> None:
        prof = load_profile(path)
        cedar_text = compile_to_cedar(prof)
        rego_text = compile_to_rego(prof)
        for request in _build_input_matrix(prof):
            cedar = _cedar_decide(cedar_text, request)
            rego = _rego_decide(rego_text, request)
            assert cedar == rego, (
                f"Cedar/Rego disagreed for {request}: cedar={cedar}, rego={rego}"
            )


# ── Integration: real Cedar engine (cedarpy) ──────────────────


def _cedarpy_available() -> bool:
    try:
        import cedarpy  # noqa: F401

        return True
    except ImportError:
        return False


@pytest.mark.skipif(
    not _cedarpy_available(),
    reason="cedarpy not installed (optional integration test)",
)
class TestCedarPyIntegration:
    """If cedarpy is installed, run emitted Cedar through it."""

    @pytest.mark.parametrize("path", PROFILE_PATHS, ids=lambda p: p.stem)
    def test_cedarpy_agrees_with_oracle(self, path: Path) -> None:
        import cedarpy

        prof = load_profile(path)
        cedar_text = compile_to_cedar(prof)
        for request in _build_input_matrix(prof):
            expected = _oracle_decision(prof, request)
            cedar_request = {
                "principal": f'Agent::"{request["principal_role"]}-agent"',
                "action": f'Action::"{snake_to_pascal(request["tool_name"])}"',
                "resource": 'Resource::"placeholder"',
                "context": {
                    "principal_role": request["principal_role"],
                    "resource_path": request["resource_path"],
                },
            }
            response = cedarpy.is_authorized(cedar_request, cedar_text, entities=[])
            actual = response.decision == cedarpy.Decision.Allow
            assert actual == expected, (
                f"cedarpy disagreed with oracle for {request}: "
                f"oracle={expected}, cedarpy={actual}, "
                f"diagnostics={response.diagnostics}"
            )


# ── Integration: real OPA engine (opa CLI) ────────────────────


def _opa_available() -> bool:
    return shutil.which("opa") is not None and (
        os.environ.get("AEGIS_PROFILE_SKIP_OPA") != "1"
    )


@pytest.mark.skipif(
    not _opa_available(),
    reason="opa CLI not on PATH (optional integration test)",
)
class TestOPAIntegration:
    """If `opa` is on PATH, run emitted Rego through it."""

    @pytest.mark.parametrize("path", PROFILE_PATHS, ids=lambda p: p.stem)
    def test_opa_agrees_with_oracle(self, path: Path, tmp_path: Path) -> None:
        prof = load_profile(path)
        rego_text = compile_to_rego(prof)
        rego_file = tmp_path / "policy.rego"
        rego_file.write_text(rego_text, encoding="utf-8")

        for request in _build_input_matrix(prof):
            expected = _oracle_decision(prof, request)
            actual = _opa_eval(rego_file, request)
            assert actual == expected, (
                f"opa disagreed with oracle for {request}: "
                f"oracle={expected}, opa={actual}"
            )


def _opa_eval(rego_file: Path, request: dict[str, str]) -> bool:
    # Run from rego_file's directory so we pass a basename — avoids opa.exe's
    # Windows arg-handling quirk that mangles paths containing a drive letter.
    proc = subprocess.run(  # noqa: S603 — trusted: opa is opted-in via PATH presence
        [
            "opa",
            "eval",
            "--format",
            "json",
            "--stdin-input",
            "--data",
            rego_file.name,
            "data.agentos.aegis.allow",
        ],
        input=json.dumps(request),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        cwd=rego_file.parent,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"opa eval failed (exit {proc.returncode}): "
            f"stderr={proc.stderr.strip()!r} stdout={proc.stdout.strip()!r}"
        )
    payload: dict[str, Any] = json.loads(proc.stdout)
    expressions = payload["result"][0]["expressions"]
    value = expressions[0]["value"] if expressions else False
    return bool(value)
