# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the policy linter (GitHub issue #404)."""

from __future__ import annotations

import json
import sys
import textwrap

import pytest

from agent_compliance.lint_policy import (
    KNOWN_ACTIONS,
    KNOWN_OPERATORS,
    LintMessage,
    LintResult,
    lint_file,
    lint_path,
)
from agent_compliance.cli.main import main


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_policy(tmp_path, content: str, name: str = "policy.yaml"):
    """Write *content* to a YAML file and return its Path."""
    p = tmp_path / name
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


def run_cli(*args: str) -> int:
    """Run the CLI with the given arguments and return the exit code."""
    old_argv = sys.argv
    sys.argv = ["agent-compliance", *args]
    try:
        return main()
    finally:
        sys.argv = old_argv


# ---------------------------------------------------------------------------
# LintMessage / LintResult unit tests
# ---------------------------------------------------------------------------


class TestLintMessage:
    def test_str_format(self):
        msg = LintMessage("error", "bad thing", "policy.yaml", 5)
        assert str(msg) == "policy.yaml:5: error: bad thing"

    def test_to_dict(self):
        msg = LintMessage("warning", "hmm", "f.yaml", 3)
        d = msg.to_dict()
        assert d == {
            "severity": "warning",
            "message": "hmm",
            "file": "f.yaml",
            "line": 3,
        }


class TestLintResult:
    def test_passed_when_no_errors(self):
        r = LintResult(
            messages=[LintMessage("warning", "w", "f.yaml", 1)]
        )
        assert r.passed is True

    def test_failed_when_errors(self):
        r = LintResult(
            messages=[LintMessage("error", "e", "f.yaml", 1)]
        )
        assert r.passed is False

    def test_summary_no_issues(self):
        assert "No issues" in LintResult().summary()

    def test_summary_with_issues(self):
        r = LintResult(
            messages=[
                LintMessage("error", "e", "f.yaml", 1),
                LintMessage("warning", "w", "f.yaml", 2),
            ]
        )
        s = r.summary()
        assert "1 error(s)" in s
        assert "1 warning(s)" in s

    def test_to_dict(self):
        r = LintResult(
            messages=[LintMessage("error", "e", "f.yaml", 1)]
        )
        d = r.to_dict()
        assert d["passed"] is False
        assert d["errors"] == 1
        assert len(d["messages"]) == 1


# ---------------------------------------------------------------------------
# lint_file tests
# ---------------------------------------------------------------------------


class TestLintFileValid:
    """A fully valid policy file should produce no messages."""

    def test_valid_policy_no_messages(self, tmp_path):
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: test-policy
            rules:
              - name: allow-read
                condition:
                  field: tool_name
                  operator: eq
                  value: read_file
                action: allow
                priority: 10
        """)
        result = lint_file(p)
        assert result.passed
        assert result.messages == []


class TestLintFileMissingFields:
    def test_missing_version(self, tmp_path):
        p = _write_policy(tmp_path, """\
            name: test
            rules: []
        """)
        result = lint_file(p)
        msgs = [m for m in result.errors if "'version'" in m.message]
        assert len(msgs) == 1

    def test_missing_name(self, tmp_path):
        p = _write_policy(tmp_path, """\
            version: "1.0"
            rules: []
        """)
        result = lint_file(p)
        msgs = [m for m in result.errors if "'name'" in m.message]
        assert len(msgs) == 1

    def test_missing_rules(self, tmp_path):
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: test
        """)
        result = lint_file(p)
        msgs = [m for m in result.errors if "'rules'" in m.message]
        assert len(msgs) == 1


class TestLintFileEmptyRules:
    def test_empty_rules_warning(self, tmp_path):
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: test
            rules: []
        """)
        result = lint_file(p)
        assert result.passed  # warning only
        assert any("empty" in m.message.lower() for m in result.warnings)


class TestLintFileUnknownOperator:
    def test_unknown_operator_error(self, tmp_path):
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: test
            rules:
              - name: bad-op
                condition:
                  field: tool_name
                  operator: fuzzy_match
                  value: foo
                action: allow
        """)
        result = lint_file(p)
        assert not result.passed
        assert any("fuzzy_match" in m.message for m in result.errors)


class TestLintFileUnknownAction:
    def test_unknown_action_error(self, tmp_path):
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: test
            rules:
              - name: bad-action
                condition:
                  field: tool_name
                  operator: eq
                  value: foo
                action: quarantine
        """)
        result = lint_file(p)
        assert not result.passed
        assert any("quarantine" in m.message for m in result.errors)


class TestLintFileConflictingRules:
    def test_allow_deny_same_condition(self, tmp_path):
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: test
            rules:
              - name: allow-read
                condition:
                  field: tool_name
                  operator: eq
                  value: read_file
                action: allow
              - name: deny-read
                condition:
                  field: tool_name
                  operator: eq
                  value: read_file
                action: deny
        """)
        result = lint_file(p)
        assert any("conflicts" in m.message.lower() for m in result.warnings)

    def test_third_rule_against_same_key_not_silently_swallowed(self, tmp_path):
        """Regression: previously seen[key] = action only when no
        prior action existed. Once the first conflict was reported,
        further rules against the same key were compared only against
        the FIRST action and never recorded themselves, so the third
        rule and beyond were silently dropped from conflict reporting.
        Fix: track every (rule_name, action) seen for a key.
        """
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: test
            rules:
              - name: rule-a
                condition: {field: tool_name, operator: eq, value: read_file}
                action: allow
              - name: rule-b
                condition: {field: tool_name, operator: eq, value: read_file}
                action: deny
              - name: rule-c
                condition: {field: tool_name, operator: eq, value: read_file}
                action: allow
        """)
        result = lint_file(p)
        conflict_msgs = [m for m in result.warnings if "conflicts" in m.message.lower()]
        # rule-b conflicts with rule-a; rule-c conflicts with rule-b.
        # Both must surface — not just the first.
        assert any("rule-b" in m.message and "rule-a" in m.message for m in conflict_msgs)
        assert any("rule-c" in m.message and "rule-b" in m.message for m in conflict_msgs)

    def test_canonical_value_form_collapses_equivalent_dicts(self, tmp_path):
        """Two conditions that differ only in dict key order in the
        ``value`` field should be treated as equivalent for conflict
        detection — JSON-canonical form collapses them.
        """
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: test
            rules:
              - name: allow-x
                condition:
                  field: metadata
                  operator: eq
                  value: {a: 1, b: 2}
                action: allow
              - name: deny-x
                condition:
                  field: metadata
                  operator: eq
                  value: {b: 2, a: 1}
                action: deny
        """)
        result = lint_file(p)
        assert any("conflicts" in m.message.lower() for m in result.warnings)

    def test_int_vs_string_value_distinguished(self, tmp_path):
        """A condition on the integer 1 vs the string "1" should NOT
        conflict — JSON-canonical form preserves the type distinction
        that the prior str() approach erased.
        """
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: test
            rules:
              - name: allow-int
                condition: {field: count, operator: eq, value: 1}
                action: allow
              - name: deny-string
                condition: {field: count, operator: eq, value: "1"}
                action: deny
        """)
        result = lint_file(p)
        assert not any("conflicts" in m.message.lower() for m in result.warnings)


class TestLintFileDeprecatedFields:
    def test_deprecated_top_level(self, tmp_path):
        p = _write_policy(tmp_path, """\
            version: "1.0"
            policy_name: test
            name: test
            rules: []
        """)
        result = lint_file(p)
        assert any(
            "policy_name" in m.message and "deprecated" in m.message.lower()
            for m in result.warnings
        )

    def test_deprecated_field_in_rule(self, tmp_path):
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: test
            rules:
              - name: r1
                type: allow
                action: allow
                condition:
                  field: tool_name
                  operator: eq
                  value: foo
        """)
        result = lint_file(p)
        assert any(
            "'type'" in m.message and "deprecated" in m.message.lower()
            for m in result.warnings
        )

    def test_deprecated_op_in_condition(self, tmp_path):
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: test
            rules:
              - name: r1
                action: allow
                condition:
                  field: tool_name
                  op: eq
                  operator: eq
                  value: foo
        """)
        result = lint_file(p)
        assert any(
            "'op'" in m.message and "deprecated" in m.message.lower()
            for m in result.warnings
        )


class TestLintFileInvalidPriority:
    def test_string_priority(self, tmp_path):
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: test
            rules:
              - name: r1
                condition:
                  field: tool_name
                  operator: eq
                  value: foo
                action: allow
                priority: "high"
        """)
        result = lint_file(p)
        assert not result.passed
        assert any("priority" in m.message.lower() for m in result.errors)


class TestLintFileInvalidYaml:
    def test_malformed_yaml(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text("  :\n  - :\n    bad: [", encoding="utf-8")
        result = lint_file(p)
        assert not result.passed
        assert any("Invalid YAML" in m.message for m in result.errors)


class TestLintFileNonMapping:
    def test_yaml_list_at_root(self, tmp_path):
        p = _write_policy(tmp_path, """\
            - item1
            - item2
        """)
        result = lint_file(p)
        assert not result.passed
        assert any("mapping" in m.message.lower() for m in result.errors)


class TestLintFileNotReadable:
    def test_nonexistent_file(self, tmp_path):
        p = tmp_path / "does_not_exist.yaml"
        result = lint_file(p)
        assert not result.passed
        assert any("Cannot read" in m.message for m in result.errors)


class TestLintFileSharedConditions:
    """PolicyDocument uses 'condition' (singular), SharedPolicySchema uses
    'conditions' (plural list). The linter should handle both."""

    def test_conditions_list_unknown_operator(self, tmp_path):
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: test
            rules:
              - name: r1
                conditions:
                  - field: tool_name
                    operator: nope
                    value: foo
                action: allow
        """)
        result = lint_file(p)
        assert not result.passed
        assert any("nope" in m.message for m in result.errors)


# ---------------------------------------------------------------------------
# lint_path tests
# ---------------------------------------------------------------------------


class TestLintPath:
    def test_lint_directory(self, tmp_path):
        _write_policy(tmp_path, """\
            version: "1.0"
            name: p1
            rules: []
        """, "a.yaml")
        _write_policy(tmp_path, """\
            version: "1.0"
            name: p2
            rules: []
        """, "b.yml")
        result = lint_path(tmp_path)
        # Both files produce an "empty rules" warning
        assert len(result.warnings) == 2

    def test_lint_directory_no_yaml(self, tmp_path):
        result = lint_path(tmp_path)
        assert any("No YAML" in m.message for m in result.warnings)

    def test_lint_nonexistent_path(self, tmp_path):
        result = lint_path(tmp_path / "nope")
        assert not result.passed

    def test_lint_single_file(self, tmp_path):
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: ok
            rules:
              - name: r1
                condition:
                  field: tool_name
                  operator: eq
                  value: x
                action: allow
        """)
        result = lint_path(p)
        assert result.passed


# ---------------------------------------------------------------------------
# CLI integration tests
# ---------------------------------------------------------------------------


class TestLintPolicyCLI:
    def test_lint_clean_exit_0(self, tmp_path):
        _write_policy(tmp_path, """\
            version: "1.0"
            name: ok
            rules:
              - name: r1
                condition:
                  field: tool_name
                  operator: eq
                  value: x
                action: allow
        """)
        rc = run_cli("lint-policy", str(tmp_path))
        assert rc == 0

    def test_lint_errors_exit_1(self, tmp_path):
        p = _write_policy(tmp_path, """\
            name: bad
        """)
        rc = run_cli("lint-policy", str(p))
        assert rc == 1

    def test_lint_json_output(self, tmp_path, capsys):
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: test
            rules: []
        """)
        run_cli("lint-policy", "--json", str(p))
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert "passed" in parsed
        assert "messages" in parsed

    def test_lint_strict_warnings_exit_1(self, tmp_path):
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: test
            rules: []
        """)
        rc = run_cli("lint-policy", "--strict", str(p))
        assert rc == 1  # empty rules warning triggers failure

    def test_lint_strict_clean_exit_0(self, tmp_path):
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: ok
            rules:
              - name: r1
                condition:
                  field: tool_name
                  operator: eq
                  value: x
                action: allow
        """)
        rc = run_cli("lint-policy", "--strict", str(p))
        assert rc == 0

    def test_lint_human_output(self, tmp_path, capsys):
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: test
            rules:
              - name: bad-op
                condition:
                  field: x
                  operator: nope
                  value: y
                action: allow
        """)
        run_cli("lint-policy", str(p))
        captured = capsys.readouterr()
        assert "nope" in captured.out
        assert "error" in captured.out

    def test_lint_nonexistent_path(self, tmp_path, capsys):
        rc = run_cli("lint-policy", str(tmp_path / "nope.yaml"))
        assert rc == 1


# ---------------------------------------------------------------------------
# AST-based line resolution
# ---------------------------------------------------------------------------


class TestAstLineResolution:
    """Pin that line numbers come from the YAML parse tree, not substring
    grep. Each case exercises a layout where the substring approach
    would have returned the wrong line, and confirms the AST resolver
    points at the structural occurrence.
    """

    def test_deprecated_op_in_condition_points_at_op_not_operator(
        self, tmp_path
    ):
        # Both keys appear in the condition; the line for the deprecated
        # 'op:' must point at the 'op:' line, not the 'operator:' line.
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: t
            rules:
              - name: r1
                action: allow
                condition:
                  field: tool_name
                  op: eq
                  operator: eq
                  value: foo
        """)
        result = lint_file(p)
        op_warnings = [
            m for m in result.warnings
            if "'op'" in m.message and "deprecated" in m.message.lower()
        ]
        assert op_warnings, "expected a deprecated-op warning"
        # The op: key sits on line 8 (after `version`, `name`, `rules:`,
        # `- name`, `action`, `condition:`, `field`).
        assert op_warnings[0].line == 8

    def test_unknown_operator_points_at_operator_value_line(self, tmp_path):
        # An unrelated rule earlier in the file mentions 'nope' as a
        # value. The substring approach would target that line instead
        # of the actual unknown-operator line.
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: t
            rules:
              - name: distraction
                action: allow
                condition:
                  field: nope
                  operator: eq
                  value: nope
              - name: real-bad
                action: allow
                condition:
                  field: tool_name
                  operator: nope
                  value: foo
        """)
        result = lint_file(p)
        op_errors = [
            m for m in result.errors
            if "unknown operator" in m.message.lower() and "nope" in m.message
        ]
        assert op_errors, "expected a single unknown-operator error"
        # The bad `operator: nope` token sits on line 14 (after the
        # 7-line distraction rule).
        assert op_errors[0].line == 14

    def test_deprecated_type_in_rule_targets_correct_rule(self, tmp_path):
        # Two rules each have a `type:` deprecated key. The previous
        # approach used `_find_line(lines, "type:")` and would only
        # ever return the first occurrence; the AST resolver gives
        # distinct lines for each rule.
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: t
            rules:
              - name: first
                type: allow
                action: allow
                condition: {field: a, operator: eq, value: x}
              - name: second
                type: deny
                action: deny
                condition: {field: b, operator: eq, value: y}
        """)
        result = lint_file(p)
        type_warnings = [
            m for m in result.warnings
            if "'type'" in m.message and "deprecated" in m.message.lower()
        ]
        assert len(type_warnings) == 2
        # First rule's `type:` is line 5, second rule's is line 9.
        lines = sorted(m.line for m in type_warnings)
        assert lines == [5, 9]

    def test_unknown_action_points_at_action_key(self, tmp_path):
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: t
            rules:
              - name: r1
                condition:
                  field: x
                  operator: eq
                  value: y
                action: zap
        """)
        result = lint_file(p)
        action_errors = [
            m for m in result.errors
            if "unknown action" in m.message.lower()
        ]
        assert action_errors
        # The `action: zap` key sits on line 9.
        assert action_errors[0].line == 9

    def test_invalid_priority_targets_priority_key(self, tmp_path):
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: t
            rules:
              - name: r1
                action: allow
                condition:
                  field: x
                  operator: eq
                  value: y
                priority: "high"
        """)
        result = lint_file(p)
        prio_errors = [
            m for m in result.errors
            if "priority must be an integer" in m.message.lower()
        ]
        assert prio_errors
        # `priority:` sits on line 10.
        assert prio_errors[0].line == 10

    def test_empty_rules_warning_points_at_rules_key(self, tmp_path):
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: t
            rules: []
        """)
        result = lint_file(p)
        empty = [m for m in result.warnings if "empty" in m.message.lower()]
        assert empty
        # `rules:` is on line 3.
        assert empty[0].line == 3

    def test_substring_collision_in_comment_ignored(self, tmp_path):
        # The earlier comment line contains the literal text `op: eq`,
        # which a substring search for "op:" would match before
        # reaching the real deprecated key two lines below.
        p = _write_policy(tmp_path, """\
            version: "1.0"
            name: t
            rules:
              - name: r1
                action: allow
                # legacy stub: op: eq
                condition:
                  field: x
                  op: eq
                  operator: eq
                  value: y
        """)
        result = lint_file(p)
        op_warnings = [
            m for m in result.warnings
            if "'op'" in m.message and "deprecated" in m.message.lower()
        ]
        assert op_warnings
        # The structural `op:` key lives on line 9, not line 6 where
        # the comment mentions it.
        assert op_warnings[0].line == 9
