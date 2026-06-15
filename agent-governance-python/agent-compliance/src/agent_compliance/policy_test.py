# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Policy regression testing — replay engine.

Loads JSON/YAML test fixtures, evaluates each against current policy
rules, and reports verdict mismatches. Designed for CI gating:
exit code 0 when all fixtures pass, 1 on any mismatch.

Fixture format:
    {"id": "unique-name",
     "input": {"action": "sql_execute", ...},
     "expected_verdict": "allow",
     "expected_rule": "pg-staging-reads"  # optional
    }

See schemas/fixture_schema.json for the full JSON Schema.

Usage (programmatic):
    from agent_compliance.policy_test import replay
    results = replay("policies/", "fixtures/")

Usage (CLI):
    agt test policies/ fixtures/
"""

from __future__ import annotations

import json
import logging

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class FixtureResult:
    """Outcome of replaying a single fixture against the policy engine."""

    fixture_id: str
    passed: bool
    expected_verdict: str
    actual_verdict: str
    expected_rule: str | None = None
    actual_rule: str | None = None
    fixture_path: str = ""
    resolution_metadata: dict[str, Any] | None = None

    def mismatch_summary(self) -> str:
        """Human-readable diff for a failed fixture."""
        lines = [f"  want verdict={self.expected_verdict!r}"]
        if self.expected_rule:
            lines[0] += f"  rule={self.expected_rule!r}"
        lines.append(f"  got  verdict={self.actual_verdict!r}")
        if self.actual_rule:
            lines[-1] += f"  rule={self.actual_rule!r}"
        return "\n".join(lines)


@dataclass
class ReplayReport:
    """Aggregate results from a replay run."""

    results: list[FixtureResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return self.total - self.passed

    @property
    def ok(self) -> bool:
        return self.failed == 0

    @property
    def mismatches(self) -> list[FixtureResult]:
        return [r for r in self.results if not r.passed]

    def summary(self) -> str:
        return f"{self.total} fixture(s) checked, {self.failed} mismatch(es)"

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable representation."""
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "ok": self.ok,
            "results": [
                {
                    "id": r.fixture_id,
                    "passed": r.passed,
                    "expected_verdict": r.expected_verdict,
                    "actual_verdict": r.actual_verdict,
                    "expected_rule": r.expected_rule,
                    "actual_rule": r.actual_rule,
                    "fixture_path": r.fixture_path,
                    "resolution_metadata": r.resolution_metadata,
                }
                for r in self.results
            ],
        }


def _load_fixtures(fixture_path: Path) -> list[dict[str, Any]]:
    """Load fixtures from a file or directory.

    Supports JSON and YAML. A single file may contain one fixture (object)
    or many (array / YAML list). A directory is globbed for *.json and
    *.yaml/*.yml files.
    """
    paths: list[Path] = []

    if fixture_path.is_dir():
        for ext in ("*.json", "*.yaml", "*.yml"):
            paths.extend(sorted(fixture_path.glob(ext)))
    elif fixture_path.is_file():
        paths.append(fixture_path)
    else:
        raise FileNotFoundError(f"Fixture path not found: {fixture_path}")

    if not paths:
        raise FileNotFoundError(f"No fixture files found in {fixture_path}")

    fixtures: list[dict[str, Any]] = []
    for p in paths:
        raw = _load_file(p)
        if isinstance(raw, list):
            for item in raw:
                item.setdefault("_source", str(p))
            fixtures.extend(raw)
        elif isinstance(raw, dict):
            # Check for YAML scenarios wrapper (tutorial compat)
            if "scenarios" in raw and isinstance(raw["scenarios"], list):
                for item in raw["scenarios"]:
                    item.setdefault("_source", str(p))
                fixtures.extend(raw["scenarios"])
            else:
                raw.setdefault("_source", str(p))
                fixtures.append(raw)
    return fixtures


def _load_file(path: Path) -> Any:
    """Load a single JSON or YAML file."""
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)

    try:
        import yaml
    except ImportError as exc:
        raise ImportError("pyyaml is required: pip install pyyaml") from exc
    return yaml.safe_load(text)


def _normalize_verdict(decision_action: str, decision_allowed: bool) -> str:
    """Map a PolicyDecision to a canonical verdict string.

    Fixtures can use "allow", "deny", "audit", or "block" as the
    expected_verdict. The evaluator returns an action string plus a
    boolean. We normalize to the action string for comparison.
    """
    return decision_action


def replay(
    policy_path: str | Path,
    fixture_path: str | Path,
) -> ReplayReport:
    """Replay fixtures against policies and return a report.

    Args:
        policy_path: Directory or single YAML file containing policies.
        fixture_path: Directory or single file containing test fixtures.

    Returns:
        A ReplayReport with per-fixture pass/fail results.
    """
    # Lazy import so the module can be loaded without agent_os installed
    # (useful for CLI help text, tab completion, etc.)
    from agent_os.policies.evaluator import PolicyEvaluator
    from agent_os.policies.schema import PolicyDocument

    policy_path = Path(policy_path)
    fixture_path = Path(fixture_path)

    # Load policies
    policies: list[PolicyDocument] = []
    if policy_path.is_dir():
        for ext in ("*.yaml", "*.yml"):
            for p in sorted(policy_path.glob(ext)):
                policies.append(PolicyDocument.from_yaml(p))
    elif policy_path.is_file():
        policies.append(PolicyDocument.from_yaml(policy_path))
    else:
        raise FileNotFoundError(f"Policy path not found: {policy_path}")

    if not policies:
        raise FileNotFoundError(f"No policy files found in {policy_path}")

    evaluator = PolicyEvaluator(policies=policies)

    # Load and replay fixtures
    fixtures = _load_fixtures(fixture_path)
    report = ReplayReport()

    for fixture in fixtures:
        # Extract fields — support both issue-spec format and tutorial format
        fixture_id = fixture.get("id") or fixture.get("name", "unnamed")
        context = fixture.get("input") or fixture.get("context", {})
        expected_verdict = fixture.get("expected_verdict") or fixture.get("expected_action")
        expected_rule = fixture.get("expected_rule")
        source = fixture.get("_source", "")

        # Also support expected_allowed (boolean) from tutorial format
        expected_allowed = fixture.get("expected_allowed")
        resolution_metadata = fixture.get("resolution_metadata")

        if expected_verdict is None and expected_allowed is None:
            logger.warning(
                "Fixture %r has no expected_verdict or expected_allowed — skipping",
                fixture_id,
            )
            continue

        decision = evaluator.evaluate(context)
        actual_verdict = _normalize_verdict(decision.action, decision.allowed)
        actual_rule = decision.matched_rule

        # Determine pass/fail
        passed = True
        if expected_verdict is not None and actual_verdict != expected_verdict:
            passed = False
        if expected_allowed is not None and decision.allowed != expected_allowed:
            passed = False
        if expected_rule is not None and actual_rule != expected_rule:
            passed = False

        # Validate resolution_metadata.rule_id if provided (superset of
        # expected_rule: rule_id is resolution-aware, checked after expected_rule)
        if resolution_metadata is not None and passed:
            rule_id = resolution_metadata.get("rule_id")
            if rule_id is not None and actual_rule != rule_id:
                passed = False
                logger.debug(
                    "resolution_metadata mismatch: expected rule_id=%r, got %r",
                    rule_id, actual_rule,
                )

        report.results.append(
            FixtureResult(
                fixture_id=fixture_id,
                passed=passed,
                expected_verdict=expected_verdict or ("allow" if expected_allowed else "deny"),
                actual_verdict=actual_verdict,
                expected_rule=expected_rule,
                actual_rule=actual_rule,
                fixture_path=source,
                resolution_metadata=resolution_metadata,
            )
        )

    return report


def print_report(report: ReplayReport, *, use_json: bool = False) -> None:
    """Print a replay report to stdout."""
    if use_json:
        print(json.dumps(report.to_dict(), indent=2))
        return

    for result in report.results:
        status = "ok" if result.passed else "FAIL"
        print(f"{status:4s}  {result.fixture_id}")
        if not result.passed:
            print(result.mismatch_summary())

    print()
    print(report.summary())
