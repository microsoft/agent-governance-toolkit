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
     "expected_verdict": "allow"
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
    fixture_path: str = ""
    resolution_metadata: dict[str, Any] | None = None

    def mismatch_summary(self) -> str:
        """Human-readable diff for a failed fixture."""
        lines = [f"  want verdict={self.expected_verdict!r}"]
        lines.append(f"  got  verdict={self.actual_verdict!r}")
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


def replay(
    manifest_path: str | Path,
    fixture_path: str | Path,
) -> ReplayReport:
    """Replay fixtures against a native ACS manifest and return a report."""
    from agt.policies import AgtRuntime

    manifest_path = Path(manifest_path)
    fixture_path = Path(fixture_path)
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Manifest path not found: {manifest_path}")

    runtime = AgtRuntime.from_manifest(manifest_path)
    fixtures = _load_fixtures(fixture_path)
    report = ReplayReport()

    try:
        for fixture in fixtures:
            fixture_id = fixture.get("id") or fixture.get("name", "unnamed")
            raw_input = fixture.get("input") or fixture.get("context", {})
            intervention_point = fixture.get("intervention_point", "input")
            expected_verdict = fixture.get("expected_verdict") or fixture.get(
                "expected_action"
            )
            expected_allowed = fixture.get("expected_allowed")
            source = fixture.get("_source", "")
            resolution_metadata = fixture.get("resolution_metadata")

            if expected_verdict is None and expected_allowed is None:
                logger.warning(
                    "Fixture %r has no expected result — skipping", fixture_id
                )
                continue

            if (
                isinstance(raw_input, dict)
                and "envelope" in raw_input
                and intervention_point in raw_input
            ):
                snapshot = raw_input
            else:
                identity = (
                    raw_input.get("agent_id")
                    or raw_input.get("agent_did")
                    or "fixture-agent"
                    if isinstance(raw_input, dict)
                    else "fixture-agent"
                )
                snapshot = {
                    "envelope": {
                        "agent_id": identity,
                        "budgets": {
                            "token_count": (
                                raw_input.get("token_count", 0)
                                if isinstance(raw_input, dict)
                                else 0
                            ),
                            "tool_call_count": (
                                raw_input.get("tool_call_count", 0)
                                if isinstance(raw_input, dict)
                                else 0
                            ),
                        },
                    },
                    "input": {"body": raw_input},
                }

            evaluation = runtime.evaluate(intervention_point, snapshot)
            actual_verdict = evaluation.verdict
            passed = True
            if expected_verdict is not None and actual_verdict != expected_verdict:
                passed = False
            if (
                expected_allowed is not None
                and evaluation.is_allowed() != expected_allowed
            ):
                passed = False

            report.results.append(
                FixtureResult(
                    fixture_id=fixture_id,
                    passed=passed,
                    expected_verdict=expected_verdict
                    or ("allow" if expected_allowed else "deny"),
                    actual_verdict=actual_verdict,
                    fixture_path=source,
                    resolution_metadata=resolution_metadata,
                )
            )
    finally:
        runtime.close()

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
