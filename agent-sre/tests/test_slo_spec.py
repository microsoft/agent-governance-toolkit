# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for SLO-as-code: spec, validation, diff, and inheritance."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from agent_sre.slo.spec import (
    BurnRateThreshold,
    ComparisonOp,
    ErrorBudgetPolicy,
    SLISpec,
    SLOSpec,
    load_slo_specs,
    resolve_inheritance,
)
from agent_sre.slo.validator import (
    TargetChange,
    diff_specs,
    validate_spec,
)

SPECS_DIR = Path(__file__).resolve().parent.parent / "specs" / "slos"


# ---- Fixtures ----


@pytest.fixture()
def base_spec() -> SLOSpec:
    return SLOSpec(
        name="test-base",
        description="Base test SLO",
        service="test-agent",
        sli=SLISpec(metric="task_success_ratio", threshold=0.99, comparison=ComparisonOp.GTE),
        target=99.0,
        window="30d",
        error_budget_policy=ErrorBudgetPolicy(
            burn_rate_thresholds=[
                BurnRateThreshold(name="slow", rate=2.0, severity="warning"),
                BurnRateThreshold(name="fast", rate=10.0, severity="critical"),
            ]
        ),
        labels={"tier": "standard"},
    )


@pytest.fixture()
def child_spec() -> SLOSpec:
    return SLOSpec(
        name="test-child",
        description="Child test SLO",
        service="critical-agent",
        inherits_from="test-base",
        target=99.9,
        sli=SLISpec(metric="task_success_ratio", threshold=0.999, comparison=ComparisonOp.GTE),
        labels={"tier": "critical"},
    )


# ---- YAML roundtrip ----


class TestYAMLRoundtrip:
    def test_save_and_load(self, base_spec: SLOSpec) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.yaml"
            base_spec.to_yaml(path)
            loaded = SLOSpec.from_yaml(path)
            assert loaded.name == base_spec.name
            assert loaded.target == base_spec.target
            assert loaded.sli is not None
            assert loaded.sli.metric == base_spec.sli.metric  # type: ignore[union-attr]
            assert loaded.window == base_spec.window

    def test_roundtrip_preserves_all_fields(self, base_spec: SLOSpec) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "roundtrip.yaml"
            base_spec.to_yaml(path)
            loaded = SLOSpec.from_yaml(path)
            # Compare full serialized form
            assert base_spec.model_dump(mode="json") == loaded.model_dump(mode="json")

    def test_load_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            for name, target in [("a", 99.0), ("b", 95.0)]:
                spec = SLOSpec(name=name, target=target)
                spec.to_yaml(Path(tmpdir) / f"{name}.yaml")
            specs = load_slo_specs(tmpdir)
            assert len(specs) == 2
            names = {s.name for s in specs}
            assert names == {"a", "b"}


# ---- Validation ----


class TestValidation:
    def test_valid_spec_passes(self, base_spec: SLOSpec) -> None:
        errors = validate_spec(base_spec)
        assert errors == []

    def test_target_too_high(self, base_spec: SLOSpec) -> None:
        bad = base_spec.model_copy(update={"target": 101.0})
        errors = validate_spec(bad)
        assert any(e.field == "target" for e in errors)

    def test_target_too_low(self, base_spec: SLOSpec) -> None:
        bad = base_spec.model_copy(update={"target": -1.0})
        errors = validate_spec(bad)
        assert any(e.field == "target" for e in errors)

    def test_invalid_window(self, base_spec: SLOSpec) -> None:
        bad = base_spec.model_copy(update={"window": "invalid"})
        errors = validate_spec(bad)
        assert any(e.field == "window" for e in errors)

    def test_empty_sli_metric(self) -> None:
        spec = SLOSpec(
            name="bad-metric",
            sli=SLISpec(metric="", threshold=0.99, comparison=ComparisonOp.GTE),
        )
        errors = validate_spec(spec)
        assert any(e.field == "sli.metric" for e in errors)

    def test_burn_rate_ordering(self) -> None:
        spec = SLOSpec(
            name="bad-burn-rates",
            error_budget_policy=ErrorBudgetPolicy(
                burn_rate_thresholds=[
                    BurnRateThreshold(name="fast", rate=10.0, severity="critical"),
                    BurnRateThreshold(name="slow", rate=2.0, severity="warning"),
                ]
            ),
        )
        errors = validate_spec(spec)
        assert any("burn_rate_thresholds" in e.field for e in errors)


# ---- Diff ----


class TestDiff:
    def test_no_change(self, base_spec: SLOSpec) -> None:
        diff = diff_specs(base_spec, base_spec)
        assert diff.changed_fields == []
        assert diff.target_change == TargetChange.UNCHANGED
        assert not diff.is_breaking

    def test_tightened_target(self, base_spec: SLOSpec) -> None:
        tighter = base_spec.model_copy(update={"target": 99.9})
        diff = diff_specs(base_spec, tighter)
        assert "target" in diff.changed_fields
        assert diff.target_change == TargetChange.TIGHTENED
        assert diff.is_breaking

    def test_loosened_target(self, base_spec: SLOSpec) -> None:
        looser = base_spec.model_copy(update={"target": 95.0})
        diff = diff_specs(base_spec, looser)
        assert "target" in diff.changed_fields
        assert diff.target_change == TargetChange.LOOSENED
        assert not diff.is_breaking

    def test_changed_metric_is_breaking(self, base_spec: SLOSpec) -> None:
        changed = base_spec.model_copy(
            update={"sli": SLISpec(metric="new_metric", threshold=0.99)}
        )
        diff = diff_specs(base_spec, changed)
        assert diff.is_breaking

    def test_description_change_not_breaking(self, base_spec: SLOSpec) -> None:
        changed = base_spec.model_copy(update={"description": "Updated"})
        diff = diff_specs(base_spec, changed)
        assert "description" in diff.changed_fields
        assert not diff.is_breaking


# ---- Inheritance ----


class TestInheritance:
    def test_resolve_simple(
        self, base_spec: SLOSpec, child_spec: SLOSpec
    ) -> None:
        resolved = resolve_inheritance([base_spec, child_spec])
        assert len(resolved) == 2
        child = next(s for s in resolved if s.name == "test-child")
        # Child overrides
        assert child.target == 99.9
        assert child.service == "critical-agent"
        # Child inherits parent labels (merged)
        assert child.labels.get("tier") == "critical"  # overridden

    def test_inherits_from_cleared(
        self, base_spec: SLOSpec, child_spec: SLOSpec
    ) -> None:
        resolved = resolve_inheritance([base_spec, child_spec])
        child = next(s for s in resolved if s.name == "test-child")
        assert child.inherits_from is None

    def test_unknown_parent_raises(self) -> None:
        orphan = SLOSpec(name="orphan", inherits_from="nonexistent")
        with pytest.raises(ValueError, match="unknown spec"):
            resolve_inheritance([orphan])

    def test_parent_unchanged(
        self, base_spec: SLOSpec, child_spec: SLOSpec
    ) -> None:
        resolved = resolve_inheritance([base_spec, child_spec])
        parent = next(s for s in resolved if s.name == "test-base")
        assert parent.target == 99.0


# ---- Example specs ----


class TestExampleSpecs:
    def test_example_specs_load(self) -> None:
        specs = load_slo_specs(SPECS_DIR)
        assert len(specs) >= 3
        names = {s.name for s in specs}
        assert "base-agent-slo" in names
        assert "critical-agent-slo" in names
        assert "batch-agent-slo" in names

    def test_example_specs_validate(self) -> None:
        specs = load_slo_specs(SPECS_DIR)
        for spec in specs:
            errors = validate_spec(spec)
            assert errors == [], f"Spec '{spec.name}' has validation errors: {errors}"

    def test_example_specs_resolve_inheritance(self) -> None:
        specs = load_slo_specs(SPECS_DIR)
        resolved = resolve_inheritance(specs)
        assert len(resolved) == len(specs)
        # Critical should have inherited and overridden
        critical = next(s for s in resolved if s.name == "critical-agent-slo")
        assert critical.target == 99.9
        assert critical.inherits_from is None

    def test_base_spec_values(self) -> None:
        specs = load_slo_specs(SPECS_DIR)
        base = next(s for s in specs if s.name == "base-agent-slo")
        assert base.target == 99.0
        assert base.sli is not None
        assert base.sli.metric == "agent_task_success_ratio"
        assert base.window == "30d"

    def test_batch_spec_values(self) -> None:
        specs = load_slo_specs(SPECS_DIR)
        batch = next(s for s in specs if s.name == "batch-agent-slo")
        assert batch.target == 95.0
        assert batch.window == "7d"
