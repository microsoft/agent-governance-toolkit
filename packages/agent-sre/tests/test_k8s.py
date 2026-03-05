# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Kubernetes operator module."""

from __future__ import annotations

import pytest

from agent_sre.k8s import (
    CRD_GROUP,
    CRD_PLURAL,
    CRD_VERSION,
    Condition,
    ConditionStatus,
    ConditionType,
    ReconcileAction,
    Reconciler,
    ResourceStatus,
    generate_crd_manifest,
)

# ---------------------------------------------------------------------------
# CRD manifest
# ---------------------------------------------------------------------------

class TestCRDManifest:
    def test_generate_crd(self):
        crd = generate_crd_manifest()
        assert crd["apiVersion"] == "apiextensions.k8s.io/v1"
        assert crd["kind"] == "CustomResourceDefinition"
        assert crd["metadata"]["name"] == f"{CRD_PLURAL}.{CRD_GROUP}"

    def test_crd_has_versions(self):
        crd = generate_crd_manifest()
        versions = crd["spec"]["versions"]
        assert len(versions) == 1
        assert versions[0]["name"] == CRD_VERSION
        assert versions[0]["served"] is True
        assert versions[0]["storage"] is True

    def test_crd_has_schema(self):
        crd = generate_crd_manifest()
        schema = crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]
        assert schema["type"] == "object"
        spec_props = schema["properties"]["spec"]["properties"]
        assert "strategy" in spec_props
        assert "candidate" in spec_props
        assert "steps" in spec_props

    def test_crd_has_subresources(self):
        crd = generate_crd_manifest()
        assert "status" in crd["spec"]["versions"][0]["subresources"]

    def test_crd_printer_columns(self):
        crd = generate_crd_manifest()
        columns = crd["spec"]["versions"][0]["additionalPrinterColumns"]
        names = [c["name"] for c in columns]
        assert "Strategy" in names
        assert "Phase" in names
        assert "Weight" in names

    def test_crd_scope(self):
        crd = generate_crd_manifest()
        assert crd["spec"]["scope"] == "Namespaced"

    def test_crd_short_names(self):
        crd = generate_crd_manifest()
        assert "aroll" in crd["spec"]["names"]["shortNames"]


# ---------------------------------------------------------------------------
# ResourceStatus
# ---------------------------------------------------------------------------

class TestResourceStatus:
    def test_defaults(self):
        status = ResourceStatus()
        assert status.phase == "Pending"
        assert status.current_step == 0
        assert status.current_weight == 0.0
        assert status.conditions == []

    def test_set_condition_new(self):
        status = ResourceStatus()
        status.set_condition(ConditionType.AVAILABLE, ConditionStatus.TRUE, "Ready")
        assert len(status.conditions) == 1
        assert status.conditions[0].type == ConditionType.AVAILABLE

    def test_set_condition_update(self):
        status = ResourceStatus()
        status.set_condition(ConditionType.AVAILABLE, ConditionStatus.FALSE)
        status.set_condition(ConditionType.AVAILABLE, ConditionStatus.TRUE, "Now ready")
        assert len(status.conditions) == 1
        assert status.conditions[0].status == ConditionStatus.TRUE

    def test_get_condition(self):
        status = ResourceStatus()
        status.set_condition(ConditionType.PROGRESSING, ConditionStatus.TRUE)
        c = status.get_condition(ConditionType.PROGRESSING)
        assert c is not None
        assert c.status == ConditionStatus.TRUE

    def test_get_condition_missing(self):
        status = ResourceStatus()
        assert status.get_condition(ConditionType.DEGRADED) is None

    def test_to_dict(self):
        status = ResourceStatus(phase="canary", current_step=1, current_weight=0.25)
        d = status.to_dict()
        assert d["phase"] == "canary"
        assert d["currentStep"] == 1
        assert d["currentWeight"] == 0.25

    def test_condition_to_dict(self):
        c = Condition(ConditionType.AVAILABLE, ConditionStatus.TRUE, "Ready", "All good")
        d = c.to_dict()
        assert d["type"] == "Available"
        assert d["status"] == "True"
        assert d["reason"] == "Ready"


# ---------------------------------------------------------------------------
# Reconciler — creation
# ---------------------------------------------------------------------------

SAMPLE_SPEC = {
    "strategy": "canary",
    "current": {"name": "my-agent", "version": "v1"},
    "candidate": {"name": "my-agent", "version": "v2"},
    "steps": [
        {"name": "canary-5", "weight": 0.05, "durationSeconds": 3600},
        {"name": "canary-50", "weight": 0.50, "durationSeconds": 7200},
        {"name": "full", "weight": 1.0, "durationSeconds": 0},
    ],
    "rollbackConditions": [
        {"metric": "error_rate", "threshold": 0.05, "operator": "gte"},
    ],
}


class TestReconcilerCreation:
    def test_create_rollout(self):
        r = Reconciler()
        with pytest.raises(NotImplementedError):
            r.reconcile("test", "default", SAMPLE_SPEC)

    def test_created_rollout_is_canary(self):
        r = Reconciler()
        with pytest.raises(NotImplementedError):
            r.reconcile("test", "default", SAMPLE_SPEC)

    def test_status_after_create(self):
        r = Reconciler()
        with pytest.raises(NotImplementedError):
            r.reconcile("test", "default", SAMPLE_SPEC)

    def test_invalid_spec(self):
        r = Reconciler()
        result = r.reconcile("test", "default", {"strategy": "invalid_strategy"})
        assert result.action == ReconcileAction.ERROR

    def test_generation_update_recreates(self):
        r = Reconciler()
        with pytest.raises(NotImplementedError):
            r.reconcile("test", "default", SAMPLE_SPEC, generation=1)


# ---------------------------------------------------------------------------
# Reconciler — advance & rollback
# ---------------------------------------------------------------------------

class TestReconcilerAdvance:
    def test_advance(self):
        r = Reconciler()
        with pytest.raises(NotImplementedError):
            r.reconcile("test", "default", SAMPLE_SPEC)

    def test_advance_to_completion(self):
        r = Reconciler()
        with pytest.raises(NotImplementedError):
            r.reconcile("test", "default", SAMPLE_SPEC)

    def test_advance_nonexistent(self):
        r = Reconciler()
        result = r.advance("missing", "default")
        assert result.action == ReconcileAction.ERROR

    def test_rollback(self):
        r = Reconciler()
        with pytest.raises(NotImplementedError):
            r.reconcile("test", "default", SAMPLE_SPEC)

    def test_rollback_nonexistent(self):
        r = Reconciler()
        result = r.rollback("missing", "default")
        assert result.action == ReconcileAction.ERROR


# ---------------------------------------------------------------------------
# Reconciler — sync (idempotent reconcile)
# ---------------------------------------------------------------------------

class TestReconcilerSync:
    def test_noop_on_same_generation(self):
        r = Reconciler()
        with pytest.raises(NotImplementedError):
            r.reconcile("test", "default", SAMPLE_SPEC, generation=1)

    def test_completed_stays_completed(self):
        r = Reconciler()
        with pytest.raises(NotImplementedError):
            r.reconcile("test", "default", SAMPLE_SPEC)

    def test_rolled_back_stays_rolled_back(self):
        r = Reconciler()
        with pytest.raises(NotImplementedError):
            r.reconcile("test", "default", SAMPLE_SPEC)


# ---------------------------------------------------------------------------
# Reconciler — queries
# ---------------------------------------------------------------------------

class TestReconcilerQueries:
    def test_list_rollouts(self):
        r = Reconciler()
        with pytest.raises(NotImplementedError):
            r.reconcile("a", "default", SAMPLE_SPEC)

    def test_list_rollouts_filtered(self):
        r = Reconciler()
        with pytest.raises(NotImplementedError):
            r.reconcile("a", "default", SAMPLE_SPEC)

    def test_active_count(self):
        r = Reconciler()
        with pytest.raises(NotImplementedError):
            r.reconcile("a", "default", SAMPLE_SPEC)

    def test_get_status_missing(self):
        r = Reconciler()
        assert r.get_status("missing", "default") is None

    def test_get_rollout_missing(self):
        r = Reconciler()
        assert r.get_rollout("missing", "default") is None

    def test_reconcile_result_to_dict(self):
        r = Reconciler()
        with pytest.raises(NotImplementedError):
            r.reconcile("test", "default", SAMPLE_SPEC)


# ---------------------------------------------------------------------------
# Spec parsing edge cases
# ---------------------------------------------------------------------------

class TestSpecParsing:
    def test_minimal_spec(self):
        r = Reconciler()
        spec = {
            "candidate": {"name": "agent", "version": "v1"},
        }
        with pytest.raises(NotImplementedError):
            r.reconcile("minimal", "default", spec)

    def test_shadow_strategy(self):
        r = Reconciler()
        spec = {
            "strategy": "shadow",
            "candidate": {"name": "agent", "version": "v2"},
            "steps": [{"weight": 0.0, "durationSeconds": 86400}],
        }
        with pytest.raises(NotImplementedError):
            r.reconcile("shadow", "default", spec)

    def test_spec_with_slo_requirements(self):
        r = Reconciler()
        spec = dict(SAMPLE_SPEC)
        spec["sloRequirements"] = [{"name": "accuracy", "target": 0.99}]
        with pytest.raises(NotImplementedError):
            r.reconcile("slo-test", "default", spec)

    def test_spec_with_analysis_criteria(self):
        r = Reconciler()
        spec = {
            "candidate": {"name": "agent", "version": "v2"},
            "steps": [
                {
                    "weight": 0.1,
                    "analysis": [{"metric": "accuracy", "threshold": 0.95}],
                },
                {"weight": 1.0},
            ],
        }
        with pytest.raises(NotImplementedError):
            r.reconcile("analysis", "default", spec)
