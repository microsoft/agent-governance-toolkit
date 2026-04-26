# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for action risk classifier."""


from hypervisor.models import ActionDescriptor, ExecutionRing, ReversibilityLevel
from hypervisor.rings.classifier import ActionClassifier, ClassificationResult


class TestClassificationResult:
    def test_creation(self):
        result = ClassificationResult(
            action_id="act-1",
            ring=ExecutionRing.RING_2_STANDARD,
            risk_weight=0.5,
            reversibility=ReversibilityLevel.FULL,
        )
        assert result.action_id == "act-1"
        assert result.ring == ExecutionRing.RING_2_STANDARD
        assert result.risk_weight == 0.5
        assert result.reversibility == ReversibilityLevel.FULL
        assert result.confidence == 1.0

    def test_custom_confidence(self):
        result = ClassificationResult(
            action_id="a",
            ring=ExecutionRing.RING_3_SANDBOX,
            risk_weight=0.1,
            reversibility=ReversibilityLevel.NONE,
            confidence=0.7,
        )
        assert result.confidence == 0.7


class TestActionClassifier:
    def test_init(self):
        classifier = ActionClassifier()
        assert classifier._cache == {}
        assert classifier._overrides == {}

    def test_classify_read_only(self):
        classifier = ActionClassifier()
        action = ActionDescriptor(
            action_id="read-data",
            name="Read Data",
            execute_api="/api/read",
            is_read_only=True,
        )
        result = classifier.classify(action)
        assert result.action_id == "read-data"
        assert result.ring == ExecutionRing.RING_3_SANDBOX
        assert result.reversibility == ReversibilityLevel.NONE

    def test_classify_admin_action(self):
        classifier = ActionClassifier()
        action = ActionDescriptor(
            action_id="config-update",
            name="Update Config",
            execute_api="/api/config",
            is_admin=True,
        )
        result = classifier.classify(action)
        assert result.ring == ExecutionRing.RING_0_ROOT

    def test_classify_destructive_non_reversible(self):
        classifier = ActionClassifier()
        action = ActionDescriptor(
            action_id="delete-db",
            name="Delete Database",
            execute_api="/api/delete",
            reversibility=ReversibilityLevel.NONE,
            is_read_only=False,
        )
        result = classifier.classify(action)
        assert result.ring == ExecutionRing.RING_1_PRIVILEGED

    def test_classify_reversible_action(self):
        classifier = ActionClassifier()
        action = ActionDescriptor(
            action_id="update-record",
            name="Update Record",
            execute_api="/api/update",
            undo_api="/api/undo",
            reversibility=ReversibilityLevel.FULL,
        )
        result = classifier.classify(action)
        assert result.ring == ExecutionRing.RING_2_STANDARD

    def test_classify_caches_result(self):
        classifier = ActionClassifier()
        action = ActionDescriptor(
            action_id="act-cache",
            name="Cached",
            execute_api="/api/x",
            is_read_only=True,
        )
        r1 = classifier.classify(action)
        r2 = classifier.classify(action)
        assert r1 is r2

    def test_classify_risk_weight_from_reversibility(self):
        classifier = ActionClassifier()
        action = ActionDescriptor(
            action_id="partial-rev",
            name="Partial",
            execute_api="/api/p",
            reversibility=ReversibilityLevel.PARTIAL,
        )
        result = classifier.classify(action)
        assert result.risk_weight == ReversibilityLevel.PARTIAL.default_risk_weight

    def test_set_override(self):
        classifier = ActionClassifier()
        action = ActionDescriptor(
            action_id="overridden",
            name="Test",
            execute_api="/api/t",
            is_read_only=True,
        )
        # Classify first to populate cache
        classifier.classify(action)
        classifier.set_override(
            "overridden",
            ring=ExecutionRing.RING_1_PRIVILEGED,
            risk_weight=0.9,
        )
        result = classifier.classify(action)
        assert result.ring == ExecutionRing.RING_1_PRIVILEGED
        assert result.risk_weight == 0.9
        assert result.confidence == 0.9

    def test_set_override_without_cache(self):
        classifier = ActionClassifier()
        classifier.set_override("unknown-action", ring=ExecutionRing.RING_1_PRIVILEGED)
        action = ActionDescriptor(
            action_id="unknown-action",
            name="Unknown",
            execute_api="/api/u",
        )
        result = classifier.classify(action)
        assert result.ring == ExecutionRing.RING_1_PRIVILEGED
        assert result.confidence == 0.9

    def test_clear_cache(self):
        classifier = ActionClassifier()
        action = ActionDescriptor(
            action_id="cached-act",
            name="X",
            execute_api="/api/x",
            is_read_only=True,
        )
        classifier.classify(action)
        assert "cached-act" in classifier._cache
        classifier.clear_cache()
        assert classifier._cache == {}

    def test_clear_cache_does_not_clear_overrides(self):
        classifier = ActionClassifier()
        classifier.set_override("act-o", ring=ExecutionRing.RING_0_ROOT)
        classifier.clear_cache()
        assert "act-o" in classifier._overrides

    def test_override_takes_precedence_over_cache(self):
        classifier = ActionClassifier()
        action = ActionDescriptor(
            action_id="act-p",
            name="Test",
            execute_api="/api/x",
            is_read_only=True,
        )
        classifier.classify(action)
        classifier.set_override("act-p", ring=ExecutionRing.RING_1_PRIVILEGED, risk_weight=1.0)
        result = classifier.classify(action)
        assert result.ring == ExecutionRing.RING_1_PRIVILEGED
