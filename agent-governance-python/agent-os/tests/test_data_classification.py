# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for data-layer ABAC policies and detection helpers."""

from __future__ import annotations

import pytest

from agent_os.policies.data_classification import (
    ABACPolicy,
    DataAccessDecision,
    DataAccessEvaluator,
    DataClassification,
    DataLabel,
    classify_text,
    detect_pci,
    detect_phi,
    detect_pii,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def public_label() -> DataLabel:
    return DataLabel(classification=DataClassification.PUBLIC, categories=[], geography="US")


@pytest.fixture()
def confidential_pii_label() -> DataLabel:
    return DataLabel(
        classification=DataClassification.CONFIDENTIAL,
        categories=["PII"],
        geography="US",
    )


@pytest.fixture()
def restricted_phi_label() -> DataLabel:
    return DataLabel(
        classification=DataClassification.RESTRICTED,
        categories=["PHI"],
        geography="EU",
    )


@pytest.fixture()
def permissive_policy() -> ABACPolicy:
    return ABACPolicy(
        agent_id="agent-1",
        allowed_classifications=[
            DataClassification.PUBLIC,
            DataClassification.INTERNAL,
            DataClassification.CONFIDENTIAL,
        ],
        allowed_categories=["PII", "GDPR"],
        denied_categories=[],
        max_classification=DataClassification.CONFIDENTIAL,
    )


@pytest.fixture()
def restrictive_policy() -> ABACPolicy:
    return ABACPolicy(
        agent_id="agent-1",
        allowed_classifications=[DataClassification.PUBLIC],
        allowed_categories=[],
        denied_categories=["PII"],
        max_classification=DataClassification.PUBLIC,
    )


# ---------------------------------------------------------------------------
# Classification hierarchy enforcement
# ---------------------------------------------------------------------------


class TestClassificationHierarchy:
    def test_public_less_than_top_secret(self) -> None:
        assert DataClassification.PUBLIC < DataClassification.TOP_SECRET

    def test_ordering(self) -> None:
        assert (
            DataClassification.PUBLIC
            < DataClassification.INTERNAL
            < DataClassification.CONFIDENTIAL
            < DataClassification.RESTRICTED
            < DataClassification.TOP_SECRET
        )

    def test_exceeds_max_classification_denied(
        self, permissive_policy: ABACPolicy
    ) -> None:
        label = DataLabel(classification=DataClassification.RESTRICTED)
        evaluator = DataAccessEvaluator([permissive_policy])
        decision = evaluator.evaluate("agent-1", label)
        assert not decision.allowed
        assert "exceeds" in decision.reason.lower()

    def test_within_max_classification_allowed(
        self, permissive_policy: ABACPolicy, public_label: DataLabel
    ) -> None:
        evaluator = DataAccessEvaluator([permissive_policy])
        decision = evaluator.evaluate("agent-1", public_label)
        assert decision.allowed


# ---------------------------------------------------------------------------
# Category allow / deny lists
# ---------------------------------------------------------------------------


class TestCategoryLists:
    def test_denied_category_blocks_access(self) -> None:
        policy = ABACPolicy(
            agent_id="agent-x",
            denied_categories=["ITAR"],
            max_classification=DataClassification.TOP_SECRET,
        )
        label = DataLabel(
            classification=DataClassification.INTERNAL, categories=["ITAR"]
        )
        decision = DataAccessEvaluator([policy]).evaluate("agent-x", label)
        assert not decision.allowed
        assert "denied" in decision.reason.lower()

    def test_allowed_category_passes(self, permissive_policy: ABACPolicy) -> None:
        label = DataLabel(
            classification=DataClassification.CONFIDENTIAL, categories=["PII"]
        )
        evaluator = DataAccessEvaluator([permissive_policy])
        decision = evaluator.evaluate("agent-1", label)
        assert decision.allowed

    def test_unlisted_category_denied_when_allowlist_set(self) -> None:
        policy = ABACPolicy(
            agent_id="agent-y",
            allowed_categories=["PII"],
            max_classification=DataClassification.TOP_SECRET,
        )
        label = DataLabel(
            classification=DataClassification.PUBLIC, categories=["GDPR"]
        )
        decision = DataAccessEvaluator([policy]).evaluate("agent-y", label)
        assert not decision.allowed
        assert "not in allowed" in decision.reason.lower()

    def test_empty_allowlist_permits_all_categories(self) -> None:
        policy = ABACPolicy(
            agent_id="agent-z",
            allowed_categories=[],
            max_classification=DataClassification.TOP_SECRET,
        )
        label = DataLabel(
            classification=DataClassification.PUBLIC, categories=["PCI", "GDPR"]
        )
        decision = DataAccessEvaluator([policy]).evaluate("agent-z", label)
        assert decision.allowed


# ---------------------------------------------------------------------------
# Geography restrictions
# ---------------------------------------------------------------------------


class TestGeography:
    def test_matching_geography_allowed(self) -> None:
        policy = ABACPolicy(
            agent_id="geo-agent",
            required_geography="US",
            max_classification=DataClassification.CONFIDENTIAL,
        )
        label = DataLabel(classification=DataClassification.PUBLIC, geography="US")
        decision = DataAccessEvaluator([policy]).evaluate("geo-agent", label)
        assert decision.allowed

    def test_mismatched_geography_denied(self) -> None:
        policy = ABACPolicy(
            agent_id="geo-agent",
            required_geography="US",
            max_classification=DataClassification.CONFIDENTIAL,
        )
        label = DataLabel(classification=DataClassification.PUBLIC, geography="EU")
        decision = DataAccessEvaluator([policy]).evaluate("geo-agent", label)
        assert not decision.allowed
        assert "geography" in decision.reason.lower()

    def test_no_geography_requirement_allows_any(self) -> None:
        policy = ABACPolicy(
            agent_id="flex-agent",
            max_classification=DataClassification.TOP_SECRET,
        )
        label = DataLabel(classification=DataClassification.PUBLIC, geography="APAC")
        decision = DataAccessEvaluator([policy]).evaluate("flex-agent", label)
        assert decision.allowed


# ---------------------------------------------------------------------------
# Default deny for unregistered agents
# ---------------------------------------------------------------------------


class TestDefaultDeny:
    def test_unregistered_agent_denied(self, public_label: DataLabel) -> None:
        evaluator = DataAccessEvaluator([])
        decision = evaluator.evaluate("unknown-agent", public_label)
        assert not decision.allowed
        assert "no abac policy" in decision.reason.lower()


# ---------------------------------------------------------------------------
# Multiple policies - most restrictive wins
# ---------------------------------------------------------------------------


class TestMultiplePolicies:
    def test_most_restrictive_wins(self) -> None:
        permissive = ABACPolicy(
            agent_id="multi",
            max_classification=DataClassification.TOP_SECRET,
        )
        restrictive = ABACPolicy(
            agent_id="multi",
            denied_categories=["PII"],
            max_classification=DataClassification.TOP_SECRET,
        )
        label = DataLabel(
            classification=DataClassification.PUBLIC, categories=["PII"]
        )
        decision = DataAccessEvaluator([permissive, restrictive]).evaluate(
            "multi", label
        )
        assert not decision.allowed

    def test_all_policies_allow(self) -> None:
        p1 = ABACPolicy(agent_id="multi2", max_classification=DataClassification.CONFIDENTIAL)
        p2 = ABACPolicy(agent_id="multi2", max_classification=DataClassification.RESTRICTED)
        label = DataLabel(classification=DataClassification.INTERNAL)
        decision = DataAccessEvaluator([p1, p2]).evaluate("multi2", label)
        assert decision.allowed


# ---------------------------------------------------------------------------
# PII detection
# ---------------------------------------------------------------------------


class TestDetectPII:
    def test_ssn_detected(self) -> None:
        assert "SSN" in detect_pii("My SSN is 123-45-6789")

    def test_email_detected(self) -> None:
        assert "email" in detect_pii("Contact user@example.com")

    def test_phone_detected(self) -> None:
        assert "phone" in detect_pii("Call (555) 123-4567")

    def test_no_pii(self) -> None:
        assert detect_pii("Hello world") == []


# ---------------------------------------------------------------------------
# PHI detection
# ---------------------------------------------------------------------------


class TestDetectPHI:
    def test_mrn_detected(self) -> None:
        assert "MRN" in detect_phi("Patient MRN: 12345678")

    def test_icd_code_detected(self) -> None:
        assert "ICD-code" in detect_phi("Diagnosis J45.20")

    def test_no_phi(self) -> None:
        assert detect_phi("No medical data here") == []


# ---------------------------------------------------------------------------
# PCI detection
# ---------------------------------------------------------------------------


class TestDetectPCI:
    def test_credit_card_detected(self) -> None:
        assert "credit-card" in detect_pci("Card 4111 1111 1111 1111")

    def test_no_pci(self) -> None:
        assert detect_pci("No card numbers") == []


# ---------------------------------------------------------------------------
# Auto-classification
# ---------------------------------------------------------------------------


class TestClassifyText:
    def test_plain_text_is_public(self) -> None:
        label = classify_text("Hello world")
        assert label.classification == DataClassification.PUBLIC
        assert label.categories == []

    def test_pii_classified_confidential(self) -> None:
        label = classify_text("SSN: 123-45-6789")
        assert label.classification >= DataClassification.CONFIDENTIAL
        assert "PII" in label.categories

    def test_phi_classified_restricted(self) -> None:
        label = classify_text("Patient MRN: 12345678")
        assert label.classification >= DataClassification.RESTRICTED
        assert "PHI" in label.categories

    def test_mixed_pii_and_pci(self) -> None:
        label = classify_text("Email user@test.com card 4111 1111 1111 1111")
        assert "PII" in label.categories
        assert "PCI" in label.categories


# ---------------------------------------------------------------------------
# Decision model
# ---------------------------------------------------------------------------


class TestDataAccessDecision:
    def test_evaluated_at_populated(self) -> None:
        d = DataAccessDecision(
            allowed=True,
            reason="ok",
            agent_id="a",
            data_label=DataLabel(classification=DataClassification.PUBLIC),
        )
        assert d.evaluated_at is not None