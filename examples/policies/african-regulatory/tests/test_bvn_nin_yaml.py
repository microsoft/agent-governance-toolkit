# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
YAML-level schema validation tests for the BVN/NIN protection policy pack.

These tests exercise the enforced artifact (the YAML PolicyDocument) rather
than the Rego reference layer. They catch operator typos, unsupported schema
constructs, and missing rules before CI.
"""

import sys
import warnings
from pathlib import Path

import pytest

warnings.filterwarnings("ignore", category=DeprecationWarning)

AGT_SRC = Path(__file__).parents[4] / "agent-governance-python" / "agent-os" / "src"
sys.path.insert(0, str(AGT_SRC))

from agent_os.policies.schema import PolicyAction, PolicyDocument, PolicyOperator

POLICY_PATH = Path(__file__).parents[1] / "bvn-nin-protection.yaml"

VALID_OPERATORS = {op.value for op in PolicyOperator}


# ── Fixture ───────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def doc() -> PolicyDocument:
    return PolicyDocument.from_yaml(POLICY_PATH)


# ── Load / schema validity ─────────────────────────────────────────────────────

class TestSchemaValidity:
    def test_yaml_loads_without_error(self, doc):
        assert doc is not None

    def test_all_operators_are_valid(self, doc):
        invalid = [
            (r.name, r.condition.operator.value)
            for r in doc.rules
            if r.condition.operator.value not in VALID_OPERATORS
        ]
        assert invalid == [], f"Rules with invalid operators: {invalid}"

    def test_all_actions_are_valid(self, doc):
        valid_actions = {a.value for a in PolicyAction}
        invalid = [
            (r.name, r.action.value)
            for r in doc.rules
            if r.action.value not in valid_actions
        ]
        assert invalid == [], f"Rules with invalid actions: {invalid}"

    def test_no_compound_conditions(self, doc):
        for rule in doc.rules:
            cond = rule.condition
            assert hasattr(cond, "field"), (
                f"Rule '{rule.name}' condition is missing 'field' — compound "
                f"conditions (all/any) are not supported by the flat schema"
            )


# ── Rule presence ──────────────────────────────────────────────────────────────

class TestRulePresence:
    def test_nimc_2026_illegal_persistence_present(self, doc):
        names = [r.name for r in doc.rules]
        assert "nimc-2026-illegal-data-persistence-block" in names

    def test_nimc_2026_bulk_export_present(self, doc):
        names = [r.name for r in doc.rules]
        assert "nimc-2026-bulk-nin-export-block" in names

    def test_nimc_2026_mandatory_nin_gate_present(self, doc):
        names = [r.name for r in doc.rules]
        assert "nimc-2026-mandatory-nin-service-gate" in names

    def test_nimc_2026_rules_are_three_total(self, doc):
        nimc_rules = [r for r in doc.rules if r.name.startswith("nimc-2026-")]
        assert len(nimc_rules) == 3, (
            f"Expected 3 NIMC 2026 YAML rules (purpose-limitation is Rego-only); "
            f"found {len(nimc_rules)}: {[r.name for r in nimc_rules]}"
        )


# ── NIMC 2026 rule correctness ────────────────────────────────────────────────

class TestNimc2026Rules:
    def test_illegal_persistence_is_deny(self, doc):
        rule = next(r for r in doc.rules if r.name == "nimc-2026-illegal-data-persistence-block")
        assert rule.action == PolicyAction.DENY

    def test_bulk_export_is_deny(self, doc):
        rule = next(r for r in doc.rules if r.name == "nimc-2026-bulk-nin-export-block")
        assert rule.action == PolicyAction.DENY

    def test_mandatory_nin_gate_is_audit(self, doc):
        rule = next(r for r in doc.rules if r.name == "nimc-2026-mandatory-nin-service-gate")
        assert rule.action == PolicyAction.AUDIT

    def test_mandatory_nin_gate_uses_matches_operator(self, doc):
        rule = next(r for r in doc.rules if r.name == "nimc-2026-mandatory-nin-service-gate")
        assert rule.condition.operator == PolicyOperator.MATCHES

    def test_illegal_persistence_covers_store_nin(self, doc):
        rule = next(r for r in doc.rules if r.name == "nimc-2026-illegal-data-persistence-block")
        import re
        assert re.search(r"store_nin", rule.condition.value)

    def test_bulk_export_covers_export_nin_data(self, doc):
        rule = next(r for r in doc.rules if r.name == "nimc-2026-bulk-nin-export-block")
        import re
        assert re.search(r"export_nin_data", rule.condition.value)
