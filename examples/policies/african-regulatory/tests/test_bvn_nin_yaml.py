# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
YAML-level schema validation tests for the BVN/NIN protection policy pack.

These tests exercise the enforced artifact (the YAML policy document) rather
than the Rego reference layer. They catch operator typos, unsupported schema
constructs, and missing rules before CI.

Validated against the raw YAML mapping rather than the legacy Agent-OS
PolicyDocument/PolicyAction/PolicyOperator classes, which are being phased
out in favor of the ACS (v5) policy layer (see docs/v4-removal.md) —
importing those classes here would regress the v4 removal ratchet for a
brand-new file.
"""

import re
from pathlib import Path

import pytest
import yaml

POLICY_PATH = Path(__file__).parents[1] / "bvn-nin-protection.yaml"

# Mirrors agent_os.policies.schema.PolicyOperator / PolicyAction values.
VALID_OPERATORS = {"eq", "ne", "gt", "lt", "gte", "lte", "in", "not_in", "matches", "contains"}
VALID_ACTIONS = {"allow", "deny", "audit", "block"}


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def doc() -> dict:
    return yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def rules(doc) -> list[dict]:
    return doc["rules"]


# ── Load / schema validity ─────────────────────────────────────────────────

class TestSchemaValidity:
    def test_yaml_loads_without_error(self, doc):
        assert doc is not None

    def test_all_operators_are_valid(self, rules):
        invalid = [
            (r["name"], r["condition"]["operator"])
            for r in rules
            if r["condition"]["operator"] not in VALID_OPERATORS
        ]
        assert invalid == [], f"Rules with invalid operators: {invalid}"

    def test_all_actions_are_valid(self, rules):
        invalid = [(r["name"], r["action"]) for r in rules if r["action"] not in VALID_ACTIONS]
        assert invalid == [], f"Rules with invalid actions: {invalid}"

    def test_no_compound_conditions(self, rules):
        for rule in rules:
            assert "field" in rule["condition"], (
                f"Rule '{rule['name']}' condition is missing 'field' — compound "
                f"conditions (all/any) are not supported by the flat schema"
            )


# ── Rule presence ───────────────────────────────────────────────────────────

class TestRulePresence:
    def test_nimc_2026_illegal_persistence_present(self, rules):
        names = [r["name"] for r in rules]
        assert "nimc-2026-illegal-data-persistence-block" in names

    def test_nimc_2026_bulk_export_present(self, rules):
        names = [r["name"] for r in rules]
        assert "nimc-2026-bulk-nin-export-block" in names

    def test_nimc_2026_mandatory_nin_gate_present(self, rules):
        names = [r["name"] for r in rules]
        assert "nimc-2026-mandatory-nin-service-gate" in names

    def test_nimc_2026_rules_are_three_total(self, rules):
        nimc_rules = [r for r in rules if r["name"].startswith("nimc-2026-")]
        assert len(nimc_rules) == 3, (
            f"Expected 3 NIMC 2026 YAML rules (purpose-limitation is Rego-only); "
            f"found {len(nimc_rules)}: {[r['name'] for r in nimc_rules]}"
        )


# ── NIMC 2026 rule correctness ───────────────────────────────────────────────

class TestNimc2026Rules:
    def test_illegal_persistence_is_deny(self, rules):
        rule = next(r for r in rules if r["name"] == "nimc-2026-illegal-data-persistence-block")
        assert rule["action"] == "deny"

    def test_bulk_export_is_deny(self, rules):
        rule = next(r for r in rules if r["name"] == "nimc-2026-bulk-nin-export-block")
        assert rule["action"] == "deny"

    def test_mandatory_nin_gate_is_audit(self, rules):
        rule = next(r for r in rules if r["name"] == "nimc-2026-mandatory-nin-service-gate")
        assert rule["action"] == "audit"

    def test_mandatory_nin_gate_uses_matches_operator(self, rules):
        rule = next(r for r in rules if r["name"] == "nimc-2026-mandatory-nin-service-gate")
        assert rule["condition"]["operator"] == "matches"

    def test_illegal_persistence_covers_store_nin(self, rules):
        rule = next(r for r in rules if r["name"] == "nimc-2026-illegal-data-persistence-block")
        assert re.search(r"store_nin", rule["condition"]["value"])

    def test_bulk_export_covers_export_nin_data(self, rules):
        rule = next(r for r in rules if r["name"] == "nimc-2026-bulk-nin-export-block")
        assert re.search(r"export_nin_data", rule["condition"]["value"])
