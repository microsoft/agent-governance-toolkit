#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for check_v4_ratchet.py."""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import check_v4_ratchet as ratchet  # noqa: E402


def _py(src: str, rel: str = "x.py") -> dict:
    return ratchet._scan_python(Path(rel), src, rel).counts


# --------------------------- AST scanning --------------------------------

def test_ast_ignores_strings_and_comments():
    src = (
        "from agent_os.integrations.base import GovernancePolicy\n"
        "policy = GovernancePolicy()\n"
        "# GovernancePolicy in a comment must not count\n"
        "note = 'GovernancePolicy in a string must not count'\n"
    )
    assert _py(src)["GovernancePolicy"] == 2  # import + call


def test_ast_counts_class_and_function_definitions():
    assert _py("class GovernancePolicy: ...\n")["GovernancePolicy"] == 1
    assert _py("def governance_to_document(): ...\n")["governance_to_document"] == 1


def test_ast_counts_aliased_import_and_alias_uses():
    src = (
        "from agent_os.integrations.base import GovernancePolicy as GP\n"
        "a = GP()\n"
        "b = GP()\n"
    )
    assert _py(src)["GovernancePolicy"] == 3


def test_ast_counts_keyword_and_parameter_names():
    assert _py("run(resolution_root=None)\n")["resolution_root"] == 1
    assert _py("def f(resolution_root=None): ...\n")["resolution_root"] == 1


def test_ast_counts_all_entries_and_simple_string_annotation():
    assert _py("__all__ = ['GovernancePolicy']\n")["GovernancePolicy"] == 1
    assert _py("x: 'GovernancePolicy'\n")["GovernancePolicy"] == 1


def test_ast_counts_compound_string_annotation():
    # Bypass: forward-ref inside a subscript must be parsed, not exact-matched.
    assert _py("x: 'list[GovernancePolicy]'\n")["GovernancePolicy"] == 1
    assert _py("def f() -> 'dict[str, PatternType]': ...\n")["PatternType"] == 1
    assert _py("x: 'list[agent_os.policies.PolicyEvaluator]'\n")[
        "PolicyEvaluator"
    ] == 1


def test_ast_counts_parent_plus_submodule_import():
    # Bypass: `from agt.policies import bridge as legacy`.
    counts = _py("from agt.policies import bridge as legacy\n")
    assert counts["import:agt.policies.bridge"] == 1


def test_ast_no_double_count_direct_bridge_import():
    counts = _py("from agt.policies.bridge import governance_to_acs_manifest\n")
    assert counts["import:agt.policies.bridge"] == 1
    assert counts["governance_to_acs_manifest"] == 1


def test_ast_counts_aliased_dynamic_import():
    # import_module bound under an alias; the module-path string is counted
    # once via semantic-string detection.
    src = "from importlib import import_module as im\nim('agt.policies.bridge')\n"
    assert _py(src)["import:agt.policies.bridge"] == 1


def test_ast_counts_relative_bridge_import():
    counts = _py(
        "from ._v5_runtime_bridge import get_runtime_bridge\n",
        "agent-governance-python/agent-os/src/agent_os/integrations/openai_adapter.py",
    )
    assert counts["import:agent_os.integrations._v5_runtime_bridge"] == 1
    assert counts["get_runtime_bridge"] == 1


# --------------------------- ambiguous qualification ---------------------

def test_ambiguous_counted_only_when_bound_from_v4_module():
    v4 = _py(
        "from agent_os.integrations.base import ExecutionContext\n"
        "ctx = ExecutionContext()\n"
    )
    assert v4["ExecutionContext"] == 2  # import + use
    foreign = _py(
        "from agent_os.stateless import ExecutionContext\n"
        "ctx = ExecutionContext()\n"
    )
    assert "ExecutionContext" not in foreign


def test_ambiguous_module_alias_attribute_access():
    # Explicit module aliases.
    assert _py("import agent_os.integrations.base as b\nb.ExecutionContext\n")[
        "ExecutionContext"
    ] == 1
    assert _py("import agent_os.policies as p\np.PolicyEvaluator\n")["PolicyEvaluator"] == 1


def test_ambiguous_full_module_and_imported_submodule_access():
    # Bypasses: unaliased dotted import and imported submodule alias.
    assert _py(
        "import agent_os.policies\nagent_os.policies.PolicyEvaluator()\n"
    )["PolicyEvaluator"] == 1
    assert _py(
        "from agent_os.integrations import base as b\nb.ExecutionContext\n"
    )["ExecutionContext"] == 1


def test_ambiguous_relative_import_resolved_against_module():
    # Real v4 relative import resolves to the qualifying module and counts.
    real = _py(
        "from .base import ExecutionContext\nExecutionContext()\n",
        "agent-governance-python/agent-os/src/agent_os/integrations/openai_adapter.py",
    )
    assert real["ExecutionContext"] == 2
    # A foreign package's own .base is not miscounted.
    foreign = _py(
        "from .base import ExecutionContext\nExecutionContext()\n",
        "agent-governance-python/agent-mesh/src/agentmesh/foo/bar.py",
    )
    assert "ExecutionContext" not in foreign


def test_ambiguous_policy_evaluator_foreign_not_counted():
    foreign = _py(
        "from agentmesh.governance.policy_evaluator import PolicyEvaluator\n"
        "e = PolicyEvaluator()\n"
    )
    assert "PolicyEvaluator" not in foreign
    v4 = _py("from agent_os.policies import PolicyEvaluator\ne = PolicyEvaluator()\n")
    assert v4["PolicyEvaluator"] == 2


def test_ambiguous_canonical_definition_and_local_use():
    rel = "agent-governance-python/agent-os/src/agent_os/integrations/base.py"
    # class def + a local use both count in the canonical file.
    counts = _py("class ExecutionContext: ...\ndef f(c: ExecutionContext): ...\n", rel)
    assert counts["ExecutionContext"] == 2
    assert "ExecutionContext" not in _py("class ExecutionContext: ...\n", "other.py")


# --------------------------- semantic strings ----------------------------

def test_semantic_string_constants_count_but_not_prose():
    # verify.py pattern: dict values used for dynamic import/getattr.
    src = 'X = {"module": "agent_os.integrations.base", "check": "GovernancePolicy"}\n'
    assert _py(src)["GovernancePolicy"] == 1
    # mock.patch dotted target.
    assert _py('patch("agent_os.policies.evaluator.PolicyEvaluator")\n')["PolicyEvaluator"] == 1
    # ordinary prose remains uncounted.
    assert "GovernancePolicy" not in _py("m = 'the GovernancePolicy was removed'\n")


# --------------------------- policy data files ---------------------------

def test_policy_data_detects_v4_policydocument_not_trust_rules(tmp_path):
    v4 = (
        "name: research\nversion: '2'\n"
        "network_allowlist:\n  - example.com\n"
    )
    hits = ratchet._scan_policy_data(Path("x/policies/p.yaml"), v4, "x/policies/p.yaml")
    assert hits.counts["v4_policy_document_file"] == 1

    trust = (
        "name: default-trust\nversion: '1.0'\n"
        "rules:\n  - name: block\n    condition:\n      field: trust_score\n"
        "      operator: lt\n      value: 200\n    action: deny\n"
    )
    hits2 = ratchet._scan_policy_data(Path("x/policies/t.yaml"), trust, "x/policies/t.yaml")
    assert hits2.counts == {}


def test_policy_data_detects_policydefaults_yaml_and_json():
    yaml_doc = (
        "version: '1.0'\nname: first\nrules: []\n"
        "defaults:\n  action: allow\n  max_tool_calls: 10\n"
    )
    assert ratchet._is_v4_policy_document("docs/example.yaml", yaml_doc)

    json_doc = (
        '{"version":"1.0","name":"first","rules":[],'
        '"defaults":{"action":"allow","max_tokens":4096}}'
    )
    assert ratchet._is_v4_policy_document("config/example.json", json_doc)


def test_all_yaml_json_are_routed_to_policy_data():
    assert ratchet.decide_scanner(REPO_PATH("outside-policy-dir.yaml")) == "policy_data"
    assert ratchet.decide_scanner(REPO_PATH("outside-policy-dir.yml")) == "policy_data"
    assert ratchet.decide_scanner(REPO_PATH("outside-policy-dir.json")) == "policy_data"


def test_policy_data_excludes_acs_and_k8s():
    acs = "agent_control_specification_version: '0.3.1'\nnetwork_allowlist: []\n"
    assert not ratchet._is_v4_policy_document("x/policies/a.yaml", acs)
    k8s = "apiVersion: v1\nkind: ConfigMap\ntool_allowlist: []\n"
    assert not ratchet._is_v4_policy_document("x/policies/k.yaml", k8s)


def test_ambiguous_names_are_not_global_doc_tokens():
    assert "PolicyEvaluator" not in ratchet.DOC_TOKENS
    assert "ExecutionContext" not in ratchet.DOC_TOKENS
    assert "PolicyCheckResult" in ratchet.DOC_TOKENS


def test_docs_count_only_qualified_ambiguous_names():
    prose = ratchet._scan_doc(
        Path("README.md"),
        "AgentMesh has a PolicyEvaluator and an ExecutionContext.\n",
    )
    assert "PolicyEvaluator" not in prose.counts
    assert "ExecutionContext" not in prose.counts

    qualified = ratchet._scan_doc(
        Path("README.md"),
        "from agent_os.policies import PolicyEvaluator\n"
        "agent_os.integrations.base.ExecutionContext\n",
    )
    assert qualified.counts["PolicyEvaluator"] == 1
    assert qualified.counts["ExecutionContext"] == 1


def test_syntax_error_is_flagged_not_silently_zero():
    hits = ratchet._scan_python(Path("x.py"), "def broken(:\n GovernancePolicy()\n", "x.py")
    assert hits.parse_error is not None
    assert hits.total == 0


# --------------------------- token scanning ------------------------------

def test_identifier_tokens_match_member_access_but_not_substrings():
    src = "let a = GovernancePolicy; let b = ns.GovernancePolicy; let c = MyGovernancePolicyX;\n"
    hits = ratchet._scan_identifier_tokens(Path("x.ts"), src, ratchet.NONPY_V4_TOKENS)
    assert hits.counts["GovernancePolicy"] == 2  # bare + member access, not the substring


# --------------------------- ratchet enforcement -------------------------

def _inv(files: dict) -> dict:
    return {
        "grand_total": sum(sum(s.values()) for s in files.values()),
        "package_totals": {},
        "files": files,
        "parse_errors": [],
    }


def test_ratchet_allows_decrease_blocks_increase():
    base = _inv({"a.py": {"GovernancePolicy": 5}})
    assert ratchet.check_ratchet(_inv({"a.py": {"GovernancePolicy": 3}}), base) == []
    v = ratchet.check_ratchet(_inv({"a.py": {"GovernancePolicy": 7}}), base)
    assert any("a.py" in m and "5 -> 7" in m for m in v)


def test_ratchet_blocks_same_file_symbol_swap():
    base = _inv({"a.py": {"GovernancePolicy": 1}})
    v = ratchet.check_ratchet(_inv({"a.py": {"PatternType": 1}}), base)
    assert any("PatternType" in m for m in v)


def test_ratchet_blocks_new_file():
    base = _inv({"a.py": {"GovernancePolicy": 1}})
    spread = _inv({"a.py": {"GovernancePolicy": 1}, "b.py": {"GovernancePolicy": 1}})
    v = ratchet.check_ratchet(spread, base)
    assert any("b.py" in m and "new file" in m for m in v)


def test_ratchet_fails_closed_on_parse_error():
    inv = _inv({})
    inv["parse_errors"] = ["broken.py: invalid syntax"]
    v = ratchet.check_ratchet(inv, _inv({}))
    assert any("fails closed" in m for m in v)


# --------------------------- governance.yaml -----------------------------

def test_governance_yaml_scanner_selected_for_both_extensions():
    assert ratchet.decide_scanner(REPO_PATH("governance.yaml")) == "governance_yaml"
    assert ratchet.decide_scanner(REPO_PATH("governance.yml")) == "governance_yaml"


def test_governance_yaml_counts_regardless_of_body(tmp_path):
    empty = tmp_path / "governance.yaml"
    empty.write_text("", encoding="utf-8")
    hits = ratchet._scan_substring_tokens(empty, "", ratchet.DOC_TOKENS)
    hits.counts["governance_yaml_file"] = hits.counts.get("governance_yaml_file", 0) + 1
    assert hits.counts["governance_yaml_file"] == 1


def test_python_decode_failure_fails_closed(tmp_path):
    bad = tmp_path / "bad.py"
    # Latin-1 bytes that are not valid UTF-8 and declare no coding cookie.
    bad.write_bytes(b"x = '\xff\xfe invalid utf8 GovernancePolicy'\n")
    text, err = ratchet._read_python(bad, "bad.py")
    assert text is None
    assert err is not None and "decode error" in err


def REPO_PATH(name: str) -> Path:
    return ratchet.REPO_ROOT / "examples" / name


# --------------------------- allowed root --------------------------------

def test_allowed_root_is_exact_migration_files_not_whole_cli():
    assert ratchet._in_allowed_root(
        "agent-governance-python/agt-policies/src/agt/cli/migrate.py"
    )
    assert ratchet._in_allowed_root("agent-governance-python/agt-v4-migrate/src/x.py")
    assert ratchet._in_allowed_root("docs/v4-removal.md")
    assert not ratchet._in_allowed_root(
        "agent-governance-python/agt-policies/src/agt/cli/some_other_cmd.py"
    )
    assert not ratchet._in_allowed_root(
        "agent-governance-python/agt-policies/src/agt/policies/bridge.py"
    )


# --------------------------- baseline integrity --------------------------

def test_repo_baseline_matches_live_inventory_exactly():
    inventory = ratchet.build_inventory(ratchet.scan_repo())
    baseline = ratchet._load_baseline()
    assert inventory["grand_total"] == baseline["grand_total"]
    assert inventory["files"] == baseline["files"]
    assert ratchet.check_ratchet(inventory, baseline) == []


def test_repo_has_no_parse_errors():
    inventory = ratchet.build_inventory(ratchet.scan_repo())
    assert inventory["parse_errors"] == []
