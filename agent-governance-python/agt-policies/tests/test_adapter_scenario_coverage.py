# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Coverage guard for AGT adapter scenario tests.

Every Agent OS adapter that routes through the ACS-backed v5 bridge must
have a matching scenario module under ``tests/scenarios``. This keeps new
adapter integrations from bypassing the allow/deny/transform/escalate
contract suite.
"""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
AGENT_OS_INTEGRATIONS = (
    REPO_ROOT
    / "agent-governance-python"
    / "agent-os"
    / "src"
    / "agent_os"
    / "integrations"
)
SCENARIO_DIR = Path(__file__).parent / "scenarios"


def _v5_adapter_names() -> set[str]:
    names: set[str] = set()
    for path in AGENT_OS_INTEGRATIONS.glob("*_adapter.py"):
        text = path.read_text(encoding="utf-8")
        if "_v5_runtime_bridge" in text or "get_runtime_bridge" in text:
            names.add(path.stem.removesuffix("_adapter"))
    return names


def _scenario_names() -> set[str]:
    names: set[str] = set()
    for path in SCENARIO_DIR.glob("test_*_adapter_scenarios.py"):
        name = path.name.removeprefix("test_").removesuffix("_adapter_scenarios.py")
        names.add(name)
    return names


def test_every_v5_agent_os_adapter_has_scenario_coverage() -> None:
    adapters = _v5_adapter_names()
    scenarios = _scenario_names()
    assert adapters <= scenarios, f"missing scenario coverage for: {sorted(adapters - scenarios)}"


def test_scenario_suite_has_no_orphan_agent_os_adapter_modules() -> None:
    adapters = _v5_adapter_names()
    scenarios = _scenario_names()
    allowed_domain_scenarios = {
        "bank_agent",
        "coding_agent",
        "egress_content_hash_escalation",
        "pii_redaction_transform",
        "records_ifc",
        "stock_library_smoke",
    }
    orphaned = scenarios - adapters - allowed_domain_scenarios
    assert not orphaned, f"scenario modules without adapter/domain mapping: {sorted(orphaned)}"
