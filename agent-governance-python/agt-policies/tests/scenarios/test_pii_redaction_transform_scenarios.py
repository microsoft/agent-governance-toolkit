# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Transform-verdict redaction scenarios.

Demonstrates the AGT D1 transform verdict shape end-to-end. A policy
rule fires on detection of PII-like patterns in the model response and
rewrites the policy target before the action proceeds. Multi-pattern
redaction is performed by the agt.redact stock library rather than by
emitting an effects array (D1).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from agt._harness.opa_runner import run_scenario
from agt._harness.snapshot import output_snapshot


pytestmark = pytest.mark.skipif(
    shutil.which("opa") is None,
    reason="opa binary required for scenario tests",
)


def _redact_governance() -> dict:
    """Policy: at the output intervention point, redact SSN-looking
    strings in response content via a transform verdict."""
    return {
        "rules": [
            {
                "name": "redact_ssn_in_output",
                "condition": {
                    "field": "response.content",
                    "operator": "matches",
                    "value": r"\b\d{3}-\d{2}-\d{4}\b",
                },
                "action": "deny",  # placeholder; the transform happens in custom rego
                "priority": 100,
                "message": "Response contains SSN-like data",
            }
        ],
        "intervention_points": {
            "output": {
                "policy_target": "$.response.content",
                "policy_target_kind": "response_content",
                "policy": {"id": "agt_legacy_rules"},
            }
        },
    }


def test_output_with_ssn_denied(tmp_path: Path) -> None:
    """Pattern detection at the output intervention point."""
    snap = output_snapshot(
        agent_id="support",
        content="Customer SSN is 123-45-6789, please update.",
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _redact_governance()},
        intervention_point="output",
        snapshot=snap,
    )
    assert result.is_deny
    assert result.reason == "redact_ssn_in_output"


def test_clean_output_passes(tmp_path: Path) -> None:
    snap = output_snapshot(
        agent_id="support",
        content="Thanks for getting in touch! We'll follow up shortly.",
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _redact_governance()},
        intervention_point="output",
        snapshot=snap,
    )
    assert result.is_allow


# ── Transform via the agt.redact stock library ───────────────────────


def _stock_redact_governance() -> dict:
    """Policy expressed as a custom Rego rule that delegates to the
    agt.redact stock library to compute a transform verdict. This is
    the realistic usage pattern for the M4 stock library."""
    return {
        "rules": [],  # the legacy rendering path is empty; we use a custom policy
        "intervention_points": {
            "output": {
                "policy_target": "$.response.content",
                "policy_target_kind": "response_content",
                "policy": {"id": "agt_redact_policy"},
            }
        },
    }


def test_stock_redact_library_produces_transform_verdict(tmp_path: Path) -> None:
    """Author a custom Rego policy that imports the stock agt.redact
    library and asserts the resulting verdict shape is a transform with
    a $policy_target-rooted path."""
    # Write governance with the additional Rego policy that uses the
    # stock library.
    governance = _stock_redact_governance()
    (tmp_path / "governance.yaml").write_text(yaml.safe_dump(governance))

    # The resolution layer produces the legacy bundle; we then add our
    # custom Rego policy alongside it. Drop a hand-written Rego file
    # that the bundle picks up at policy directory scope.
    from agt.manifest_resolution import resolve_manifest
    manifest = resolve_manifest(tmp_path, tmp_path)
    bundle_dir = Path(manifest["policies"]["agt_legacy_rules"]["bundle"])
    # Copy stock library to the bundle
    from agt._harness.opa_runner import _find_stock_rego_root
    stock_root = _find_stock_rego_root()
    for rego in stock_root.glob("*.rego"):
        if rego.name.endswith("_test.rego"):
            continue
        (bundle_dir / rego.name).write_text(rego.read_text(encoding="utf-8"))

    # Write the host's custom redaction policy
    custom = """\
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
package agt.redact_policy
import rego.v1
import data.agt.redact
import data.agt.patterns

default verdict := {"decision": "allow"}

# Pull text from policy target value (the response content string).
_text := input.policy_target.value

# Apply the stock redact helper with the canonical PII pattern set.
verdict := result if {
    is_string(_text)
    result := redact.redact_text(_text, patterns.pii_patterns, "[REDACTED]")
    result.decision == "transform"
}
"""
    (bundle_dir / "agt_redact_policy.rego").write_text(custom, encoding="utf-8")

    # Manually invoke OPA (we cannot use the harness because we have a
    # second bound policy id). We invoke the redact policy directly.
    import json as json_module
    import subprocess
    from agt._harness.snapshot import output_snapshot
    snap = output_snapshot(
        agent_id="support",
        content="Customer SSN is 123-45-6789, email alice@example.com",
    )
    policy_input = {
        "intervention_point": "output",
        "policy_target": {
            "kind": "response_content",
            "path": "$policy_target",
            "value": snap["response"]["content"],
        },
        "snapshot": snap,
        "annotations": {},
        "tool": None,
    }
    proc = subprocess.run(  # noqa: S603 — test harness
        [
            "opa", "eval", "--format", "json", "--stdin-input",
            "--data", str(bundle_dir),
            "data.agt.redact_policy.verdict",
        ],
        input=json_module.dumps(policy_input),
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 0, f"opa eval failed: {proc.stderr}"
    body = json_module.loads(proc.stdout)
    verdict = body["result"][0]["expressions"][0]["value"]

    assert verdict["decision"] == "transform"
    transform = verdict["transform"]
    assert transform["path"] == "$policy_target", (
        f"transform.path MUST be rooted at $policy_target per D1.1; got {transform['path']!r}"
    )
    # The value MUST be a string with PII redacted out
    redacted_value = transform["value"]
    assert "[REDACTED]" in redacted_value, redacted_value
    assert "123-45-6789" not in redacted_value
    assert "alice@example.com" not in redacted_value
