"""Drift guards for the reserved reason registry and the wire result schema.

These run in CI through `pytest generator`. They exist because three separate
review rounds each found the same class of defect: a reason string renamed in
code while `spec/reserved-reasons.json` kept the old name, or a schema that
described a verdict shape the bindings no longer emit. Both are invisible to
every compiler and test suite in the tree, because nothing executed the spec
artefacts. These tests execute them.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
REGISTRY = REPO / "spec" / "reserved-reasons.json"
SPEC = REPO / "spec" / "SPECIFICATION.md"
RESULT_SCHEMA = REPO / "spec" / "schema" / "wire" / "result.schema.json"
GENERATOR_RESULT_SCHEMA = (
    REPO / "generator" / "acs_generator" / "schema" / "wire" / "result.schema.json"
)

SOURCE_ROOTS = [REPO / "sdk" / "rust" / "src", REPO / "sdk" / "node" / "src", REPO / "sdk" / "python"]
SOURCE_SUFFIXES = {".rs", ".ts", ".py"}
REASON_PATTERN = re.compile(r'"(host_error:[a-z_]+)"')


def _registry_reasons() -> set[str]:
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    return {entry["reason"] for entry in data["reasons"]}


def _emitted_host_reasons() -> dict[str, str]:
    """Every `host_error:*` literal in SDK source, mapped to where it appears."""
    found: dict[str, str] = {}
    for root in SOURCE_ROOTS:
        for path in root.rglob("*"):
            if path.suffix not in SOURCE_SUFFIXES or not path.is_file():
                continue
            if "test" in path.parts or path.name.startswith("test_"):
                continue
            for match in REASON_PATTERN.finditer(path.read_text(encoding="utf-8")):
                found.setdefault(match.group(1), str(path.relative_to(REPO)))
    return found


def test_every_emitted_host_reason_is_registered() -> None:
    emitted = _emitted_host_reasons()
    assert emitted, "found no host_error literals; the scan is broken, not the tree"
    unregistered = {name: site for name, site in emitted.items() if name not in _registry_reasons()}
    assert not unregistered, (
        "these host_error reasons are emitted but absent from spec/reserved-reasons.json: "
        f"{unregistered}"
    )


def test_every_registered_host_reason_is_documented() -> None:
    spec = SPEC.read_text(encoding="utf-8")
    undocumented = [
        reason
        for reason in sorted(_registry_reasons())
        if reason.startswith("host_error:") and f"`{reason}`" not in spec
    ]
    assert not undocumented, (
        f"registered but missing from the SPECIFICATION.md reason tables: {undocumented}"
    )


def test_host_error_names_come_from_the_closed_agent_hooks_set() -> None:
    """`host_error:*` is a closed set. AGT must not mint a name of its own."""
    closed_set = {
        "host_error:context_invalid",
        "host_error:interceptor_failed",
        "host_error:interceptor_timeout",
        "host_error:verdict_invalid",
        "host_error:transform_invalid",
        "host_error:transform_target_forbidden",
        "host_error:transform_conflict",
        "host_error:composition_disagreement",
        "host_error:approval_resolver_failed",
        "host_error:approval_unresolved",
        "host_error:approval_identity_mismatch",
        "host_error:adapter_unsupported",
        "host_error:streaming_unsupported",
        "host_error:no_interceptor",
    }
    invented = sorted(set(_emitted_host_reasons()) - closed_set)
    assert not invented, f"these are not agent-hooks reserved names: {invented}"


def test_the_two_result_schema_copies_have_not_drifted() -> None:
    assert json.loads(RESULT_SCHEMA.read_text(encoding="utf-8")) == json.loads(
        GENERATOR_RESULT_SCHEMA.read_text(encoding="utf-8")
    ), "spec/ and generator/ copies of result.schema.json disagree"


@pytest.mark.parametrize(
    ("verdict", "accepted"),
    [
        ({"decision": "allow"}, True),
        ({"decision": "allow", "warnings": [{"reason": "pii_detected"}]}, True),
        ({"decision": "deny", "reason": "needs_review", "approval": {}}, True),
        ({"decision": "transform", "transform": {"path": "$target.q", "value": "x"}}, True),
        # A null value is dropped by serde, so the member is legitimately absent.
        ({"decision": "transform", "transform": {"path": "$target.secret"}}, True),
        # agent-hooks still parses the deprecated alias on a transform path.
        ({"decision": "transform", "transform": {"path": "$policy_target.q", "value": 1}}, True),
        # The engine normalizes these two away; they must never reach the host.
        ({"decision": "warn"}, False),
        ({"decision": "escalate"}, False),
        # A transform path must stay rooted at the target.
        ({"decision": "transform", "transform": {"path": "$snap.q", "value": 1}}, False),
    ],
)
def test_result_schema_matches_the_three_verdict_contract(verdict: dict, accepted: bool) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(RESULT_SCHEMA.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(
        {
            "$schema": schema["$schema"],
            "$defs": schema["$defs"],
            "$ref": "#/$defs/result_verdict",
        }
    )
    errors = list(validator.iter_errors(verdict))
    assert bool(errors) != accepted, (
        f"{verdict} should be {'accepted' if accepted else 'rejected'}; "
        f"errors={[e.message for e in errors]}"
    )
