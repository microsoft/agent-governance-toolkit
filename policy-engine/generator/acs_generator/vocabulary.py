from __future__ import annotations

from dataclasses import dataclass

ACS_VERSION = "0.3.1-beta"
ANNOTATOR_TYPES = frozenset({"classifier", "llm", "endpoint"})
DECISIONS = frozenset({"allow", "warn", "deny", "escalate", "transform"})
EFFECT_TYPES = frozenset({"append", "replace", "redact"})
POLICY_BUNDLE = "./policy"
POLICY_TYPE = "rego"
MAX_REPAIR_ATTEMPTS = 5

# Top-level keys of the policy input the core sends to policies (see core/src/constants.rs).
# The core is the single source of truth; generated Rego must read these, not the
# pre-rename `stage`/`evidence` keys, which silently evaluate to undefined.
POLICY_INPUT_POINT_KEY = "intervention_point"
POLICY_INPUT_ANNOTATIONS_KEY = "annotations"
DEPRECATED_INPUT_REFS = ("input.stage", "input.evidence")


@dataclass(frozen=True)
class InterventionPointSpec:
    name: str
    policy_target: str
    policy_target_kind: str
    tool_name_from: str | None = None


INTERVENTION_POINTS = (
    InterventionPointSpec("agent_startup", "$.agent", "agent_metadata"),
    InterventionPointSpec("input", "$.input", "user_input"),
    InterventionPointSpec("pre_model_call", "$.model_request", "model_request"),
    InterventionPointSpec("post_model_call", "$.model_response", "model_response"),
    InterventionPointSpec("pre_tool_call", "$.tool_call.args", "tool_args", "$.tool_call.name"),
    InterventionPointSpec("post_tool_call", "$.tool_result", "tool_result", "$.tool_call.name"),
    InterventionPointSpec("output", "$.output", "assistant_output"),
    InterventionPointSpec("agent_shutdown", "$.summary", "shutdown_summary"),
)
INTERVENTION_POINT_NAMES = tuple(point.name for point in INTERVENTION_POINTS)
INTERVENTION_POINT_BY_NAME = {point.name: point for point in INTERVENTION_POINTS}
TOOL_POINTS = frozenset(point.name for point in INTERVENTION_POINTS if point.tool_name_from)
