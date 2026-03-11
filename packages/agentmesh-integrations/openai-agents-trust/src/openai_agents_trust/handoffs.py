"""Trust-gated handoffs for OpenAI Agents SDK."""

from __future__ import annotations

from typing import Any, Callable, Optional, Union

from agents import Agent
from agents.handoffs import Handoff, HandoffInputData, handoff
from agents.run_context import RunContextWrapper
from agents.util._types import MaybeAwaitable

from .audit import AuditLog
from .trust import TrustScorer


def trust_gated_handoff(
    agent: Agent[Any],
    scorer: TrustScorer,
    min_score: float = 0.5,
    audit_log: Optional[AuditLog] = None,
    tool_name_override: Optional[str] = None,
    tool_description_override: Optional[str] = None,
    strip_fields: Optional[list[str]] = None,
) -> Handoff:
    """Create a trust-gated handoff that only enables when the target agent's trust score
    meets the minimum threshold.

    Args:
        agent: The agent to hand off to.
        scorer: TrustScorer instance for checking trust.
        min_score: Minimum trust score required (0.0-1.0).
        audit_log: Optional audit log for recording handoff decisions.
        tool_name_override: Optional override for the handoff tool name.
        tool_description_override: Optional override for the tool description.
        strip_fields: Optional list of field names to strip from handoff input data.
    """

    def _is_enabled(ctx: RunContextWrapper[Any], ag: Agent[Any]) -> bool:
        score = scorer.get_score(agent.name)
        trusted = score.overall >= min_score

        if audit_log:
            audit_log.record(
                agent_id=agent.name,
                action="handoff_gate",
                decision="allow" if trusted else "deny",
                details={
                    "score": score.overall,
                    "min_score": min_score,
                    "from_agent": ag.name if hasattr(ag, "name") else "unknown",
                },
            )

        return trusted

    def _input_filter(data: HandoffInputData) -> HandoffInputData:
        """Filter sensitive fields from handoff input data."""
        if not strip_fields:
            return data

        # Filter new_items by removing items that contain stripped fields
        filtered_items = []
        for item in data.new_items:
            if hasattr(item, "to_dict"):
                item_dict = item.to_dict()
                for field_name in strip_fields:
                    item_dict.pop(field_name, None)
            filtered_items.append(item)

        return data.clone(new_items=tuple(filtered_items))

    return handoff(
        agent,
        tool_name_override=tool_name_override,
        tool_description_override=tool_description_override,
        is_enabled=_is_enabled,
        input_filter=_input_filter if strip_fields else None,
    )
