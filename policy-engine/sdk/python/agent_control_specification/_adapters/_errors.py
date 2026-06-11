from __future__ import annotations

from .._types import AgentControlBlocked, Decision, InterventionPoint, InterventionPointResult, Verdict


class AdapterUnsupportedError(AgentControlBlocked):
    """Raised when a duck-typed adapter cannot safely wrap the requested shape."""

    def __init__(self, message: str):
        result = InterventionPointResult(
            Verdict(Decision.DENY, reason="runtime_error:adapter_unsupported", message=message)
        )
        super().__init__(InterventionPoint.INPUT, result)
