# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic self-correction with retry
"""
Auditor — simple null/empty check on response text.
"""


class CompletenessAuditor:
    """Basic completeness check: null, empty, or trivially short responses."""

    def __init__(self):
        self.lazy_signals = [
            "i cannot", "i'm sorry", "no data found",
            "unable to access", "context does not contain",
        ]

    def audit_response(self, agent_response: str, tool_output: str = "") -> bool:
        """
        Returns True when the response likely needs intervention.

        Checks:
        1. Null / empty response
        2. Known give-up phrases
        3. Tool returned trivially small output
        """
        if not agent_response or not agent_response.strip():
            return True

        if any(sig in agent_response.lower() for sig in self.lazy_signals):
            return True

        if tool_output and len(tool_output) < 10:
            return True

        return False
