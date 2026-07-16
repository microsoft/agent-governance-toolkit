# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Custom ACS policy dispatcher for the email-tool example."""

from __future__ import annotations

import re
from typing import Any, Mapping

_TRACKING_TOKEN = re.compile(r"TRACK-[A-Za-z0-9-]+")


class EmailPolicy:
    """Return ACS verdicts for the `send_email` policy target."""

    def evaluate(self, invocation: Mapping[str, Any]) -> dict[str, Any]:
        policy_input = invocation["input"]
        if policy_input["intervention_point"] != "pre_tool_call":
            return {"decision": "allow"}

        args = policy_input["policy_target"]["value"]
        recipient = args["to"]
        body = args["body"]

        if recipient.endswith("@example.net"):
            return {
                "decision": "deny",
                "reason": "external_recipient_blocked",
                "message": "Messages to example.net recipients are blocked.",
            }

        redacted = _TRACKING_TOKEN.sub("[REDACTED]", body)
        if redacted != body:
            return {
                "decision": "transform",
                "reason": "tracking_token_redacted",
                "message": "Tracking token redacted before tool execution.",
                "transform": {
                    "path": "$policy_target.body",
                    "value": redacted,
                },
            }

        return {"decision": "allow"}
