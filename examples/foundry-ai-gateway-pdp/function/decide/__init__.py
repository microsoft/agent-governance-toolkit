# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Minimal Azure Function PDP for the Foundry AI Gateway sample.

Implements decision contract v1.0 from
docs/adr/0026-foundry-ai-gateway-functions-pdp.md.

Decision logic here is intentionally trivial — replace with your real
authorization, compliance, or risk checks. The contract (request/response
shape, fail-closed semantics, ttl hint) is the load-bearing part.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import azure.functions as func

SCHEMA_VERSION = "1.0"

# Example allow/deny lists. In production, source these from your policy
# store (Key Vault, App Configuration, OPA, etc.) — not hardcoded.
DENIED_TOOLS = {"github.delete_repo", "azure.delete_subscription"}
APPROVAL_REQUIRED_TOOLS = {"github.create_issue", "github.merge_pr"}

_log = logging.getLogger("pdp")


def _bad_request(reason: str, correlation_id: str = "") -> func.HttpResponse:
    return func.HttpResponse(
        body=json.dumps({"error": "bad_request", "reason": reason, "correlationId": correlation_id}),
        status_code=400,
        mimetype="application/json",
    )


def main(req: func.HttpRequest) -> func.HttpResponse:
    try:
        payload: dict[str, Any] = req.get_json()
    except ValueError:
        return _bad_request("invalid_json")

    if payload.get("schemaVersion") != SCHEMA_VERSION:
        return _bad_request("unsupported_schema_version", payload.get("correlationId", ""))

    correlation_id = payload.get("correlationId", "")

    # Required-field validation per ADR-0026 decision contract v1.0.
    required = ("agentId", "callerIdentity", "operation", "target", "inputDigest")
    missing = [f for f in required if not payload.get(f)]
    if missing:
        return _bad_request(f"missing_fields:{','.join(missing)}", correlation_id)

    input_digest = payload.get("inputDigest", "")
    if not isinstance(input_digest, str) or not input_digest.startswith("sha256:") or len(input_digest) != len("sha256:") + 64:
        return _bad_request("invalid_input_digest", correlation_id)

    operation = payload.get("operation")
    target = payload.get("target", "")

    if operation not in {"model.invoke", "tool.invoke"}:
        return _bad_request("unsupported_operation", correlation_id)

    if operation == "tool.invoke" and target in DENIED_TOOLS:
        decision = {
            "decision": "deny",
            "reasonCode": "tool.denylisted",
            "ttlSeconds": 300,
        }
    elif operation == "tool.invoke" and target in APPROVAL_REQUIRED_TOOLS:
        decision = {
            "decision": "require_approval",
            "reasonCode": "tool.requires_human_review",
            "conditions": ["require_human_review"],
            "ttlSeconds": 0,
        }
    else:
        decision = {
            "decision": "allow",
            "reasonCode": "default.allow",
            "ttlSeconds": 30,
        }

    decision["auditAnnotations"] = {
        "correlationId": correlation_id,
        "agentId": payload.get("agentId", ""),
        "target": target,
    }

    # Note: avoid passing reserved LogRecord field names via `extra=`.
    _log.info(
        "pdp_decision correlationId=%s decision=%s reasonCode=%s operation=%s target=%s",
        correlation_id,
        decision["decision"],
        decision["reasonCode"],
        operation,
        target,
    )

    return func.HttpResponse(
        body=json.dumps(decision),
        status_code=200,
        mimetype="application/json",
    )
