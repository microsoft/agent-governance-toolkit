# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Policy Server

Evaluates governance policies against agent actions.
Loads YAML policy files from a configurable directory and evaluates
them via the AgentMesh policy engine.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel, Field

from agentmesh.governance.policy import PolicyDecision, PolicyEngine
from agentmesh.governance.policy_evaluator import PolicyEvaluator
from agentmesh.governance.trust_policy import TrustPolicy
from agentmesh.server import create_base_app, run_server

logger = logging.getLogger(__name__)

app = create_base_app(
    "policy-server",
    "Evaluates governance policies against agent actions.",
)

POLICY_DIR = os.getenv("AGENTMESH_POLICY_DIR", "/etc/agentmesh/policies")

# Loaded policy state
_engine: PolicyEngine = PolicyEngine()
_trust_policies: list[TrustPolicy] = []
_trust_evaluator: PolicyEvaluator | None = None
_loaded_count: int = 0


def _load_policies() -> None:
    """Load all YAML/JSON policy files from POLICY_DIR."""
    global _engine, _trust_policies, _trust_evaluator, _loaded_count

    policy_path = Path(POLICY_DIR)
    if not policy_path.exists():
        logger.warning("Policy directory %s does not exist", POLICY_DIR)
        return

    _engine = PolicyEngine()
    _trust_policies = []
    governance_count = 0

    for f in sorted(policy_path.glob("*.yaml")):
        try:
            _engine.load_yaml(f.read_text())
            governance_count += 1
            logger.info("Loaded governance policy: %s", f.name)
        except Exception:
            try:
                tp = TrustPolicy.from_yaml(f.read_text())
                _trust_policies.append(tp)
                logger.info("Loaded trust policy: %s", f.name)
            except Exception as exc:
                logger.warning("Skipped %s: %s", f.name, exc)

    for f in sorted(policy_path.glob("*.json")):
        try:
            _engine.load_json(f.read_text())
            governance_count += 1
        except Exception as exc:
            logger.warning("Skipped %s: %s", f.name, exc)

    if _trust_policies:
        _trust_evaluator = PolicyEvaluator(_trust_policies)

    _loaded_count = governance_count + len(_trust_policies)
    logger.info(
        "Loaded %d governance + %d trust policies",
        governance_count,
        len(_trust_policies),
    )


@app.on_event("startup")
async def startup() -> None:
    _load_policies()


# ── Request / Response models ────────────────────────────────────────


class EvaluateRequest(BaseModel):
    agent_did: str = Field(..., description="DID of the acting agent")
    action: str = Field(..., description="Action being performed")
    resource: str | None = Field(None, description="Target resource")
    context: dict[str, Any] = Field(default_factory=dict, description="Additional context")


class EvaluateResponse(BaseModel):
    decision: str = Field(..., description="allow, deny, warn, or require_approval")
    matched_rule: str | None = None
    reason: str = ""
    policy_name: str | None = None


class TrustEvaluateRequest(BaseModel):
    context: dict[str, Any] = Field(..., description="Trust policy evaluation context")


class TrustEvaluateResponse(BaseModel):
    allowed: bool
    action: str
    rule_name: str | None = None
    reason: str = ""


# ── Endpoints ────────────────────────────────────────────────────────


@app.post("/api/v1/policy/evaluate", tags=["policy"], response_model=EvaluateResponse)
async def evaluate_policy(req: EvaluateRequest) -> EvaluateResponse:
    """Evaluate governance policies against an agent action."""
    ctx = {
        "action": req.action,
        "resource": req.resource,
        **req.context,
    }

    result: PolicyDecision = _engine.evaluate(agent_did=req.agent_did, context=ctx)
    return EvaluateResponse(
        decision=result.action,
        matched_rule=result.matched_rule,
        reason=result.reason,
        policy_name=result.policy_name,
    )


@app.post(
    "/api/v1/policy/trust/evaluate",
    tags=["policy"],
    response_model=TrustEvaluateResponse,
)
async def evaluate_trust_policy(req: TrustEvaluateRequest) -> TrustEvaluateResponse:
    """Evaluate trust policies against a context."""
    if _trust_evaluator is None:
        raise HTTPException(503, "No trust policies loaded")

    result = _trust_evaluator.evaluate(req.context)
    return TrustEvaluateResponse(
        allowed=result.allowed,
        action=result.action,
        rule_name=result.rule_name,
        reason=result.reason,
    )


@app.get("/api/v1/policies", tags=["policy"])
async def list_policies() -> dict[str, Any]:
    """List all loaded policies."""
    return {
        "total_loaded": _loaded_count,
        "trust_policies": len(_trust_policies),
        "policy_dir": POLICY_DIR,
    }


@app.post("/api/v1/policy/reload", tags=["policy"])
async def reload_policies() -> dict[str, Any]:
    """Reload policies from disk."""
    _load_policies()
    return {
        "status": "reloaded",
        "total_loaded": _loaded_count,
        "trust_policies": len(_trust_policies),
    }


def main() -> None:
    run_server(app, default_port=8444)


if __name__ == "__main__":
    main()
