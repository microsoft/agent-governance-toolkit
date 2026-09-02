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
_skipped_count: int = 0


def _policy_strict() -> bool:
    """Whether the directory loader fails closed on an unloadable policy file.

    Defaults to on (issue #3538): a policy file that fails to load must not be
    silently dropped, or a deny policy could vanish while a broader allow keeps
    serving. Set ``AGENTMESH_POLICY_STRICT`` to ``0``/``false``/``no``/``off``
    for best-effort loading instead. Any other value, including blank or
    unrecognised, stays strict so a misconfigured toggle fails closed.
    """
    return os.getenv("AGENTMESH_POLICY_STRICT", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def _on_load_failure(name: str, exc: Exception, strict: bool) -> None:
    """Fail closed (raise) or, in non-strict mode, log at error level."""
    if strict:
        raise RuntimeError(
            f"Policy file {name!r} failed to load: {exc}. Refusing to start with a "
            f"policy silently dropped; set AGENTMESH_POLICY_STRICT=0 for best-effort "
            f"loading (issue #3538)."
        ) from exc
    logger.error("Skipped %s: %s", name, exc)


def _load_policies() -> None:
    """Load all YAML/JSON policy files from POLICY_DIR.

    Fails closed by default (issue #3538): a file that parses as neither a
    governance policy nor a trust policy raises rather than being silently
    dropped. Set ``AGENTMESH_POLICY_STRICT=0`` for best-effort loading.
    """
    global _engine, _trust_policies, _trust_evaluator, _loaded_count, _skipped_count

    policy_path = Path(POLICY_DIR)
    if not policy_path.exists():
        logger.warning("Policy directory %s does not exist", POLICY_DIR)
        return

    strict = _policy_strict()
    # Build into local state and commit only once every file has loaded, so a
    # strict-mode failure leaves the previously loaded policy set intact instead
    # of swapping in a partially loaded (weaker) one on reload (issue #3538).
    engine = PolicyEngine()
    trust_policies: list[TrustPolicy] = []
    governance_count = 0
    skipped = 0

    for f in sorted(policy_path.glob("*.yaml")):
        try:
            engine.load_yaml(f.read_text())
            governance_count += 1
            logger.info("Loaded governance policy: %s", f.name)
        except Exception as gov_exc:
            # Not a governance policy; try loading it as a trust policy.
            # TrustPolicy.from_yaml takes a path, so pass the file, not its text.
            try:
                tp = TrustPolicy.from_yaml(f)
                trust_policies.append(tp)
                logger.info("Loaded trust policy: %s", f.name)
            except Exception as trust_exc:
                # Both parsers rejected the file. Report each reason so the
                # failure is not misattributed to only the trust parser when the
                # file was meant to be a governance policy.
                skipped += 1
                _on_load_failure(
                    f.name,
                    RuntimeError(
                        f"not a governance policy ({gov_exc}); "
                        f"not a trust policy ({trust_exc})"
                    ),
                    strict,
                )

    for f in sorted(policy_path.glob("*.json")):
        try:
            engine.load_json(f.read_text())
            governance_count += 1
        except Exception as exc:
            skipped += 1
            _on_load_failure(f.name, exc, strict)

    _engine = engine
    _trust_policies = trust_policies
    _trust_evaluator = PolicyEvaluator(trust_policies) if trust_policies else None
    _loaded_count = governance_count + len(trust_policies)
    _skipped_count = skipped
    logger.info(
        "Loaded %d governance + %d trust policies",
        governance_count,
        len(trust_policies),
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
    """Evaluate governance policies against an agent action.

    SECURITY (known gap): accepts ``agent_did`` from the request body
    without authenticating the caller. The policy-server is a separate
    service without direct access to the identity registry, so binding
    ``agent_did`` to a signed caller identity requires cross-service
    auth plumbing. Treat decisions returned here as advisory unless the
    deployment authenticates callers at the gateway. Same class of
    issue as ``audit_collector.log_entry``.
    """
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
        "skipped": _skipped_count,
        "trust_policies": len(_trust_policies),
        "policy_dir": POLICY_DIR,
    }


@app.post("/api/v1/policy/reload", tags=["policy"])
async def reload_policies() -> dict[str, Any]:
    """Reload policies from disk.

    A strict-mode load failure keeps the previously loaded policy set (see
    ``_load_policies``); this returns 409 rather than a bare 500 so the caller
    can tell the reload was rejected and the prior policies still serve.
    """
    try:
        _load_policies()
    except RuntimeError as exc:
        logger.error("Policy reload rejected, keeping previous set: %s", exc)
        raise HTTPException(
            status_code=409,
            detail=f"Policy reload rejected; previous policy set retained. {exc}",
        ) from exc
    return {
        "status": "reloaded",
        "total_loaded": _loaded_count,
        "trust_policies": len(_trust_policies),
    }


def main() -> None:
    run_server(app, default_port=8444)


if __name__ == "__main__":
    main()
