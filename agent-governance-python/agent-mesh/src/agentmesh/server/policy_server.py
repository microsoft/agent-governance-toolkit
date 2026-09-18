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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

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


@dataclass(frozen=True)
class PolicyState:
    """Immutable snapshot of one completed policy load.

    Every field comes from the same load. The module publishes a new load by
    rebinding ``_policy_state`` in a single assignment, and every reader takes
    the snapshot once per request, so a concurrent reload can never expose a
    reader to a mix of old and new generation state (e.g. a new engine paired
    with a stale trust evaluator) on the security decision path.
    """

    engine: PolicyEngine
    trust_policies: tuple[TrustPolicy, ...]
    trust_evaluator: PolicyEvaluator | None
    loaded_count: int
    skipped_count: int


def _empty_state() -> PolicyState:
    """A safe starting snapshot: no policies loaded (deny by absence)."""
    return PolicyState(
        engine=PolicyEngine(),
        trust_policies=(),
        trust_evaluator=None,
        loaded_count=0,
        skipped_count=0,
    )


# Loaded policy state — a single immutable snapshot, swapped atomically.
_policy_state: PolicyState = _empty_state()


def _policy_strict() -> bool:
    """Whether a policy file that fails to load is a hard error.

    Opt-in (issue #3538, review feedback on #3660): OFF by default so a shipped
    deployment carrying one unparseable policy file keeps serving rather than
    crash-looping. Honoured via ``AGENTMESH_POLICY_STRICT`` (primary for this
    component) OR ``AGT_POLICY_STRICT`` (the sidecar's name, accepted as an alias
    so an operator running both components need set only one). Truthy values are
    ``1``/``true``/``yes``/``on``.
    """
    truthy = {"1", "true", "yes", "on"}
    return any(
        os.getenv(var, "").strip().lower() in truthy
        for var in ("AGENTMESH_POLICY_STRICT", "AGT_POLICY_STRICT")
    )


def _on_load_failure(name: str, exc: Exception, strict: bool) -> None:
    """Fail closed (raise) or, in non-strict mode, log at error level."""
    if strict:
        raise RuntimeError(
            f"Policy file {name!r} failed to load: {exc}. Refusing to start with a "
            f"policy silently dropped; unset AGENTMESH_POLICY_STRICT for best-effort "
            f"loading (issue #3538)."
        ) from exc
    logger.error("Skipped %s: %s", name, exc)


def _load_policies() -> None:
    """Load all YAML/JSON policy files from POLICY_DIR.

    Best-effort by default (issue #3538, review feedback on #3660): a file
    that parses as neither a governance nor a trust policy is logged and
    skipped so a shipped deployment keeps serving. Set
    ``AGENTMESH_POLICY_STRICT=1`` to fail closed and refuse to start rather
    than silently drop a policy.
    """
    global _policy_state

    policy_path = Path(POLICY_DIR)
    strict = _policy_strict()
    if not policy_path.exists():
        # A missing policy directory means zero policies, hence no deny rules —
        # serving in that state is fail-open. In strict mode refuse to start
        # rather than returning early and serving wide open (issue #3538).
        if strict:
            raise RuntimeError(
                f"Policy directory {POLICY_DIR} does not exist; refusing to start "
                f"in strict mode (issue #3538)."
            )
        logger.warning("Policy directory %s does not exist", POLICY_DIR)
        return

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
                raw = yaml.safe_load(f.read_text())
                tp = TrustPolicy.from_yaml(f)
                # TrustPolicy ignores unknown keys and makes rules optional, so a
                # governance policy that merely failed governance parsing (e.g. a
                # bad apiVersion) would otherwise be silently accepted as a
                # rule-less trust policy — a deny policy quietly dropped. Reject a
                # governance-shaped file (top-level kind/apiVersion) or a trust
                # policy with no rules and route it to the load-failure handler.
                if (
                    isinstance(raw, dict) and ("kind" in raw or "apiVersion" in raw)
                ) or not tp.rules:
                    raise ValueError(
                        "not a usable trust policy (governance-shaped file or no "
                        "trust rules); refusing to silently accept an empty policy"
                    )
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

    # Publish barrier: assemble the whole immutable snapshot, then swap it in
    # with a single assignment. Every reader takes ``_policy_state`` once per
    # request, so this guarantees a reader sees one internally consistent
    # generation — engine, trust policies, evaluator and counters from the same
    # load — never a mix of old and new during a reload. A strict-mode failure
    # raises above (before this point), leaving the previous snapshot in place.
    _policy_state = PolicyState(
        engine=engine,
        trust_policies=tuple(trust_policies),
        trust_evaluator=PolicyEvaluator(trust_policies) if trust_policies else None,
        loaded_count=governance_count + len(trust_policies),
        skipped_count=skipped,
    )
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

    # Snapshot once so a concurrent reload cannot swap the engine mid-decision.
    state = _policy_state
    result: PolicyDecision = state.engine.evaluate(agent_did=req.agent_did, context=ctx)
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
    # Snapshot once: the evaluator and its policies come from the same load.
    state = _policy_state
    if state.trust_evaluator is None:
        raise HTTPException(503, "No trust policies loaded")

    result = state.trust_evaluator.evaluate(req.context)
    return TrustEvaluateResponse(
        allowed=result.allowed,
        action=result.action,
        rule_name=result.rule_name,
        reason=result.reason,
    )


@app.get("/api/v1/policies", tags=["policy"])
async def list_policies() -> dict[str, Any]:
    """List all loaded policies."""
    state = _policy_state
    return {
        "total_loaded": state.loaded_count,
        "skipped": state.skipped_count,
        "trust_policies": len(state.trust_policies),
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
    state = _policy_state
    return {
        "status": "reloaded",
        "total_loaded": state.loaded_count,
        "trust_policies": len(state.trust_policies),
    }


def main() -> None:
    run_server(app, default_port=8444)


if __name__ == "__main__":
    main()
