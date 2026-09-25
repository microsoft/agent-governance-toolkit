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

import yaml
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from agentmesh.governance.policy import PolicyDecision, PolicyEngine
from agentmesh.governance.policy_evaluator import PolicyEvaluator
from agentmesh.governance.trust_policy import TrustPolicy
from agentmesh.server import create_base_app, run_server

logger = logging.getLogger(__name__)

app = create_base_app(
    "policy-server",
    "Evaluates governance policies against agent actions.",
    include_readyz=False,
)

POLICY_DIR = os.getenv("AGENTMESH_POLICY_DIR", "/etc/agentmesh/policies")

# Loaded policy state
_engine: PolicyEngine = PolicyEngine()
_trust_policies: list[TrustPolicy] = []
_trust_evaluator: PolicyEvaluator | None = None
_loaded_count: int = 0
_GOVERNANCE_ONLY_KEYS = frozenset({"agent", "agents", "default_action", "extends", "scope"})
_effective_rule_count: int = 0
_load_warnings: list[str] = []


@app.get("/readyz", tags=["health"], response_model=None)
async def readyz() -> JSONResponse:
    payload = {
        "status": "ready" if _effective_rule_count > 0 else "not-ready",
        "component": "policy-server",
        "total_loaded": _loaded_count,
        "effective_rules": _effective_rule_count,
        "policy_dir": POLICY_DIR,
        "load_warnings": list(_load_warnings),
    }
    if _effective_rule_count == 0:
        return JSONResponse(status_code=503, content=payload)
    return JSONResponse(content=payload)


def _validate_load_warnings() -> None:
    """Record a warning when a load completes without effective rules."""
    global _load_warnings

    _load_warnings = []
    if _effective_rule_count == 0:
        warning = (
            f"Policy load validation: no effective rules loaded from {POLICY_DIR}; "
            "readiness remains blocked until an enabled policy rule is loaded."
        )
        logger.warning(warning)
        _load_warnings.append(warning)


def _load_policies() -> None:
    """Load all YAML/JSON policy files from POLICY_DIR."""
    global _engine, _trust_policies, _trust_evaluator, _loaded_count, _effective_rule_count

    policy_path = Path(POLICY_DIR)
    if not policy_path.is_dir():
        raise RuntimeError(
            f"Policy directory {POLICY_DIR} does not exist or is not a directory; "
            "refusing to load an undefined policy set"
        )

    # Load into locals first; assign globals only after all files succeed.
    # A failed reload (POST /api/v1/policy/reload) must not leave a
    # partially loaded engine live (#3536 review feedback).
    local_engine = PolicyEngine()
    local_trust: list[TrustPolicy] = []
    governance_count = 0
    effective_rule_count = 0
    errors: list[tuple[str, Exception]] = []

    try:
        with os.scandir(policy_path) as entries:
            discovered = sorted(
                (Path(entry.path) for entry in entries),
                key=lambda path: path.name,
            )
    except OSError as exc:
        raise RuntimeError(
            f"Policy directory {POLICY_DIR} cannot be read; "
            "refusing to load an undefined policy set"
        ) from exc

    for f in (path for path in discovered if path.suffix == ".yaml"):
        try:
            content = f.read_text(encoding="utf-8")
        except Exception as exc:
            errors.append((f.name, exc))
            continue

        try:
            policy = local_engine.load_yaml(content)
            governance_count += 1
            effective_rule_count += sum(rule.enabled for rule in policy.rules)
            logger.info("Loaded governance policy: %s", f.name)
        except Exception as ge:
            try:
                raw = yaml.safe_load(content)
                if not isinstance(raw, dict):
                    raise ValueError("policy document must be a mapping")
                if "kind" in raw or "apiVersion" in raw:
                    raise ValueError(
                        "governance-shaped document was not accepted by the "
                        "governance policy parser"
                    )
                governance_keys = sorted(_GOVERNANCE_ONLY_KEYS.intersection(raw))
                if governance_keys:
                    raise ValueError(
                        "governance-only fields are not valid in a trust policy: "
                        + ", ".join(governance_keys)
                    )
                tp = TrustPolicy(**raw)
                if not tp.rules:
                    raise ValueError("trust policy must contain at least one rule")
                local_trust.append(tp)
                logger.info("Loaded trust policy: %s", f.name)
            except Exception as trust_exc:
                errors.append(
                    (
                        f.name,
                        RuntimeError(
                            f"not a governance policy ({type(ge).__name__}: {ge}); "
                            f"not a trust policy ({type(trust_exc).__name__}: {trust_exc})"
                        ),
                    )
                )

    for f in (path for path in discovered if path.suffix == ".json"):
        try:
            policy = local_engine.load_json(f.read_text(encoding="utf-8"))
            governance_count += 1
            effective_rule_count += sum(rule.enabled for rule in policy.rules)
        except Exception as exc:
            errors.append((f.name, exc))

    if errors:
        for name, exc in errors:
            logger.error("Policy load failed for %s: %s", name, exc)
        raise RuntimeError(
            f"{len(errors)} policy file(s) failed to load: " + ", ".join(name for name, _ in errors)
        )

    # All loaded successfully -- swap globals atomically.
    _engine = local_engine
    _trust_policies = local_trust

    # Clear or replace the trust evaluator so a reload without trust
    # policies does not keep a stale evaluator from the previous load.
    _trust_evaluator = PolicyEvaluator(_trust_policies) if _trust_policies else None

    _loaded_count = governance_count + len(_trust_policies)
    _effective_rule_count = effective_rule_count + sum(
        len(policy.rules) for policy in _trust_policies
    )
    logger.info(
        "Loaded %d governance + %d trust policies",
        governance_count,
        len(_trust_policies),
    )
    _validate_load_warnings()


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
        "effective_rules": _effective_rule_count,
        "trust_policies": len(_trust_policies),
        "policy_dir": POLICY_DIR,
        "load_warnings": list(_load_warnings),
    }


@app.post("/api/v1/policy/reload", tags=["policy"])
async def reload_policies() -> dict[str, Any]:
    """Reload policies from disk."""
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
        "effective_rules": _effective_rule_count,
        "trust_policies": len(_trust_policies),
        "load_warnings": list(_load_warnings),
    }


def main() -> None:
    run_server(app, default_port=8444)


if __name__ == "__main__":
    main()
