# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Cedar Policy Adapter

Evaluates policies written in Cedar (AWS's authorization policy language)
alongside the existing YAML/JSON and OPA/Rego engines.

Three modes:
  1. **cedarpy** — Python bindings to the Rust Cedar engine (fastest, requires ``pip install cedarpy``)
  2. **CLI** — Calls ``cedar authorize`` subprocess (requires Cedar CLI installed)
  3. **Built-in** — Simple pattern evaluator for common permit/forbid rules (no external deps)

Why Cedar?
  Enterprises standardized on AWS Cedar for authorization won't adopt a
  new policy DSL. Supporting Cedar lets them reuse existing policies for
  agent governance without political or operational overhead.

Usage:
    from agentmesh.governance.cedar import CedarEvaluator

    # Built-in mode (no external deps)
    evaluator = CedarEvaluator(policy_content='''
        permit(
            principal,
            action == Action::"ReadData",
            resource
        );
        forbid(
            principal,
            action == Action::"DeleteFile",
            resource
        );
    ''')
    decision = evaluator.evaluate("Action::\"ReadData\"", {"agent": {"role": "analyst"}})

    # With cedarpy bindings
    evaluator = CedarEvaluator(mode="cedarpy", policy_path="policies/mesh.cedar")
    decision = evaluator.evaluate(
        "Action::\"Export\"",
        {"agent_did": "did:example:1", "resource": "Resource::\"dataset\""},
    )

    # Integrated with PolicyEngine
    from agentmesh.governance.policy import PolicyEngine
    engine = PolicyEngine()
    engine.load_cedar("policies/mesh.cedar")
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Optional

logger = logging.getLogger(__name__)


@dataclass
class CedarDecision:
    """Result from a Cedar policy evaluation.

    Attributes:
        allowed: Whether the policy permits the action.
        raw_result: Raw response from the Cedar engine.
        action: The Cedar action that was evaluated.
        evaluation_ms: Evaluation latency in milliseconds.
        source: How the evaluation was performed.
        error: Error message if evaluation failed, otherwise ``None``.
    """

    allowed: bool
    raw_result: Any = None
    action: str = ""
    evaluation_ms: float = 0.0
    source: Literal["cedarpy", "cli", "builtin", "fallback"] = "builtin"
    error: Optional[str] = None


class CedarEvaluator:
    """
    Evaluate Cedar policies for AgentMesh governance.

    Supports three modes (auto-detected by default):
      - cedarpy: Python bindings to Rust Cedar engine
      - cli: ``cedar`` CLI subprocess
      - builtin: Simple pattern matcher for permit/forbid rules
    """

    def __init__(
        self,
        mode: Literal["auto", "cedarpy", "cli", "builtin"] = "auto",
        policy_path: Optional[str] = None,
        policy_content: Optional[str] = None,
        entities: Optional[list[dict[str, Any]]] = None,
        entities_path: Optional[str] = None,
        schema_path: Optional[str] = None,
        timeout_seconds: float = 5.0,
    ):
        """Initialize the Cedar evaluator.

        Args:
            mode: Evaluation mode. ``"auto"`` tries cedarpy → CLI → builtin.
            policy_path: Path to a ``.cedar`` policy file.
            policy_content: Inline Cedar policy string.
            entities: Entities list for authorization context.
            entities_path: Path to Cedar entities JSON file.
            schema_path: Path to Cedar schema file.
            timeout_seconds: Maximum time to wait for evaluation.
        """
        self.mode = mode
        self.policy_path = policy_path
        self.policy_content = policy_content
        self.entities = entities or []
        self.schema_path = schema_path
        self.timeout_seconds = timeout_seconds

        # Eagerly load policy content
        if policy_path and not policy_content and Path(policy_path).exists():
            self.policy_content = Path(policy_path).read_text()

        # Eagerly load entities
        if entities_path and not entities and Path(entities_path).exists():
            self.entities = json.loads(Path(entities_path).read_text())

        # Detect available engines
        self._cedarpy_available = self._check_cedarpy()
        self._cli_available = shutil.which("cedar") is not None

    @staticmethod
    def _check_cedarpy() -> bool:
        try:
            import cedarpy  # noqa: F401
            return True
        except ImportError:
            return False

    def evaluate(self, action: str, context: dict) -> CedarDecision:
        """
        Evaluate a Cedar authorization request.

        Args:
            action: Cedar action string (e.g., ``Action::"ReadData"``)
            context: Input context for evaluation, should include
                ``agent_did`` or ``principal`` and ``resource`` keys.

        Returns:
            CedarDecision with the result.
        """
        start = datetime.now(timezone.utc)

        try:
            if self.mode == "cedarpy" or (
                self.mode == "auto" and self._cedarpy_available
            ):
                result = self._evaluate_cedarpy(action, context)
            elif self.mode == "cli" or (
                self.mode == "auto" and self._cli_available
            ):
                result = self._evaluate_cli(action, context)
            else:
                result = self._evaluate_builtin(action, context)

            elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000
            result.evaluation_ms = elapsed
            return result

        except Exception as e:
            elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000
            logger.error(f"Cedar evaluation failed: {e}")
            return CedarDecision(
                allowed=False,
                action=action,
                evaluation_ms=elapsed,
                source="fallback",
                error=str(e),
            )

    def _build_request(self, action: str, context: dict) -> dict[str, Any]:
        """Build a Cedar authorization request from context."""
        principal = context.get("agent_did", context.get("principal", "Agent::\"anonymous\""))
        resource = context.get("resource", "Resource::\"default\"")

        if "::" not in str(principal):
            principal = f'Agent::"{principal}"'
        if "::" not in str(resource):
            resource = f'Resource::"{resource}"'
        if "::" not in str(action):
            action = f'Action::"{action}"'

        return {
            "principal": principal,
            "action": action,
            "resource": resource,
            "context": {
                k: v for k, v in context.items()
                if k not in ("agent_did", "principal", "resource")
            },
        }

    def _evaluate_cedarpy(self, action: str, context: dict) -> CedarDecision:
        """Evaluate via cedarpy Python bindings."""
        import cedarpy

        request = self._build_request(action, context)
        response = cedarpy.is_authorized(
            request=cedarpy.AuthorizationRequest(
                principal=request["principal"],
                action=request["action"],
                resource=request["resource"],
                context=request["context"],
            ),
            policies=self.policy_content or "",
            entities=self.entities,
        )
        allowed = response.decision == cedarpy.Decision.ALLOW
        return CedarDecision(
            allowed=allowed,
            raw_result={
                "decision": str(response.decision),
                "diagnostics": str(response.diagnostics) if hasattr(response, "diagnostics") else None,
            },
            action=action,
            source="cedarpy",
        )

    def _evaluate_cli(self, action: str, context: dict) -> CedarDecision:
        """Evaluate via cedar CLI subprocess."""
        request = self._build_request(action, context)

        with tempfile.TemporaryDirectory() as tmpdir:
            policy_file = Path(tmpdir) / "policy.cedar"
            policy_file.write_text(self.policy_content or "")

            entities_file = Path(tmpdir) / "entities.json"
            entities_file.write_text(json.dumps(self.entities))

            request_file = Path(tmpdir) / "request.json"
            request_file.write_text(json.dumps(request))

            cmd = [
                "cedar", "authorize",
                "--policies", str(policy_file),
                "--entities", str(entities_file),
                "--request-json", str(request_file),
            ]
            if self.schema_path:
                cmd.extend(["--schema", self.schema_path])

            try:
                proc = subprocess.run(  # noqa: S603 — trusted subprocess for Cedar policy engine
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                )
                output = proc.stdout.strip().lower()
                allowed = "allow" in output and "deny" not in output
                return CedarDecision(
                    allowed=allowed,
                    raw_result={"stdout": proc.stdout, "stderr": proc.stderr},
                    action=action,
                    source="cli",
                )
            except subprocess.TimeoutExpired:
                return CedarDecision(
                    allowed=False,
                    action=action,
                    source="cli",
                    error="cedar authorize timed out",
                )

    def _evaluate_builtin(self, action: str, context: dict) -> CedarDecision:
        """
        Built-in Cedar pattern evaluator for common permit/forbid rules.

        Parses simple Cedar policy patterns:
          - permit(principal, action == Action::"X", resource);
          - forbid(principal, action == Action::"X", resource);
          - permit(principal, action, resource);  // catch-all
        """
        if not self.policy_content:
            return CedarDecision(
                allowed=False, action=action, source="builtin",
                error="No Cedar policy content",
            )

        # Normalize action for matching
        if "::" not in action:
            action_normalized = f'Action::"{action}"'
        else:
            action_normalized = action

        statements = _parse_cedar_statements(self.policy_content)

        has_permit = False
        for stmt in statements:
            constraint = stmt["action_constraint"]
            if constraint and constraint != action_normalized:
                continue  # Doesn't apply

            if stmt["effect"] == "forbid":
                return CedarDecision(
                    allowed=False,
                    raw_result={"matched": stmt["raw"]},
                    action=action,
                    source="builtin",
                )
            elif stmt["effect"] == "permit":
                has_permit = True

        return CedarDecision(
            allowed=has_permit,
            raw_result={"statements_checked": len(statements)},
            action=action,
            source="builtin",
        )


# ── Helpers ───────────────────────────────────────────────────


def _parse_cedar_statements(content: str) -> list[dict[str, Any]]:
    """Parse Cedar permit/forbid statements from policy content."""
    statements: list[dict[str, Any]] = []
    pattern = re.compile(
        r'(permit|forbid)\s*\((.*?)\)\s*;',
        re.DOTALL,
    )

    for match in pattern.finditer(content):
        effect = match.group(1)
        body = match.group(2)
        action_match = re.search(r'action\s*==\s*Action::"([^"]+)"', body)
        action_constraint = (
            f'Action::"{action_match.group(1)}"' if action_match else None
        )
        statements.append({
            "effect": effect,
            "action_constraint": action_constraint,
            "raw": match.group(0),
        })

    return statements


def load_cedar_into_engine(
    engine: Any,
    cedar_path: str,
    entities: Optional[list[dict[str, Any]]] = None,
) -> CedarEvaluator:
    """
    Register a .cedar file with the existing PolicyEngine.

    Usage:
        from agentmesh.governance.policy import PolicyEngine
        from agentmesh.governance.cedar import load_cedar_into_engine

        engine = PolicyEngine()
        cedar = load_cedar_into_engine(engine, "policies/mesh.cedar")

        decision = cedar.evaluate('Action::"Export"', {"agent_did": "did:example:1"})
    """
    content = Path(cedar_path).read_text() if Path(cedar_path).exists() else None
    evaluator = CedarEvaluator(
        mode="auto",
        policy_path=cedar_path,
        policy_content=content,
        entities=entities,
    )
    return evaluator
