# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
OPA/Rego Policy Adapter

Evaluates policies written in Rego (Open Policy Agent's policy language)
alongside the existing YAML/JSON engine.

Two modes:
  1. **Remote OPA** — Sends queries to an OPA server (e.g., http://localhost:8181)
  2. **Embedded Rego** — Evaluates .rego files locally via subprocess call to `opa eval`

Why OPA/Rego?
  Every Kubernetes platform engineer knows OPA. Supporting Rego lets
  teams reuse their existing infra policies for agent governance.

Usage:
    from agentmesh.governance.opa import OPAEvaluator

    # Remote OPA server
    evaluator = OPAEvaluator(mode="remote", opa_url="http://localhost:8181")
    decision = evaluator.evaluate("agentmesh/allow", {"agent": {"role": "analyst"}, "action": "export"})

    # Local rego file
    evaluator = OPAEvaluator(mode="local", rego_path="policies/mesh.rego")
    decision = evaluator.evaluate("data.agentmesh.allow", {"input": {...}})

    # Integrated with PolicyEngine
    from agentmesh.governance.policy import PolicyEngine
    engine = PolicyEngine()
    engine.load_rego("policies/mesh.rego", package="agentmesh")
"""

from __future__ import annotations

import json
import logging
import subprocess
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Optional

logger = logging.getLogger(__name__)


@dataclass
class OPADecision:
    """Result from an OPA policy evaluation.

    Attributes:
        allowed: Whether the policy permits the action.
        raw_result: Raw response from the OPA engine.
        query: The Rego query that was evaluated.
        evaluation_ms: Evaluation latency in milliseconds.
        source: How the evaluation was performed
            (``"remote"``, ``"local"``, or ``"fallback"``).
        error: Error message if evaluation failed, otherwise ``None``.
    """
    allowed: bool
    raw_result: Any = None
    query: str = ""
    evaluation_ms: float = 0.0
    source: Literal["remote", "local", "fallback"] = "local"
    error: Optional[str] = None


class OPAEvaluator:
    """
    Evaluate Rego policies via OPA.

    Supports two modes:
    - remote: Queries an OPA REST API
    - local: Runs `opa eval` subprocess on .rego files
    """

    def __init__(
        self,
        mode: Literal["remote", "local"] = "local",
        opa_url: str = "http://localhost:8181",
        rego_path: Optional[str] = None,
        rego_content: Optional[str] = None,
        timeout_seconds: float = 5.0,
    ):
        """Initialise the OPA evaluator.

        Args:
            mode: Evaluation mode — ``"remote"`` queries an OPA REST
                API, ``"local"`` uses the ``opa eval`` CLI or a
                built-in fallback parser.
            opa_url: Base URL of the OPA server (remote mode only).
            rego_path: Path to a ``.rego`` policy file (local mode).
            rego_content: Inline Rego policy string (local mode).
            timeout_seconds: Maximum time to wait for evaluation.
        """
        self.mode = mode
        self.opa_url = opa_url.rstrip("/")
        self.rego_path = rego_path
        self.rego_content = rego_content
        self.timeout_seconds = timeout_seconds

        # Check if opa CLI is available for local mode
        self._opa_available = shutil.which("opa") is not None

    def evaluate(self, query: str, input_data: dict) -> OPADecision:
        """
        Evaluate a Rego query against input data.

        Args:
            query: Rego query (e.g., "data.agentmesh.allow")
            input_data: Input context for evaluation

        Returns:
            OPADecision with the result
        """
        start = datetime.now(timezone.utc)

        try:
            if self.mode == "remote":
                result = self._evaluate_remote(query, input_data)
            else:
                result = self._evaluate_local(query, input_data)

            elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000
            result.evaluation_ms = elapsed
            return result

        except Exception as e:
            elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000
            logger.error(f"OPA evaluation failed: {e}")
            return OPADecision(
                allowed=False,
                query=query,
                evaluation_ms=elapsed,
                source="fallback",
                error=str(e),
            )

    def _evaluate_remote(self, query: str, input_data: dict) -> OPADecision:
        """Query a remote OPA server via REST API."""
        import urllib.request
        from urllib.parse import quote

        # V32: Sanitise query path to prevent URL injection
        # Only allow alphanumeric, dots, underscores, hyphens in query
        import re as _re
        if not _re.fullmatch(r"[a-zA-Z0-9._\-]+", query):
            return OPADecision(
                allowed=False,
                query=query,
                source="remote",
                error=f"Invalid OPA query path: {query}",
            )

        # Convert query path to URL: "data.agentmesh.allow" -> "/v1/data/agentmesh/allow"
        path_parts = query.replace("data.", "", 1).replace(".", "/") if query.startswith("data.") else query.replace(".", "/")
        # URL-encode each segment as a safety net
        safe_path = "/".join(quote(seg, safe="") for seg in path_parts.split("/"))
        url = f"{self.opa_url}/v1/data/{safe_path}"

        payload = json.dumps({"input": input_data}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                result_value = body.get("result", False)
                allowed = bool(result_value) if isinstance(result_value, (bool, int)) else result_value is not None

                return OPADecision(
                    allowed=allowed,
                    raw_result=body,
                    query=query,
                    source="remote",
                )
        except Exception as e:
            return OPADecision(
                allowed=False,
                query=query,
                source="remote",
                error=f"OPA server error: {e}",
            )

    def _evaluate_local(self, query: str, input_data: dict) -> OPADecision:
        """Evaluate using local `opa eval` CLI or built-in fallback."""
        if self._opa_available and (self.rego_path or self.rego_content):
            return self._evaluate_opa_cli(query, input_data)

        # Fallback: parse simple Rego rules ourselves
        if self.rego_content:
            return self._evaluate_builtin(query, input_data)

        if self.rego_path and Path(self.rego_path).exists():
            self.rego_content = Path(self.rego_path).read_text()
            return self._evaluate_builtin(query, input_data)

        return OPADecision(
            allowed=False,
            query=query,
            source="fallback",
            error="No rego file or OPA CLI available",
        )

    def _evaluate_opa_cli(self, query: str, input_data: dict) -> OPADecision:
        """Run `opa eval` subprocess."""
        input_json = json.dumps(input_data)

        cmd = ["opa", "eval", "--format", "json", "--input", "/dev/stdin", "--data"]

        if self.rego_path:
            cmd.append(self.rego_path)
        else:
            # Write rego content to temp file
            import tempfile
            with tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False) as f:
                f.write(self.rego_content)
                cmd.append(f.name)

        cmd.append(query)

        try:
            proc = subprocess.run(
                cmd,
                input=input_json,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )

            if proc.returncode != 0:
                return OPADecision(
                    allowed=False,
                    query=query,
                    source="local",
                    error=f"opa eval failed: {proc.stderr.strip()}",
                )

            result = json.loads(proc.stdout)
            # OPA eval output: {"result": [{"expressions": [{"value": true}]}]}
            expressions = result.get("result", [{}])[0].get("expressions", [{}])
            value = expressions[0].get("value", False) if expressions else False
            allowed = bool(value) if isinstance(value, (bool, int)) else value is not None

            return OPADecision(
                allowed=allowed,
                raw_result=result,
                query=query,
                source="local",
            )
        except subprocess.TimeoutExpired:
            return OPADecision(
                allowed=False, query=query, source="local", error="opa eval timed out"
            )

    def _evaluate_builtin(self, query: str, input_data: dict) -> OPADecision:
        """
        Built-in simple Rego evaluator for common patterns.

        Supports:
        - default allow = false
        - allow { input.role == "admin" }
        - deny { input.action == "delete" }
        - allow { not input.pii }
        """
        if not self.rego_content:
            return OPADecision(allowed=False, query=query, source="fallback", error="No rego content")

        # Determine what we're querying
        target_rule = query.split(".")[-1]  # e.g., "allow" from "data.agentmesh.allow"

        # Parse defaults
        defaults = {}
        for line in self.rego_content.split("\n"):
            line = line.strip()
            if line.startswith("default "):
                # default allow = false
                parts = line.replace("default ", "").split("=")
                if len(parts) == 2:
                    key = parts[0].strip()
                    val = parts[1].strip().lower()
                    defaults[key] = val == "true"

        # Parse rule bodies
        result = defaults.get(target_rule, False)
        in_rule = False
        rule_conditions = []

        for line in self.rego_content.split("\n"):
            stripped = line.strip()

            # Match: allow { ... } or allow { (multiline)
            if stripped.startswith(f"{target_rule} {{"):
                # Single-line rule: allow { input.role == "admin" }
                if stripped.endswith("}"):
                    body = stripped[len(target_rule)+2:-1].strip()
                    if self._eval_rego_condition(body, input_data):
                        result = True
                else:
                    in_rule = True
                    rule_conditions = []
                continue

            if in_rule:
                if stripped == "}":
                    # Evaluate all conditions (AND)
                    if rule_conditions and all(
                        self._eval_rego_condition(c, input_data) for c in rule_conditions
                    ):
                        result = True
                    in_rule = False
                    rule_conditions = []
                elif stripped and not stripped.startswith("#"):
                    rule_conditions.append(stripped)

        return OPADecision(allowed=result, query=query, source="local", raw_result={"parsed": True})

    def _eval_rego_condition(self, condition: str, input_data: dict) -> bool:
        """Evaluate a single Rego condition line."""
        condition = condition.strip().rstrip(";")

        # not input.xxx
        if condition.startswith("not "):
            return not self._eval_rego_condition(condition[4:], input_data)

        # input.xxx == "value"
        if "==" in condition:
            left, right = [x.strip() for x in condition.split("==", 1)]
            left_val = self._resolve_rego_path(left, input_data)
            right_val = right.strip('"').strip("'")
            # Handle booleans
            if right_val == "true":
                return left_val is True
            if right_val == "false":
                return left_val is False
            return str(left_val) == right_val

        # input.xxx != "value"
        if "!=" in condition:
            left, right = [x.strip() for x in condition.split("!=", 1)]
            left_val = self._resolve_rego_path(left, input_data)
            right_val = right.strip('"').strip("'")
            return str(left_val) != right_val

        # input.xxx (truthy check)
        val = self._resolve_rego_path(condition, input_data)
        return bool(val)

    def _resolve_rego_path(self, path: str, input_data: dict) -> Any:
        """Resolve a Rego path like 'input.agent.role' to a value."""
        parts = path.split(".")
        current = input_data

        for part in parts:
            if part == "input":
                continue  # Skip the 'input' prefix
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current


# ── Integration with PolicyEngine ─────────────────────────────────


def load_rego_into_engine(engine: Any, rego_path: str, package: str = "agentmesh") -> OPAEvaluator:
    """
    Register a .rego file with the existing PolicyEngine.

    Usage:
        from agentmesh.governance.policy import PolicyEngine
        from agentmesh.governance.opa import load_rego_into_engine

        engine = PolicyEngine()
        opa = load_rego_into_engine(engine, "policies/mesh.rego")

        # Now evaluate via OPA
        decision = opa.evaluate(f"data.{package}.allow", {"agent": {"role": "admin"}})
    """
    content = Path(rego_path).read_text() if Path(rego_path).exists() else None
    evaluator = OPAEvaluator(
        mode="local",
        rego_path=rego_path,
        rego_content=content,
    )
    return evaluator
