# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
External policy backends for Agent-OS governance.

Provides a pluggable interface for evaluating policies written in
external policy languages (OPA/Rego, Cedar) alongside the native
YAML/JSON PolicyDocument engine.

Usage:
    from agent_os.policies.backends import OPABackend, CedarBackend

    evaluator = PolicyEvaluator()
    evaluator.load_policies("policies/")

    # Add OPA/Rego policies
    evaluator.add_backend(OPABackend(rego_path="policies/agent.rego"))

    # Add Cedar policies
    evaluator.add_backend(CedarBackend(policy_path="policies/agent.cedar"))

    # evaluate() checks YAML rules first, then external backends
    decision = evaluator.evaluate(context)
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


# ── Protocol ──────────────────────────────────────────────────


@runtime_checkable
class ExternalPolicyBackend(Protocol):
    """Interface for external policy evaluation backends.

    Implementations translate between the toolkit's execution context
    and an external policy language (OPA/Rego, Cedar, etc.), returning
    a normalized decision.
    """

    @property
    def name(self) -> str:
        """Human-readable backend name (e.g., ``"opa"``, ``"cedar"``)."""
        ...

    def evaluate(self, context: dict[str, Any]) -> BackendDecision:
        """Evaluate the external policy against the given context.

        Args:
            context: Execution context dict with fields like
                ``tool_name``, ``agent_id``, ``token_count``, etc.

        Returns:
            A ``BackendDecision`` with the result.
        """
        ...


@dataclass
class BackendDecision:
    """Normalized result from an external policy backend."""

    allowed: bool
    action: str = "allow"
    reason: str = ""
    backend: str = ""
    raw_result: Any = None
    evaluation_ms: float = 0.0
    error: Optional[str] = None


# ── OPA/Rego Backend ─────────────────────────────────────────


class OPABackend:
    """Evaluate OPA/Rego policies for Agent-OS.

    Supports three modes:
      1. **Remote OPA server** — POST to ``http://host:8181/v1/data/...``
      2. **Local ``opa eval`` CLI** — subprocess call
      3. **Built-in fallback** — parses simple Rego patterns without external deps

    Args:
        mode: ``"remote"`` or ``"local"`` (default).
        opa_url: Base URL for remote OPA server.
        rego_path: Path to a ``.rego`` file.
        rego_content: Inline Rego policy string.
        package: Rego package name for query construction.
        query: Explicit Rego query (overrides package-based construction).
        timeout_seconds: Max evaluation time.

    Example:
        >>> backend = OPABackend(rego_content='''
        ... package agentos
        ... default allow = false
        ... allow { input.tool_name != "file_delete" }
        ... ''')
        >>> decision = backend.evaluate({"tool_name": "file_read"})
        >>> decision.allowed
        True
    """

    def __init__(
        self,
        mode: Literal["remote", "local"] = "local",
        opa_url: str = "http://localhost:8181",
        rego_path: Optional[str] = None,
        rego_content: Optional[str] = None,
        package: str = "agentos",
        query: Optional[str] = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self._mode = mode
        self._opa_url = opa_url.rstrip("/")
        self._rego_path = rego_path
        self._rego_content = rego_content
        self._package = package
        self._query = query or f"data.{package}.allow"
        self._timeout = timeout_seconds
        self._opa_available = shutil.which("opa") is not None

        # Eagerly load rego content from file
        if rego_path and not rego_content and Path(rego_path).exists():
            self._rego_content = Path(rego_path).read_text()

    @property
    def name(self) -> str:
        return "opa"

    def evaluate(self, context: dict[str, Any]) -> BackendDecision:
        start = datetime.now(timezone.utc)
        try:
            if self._mode == "remote":
                result = self._evaluate_remote(context)
            else:
                result = self._evaluate_local(context)
            result.evaluation_ms = (
                datetime.now(timezone.utc) - start
            ).total_seconds() * 1000
            return result
        except Exception as e:
            elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000
            logger.error("OPA evaluation failed: %s", e)
            return BackendDecision(
                allowed=False,
                action="deny",
                reason=f"OPA evaluation error: {e}",
                backend="opa",
                evaluation_ms=elapsed,
                error=str(e),
            )

    def _evaluate_remote(self, context: dict[str, Any]) -> BackendDecision:
        import urllib.request

        path_parts = (
            self._query.replace("data.", "", 1).replace(".", "/")
            if self._query.startswith("data.")
            else self._query.replace(".", "/")
        )
        url = f"{self._opa_url}/v1/data/{path_parts}"
        payload = json.dumps({"input": context}).encode()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                body = json.loads(resp.read().decode())
                result_value = body.get("result", False)
                allowed = bool(result_value)
                return BackendDecision(
                    allowed=allowed,
                    action="allow" if allowed else "deny",
                    reason=f"OPA remote ({self._package}): {'allowed' if allowed else 'denied'}",
                    backend="opa",
                    raw_result=body,
                )
        except Exception as e:
            return BackendDecision(
                allowed=False,
                action="deny",
                reason=f"OPA server error: {e}",
                backend="opa",
                error=str(e),
            )

    def _evaluate_local(self, context: dict[str, Any]) -> BackendDecision:
        if self._opa_available and self._rego_content:
            return self._evaluate_cli(context)
        if self._rego_content:
            logger.warning(
                "OPA CLI not available — falling back to built-in regex evaluation. "
                "Install OPA CLI for full policy evaluation: https://www.openpolicyagent.org/docs/latest/#running-opa"
            )
            return self._evaluate_builtin(context)
        return BackendDecision(
            allowed=False,
            action="deny",
            reason="No Rego content or OPA CLI available",
            backend="opa",
            error="No rego file or OPA CLI available",
        )

    def _evaluate_cli(self, context: dict[str, Any]) -> BackendDecision:
        input_json = json.dumps(context)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rego", delete=False
        ) as f:
            f.write(self._rego_content)
            rego_file = f.name

        cmd = [
            "opa", "eval", "--format", "json",
            "--input", "/dev/stdin",
            "--data", rego_file,
            self._query,
        ]
        try:
            proc = subprocess.run(
                cmd,
                input=input_json,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
            if proc.returncode != 0:
                return BackendDecision(
                    allowed=False,
                    action="deny",
                    reason=f"opa eval failed: {proc.stderr.strip()}",
                    backend="opa",
                    error=proc.stderr.strip(),
                )
            result = json.loads(proc.stdout)
            expressions = result.get("result", [{}])[0].get("expressions", [{}])
            value = expressions[0].get("value", False) if expressions else False
            allowed = bool(value)
            return BackendDecision(
                allowed=allowed,
                action="allow" if allowed else "deny",
                reason=f"OPA local ({self._package}): {'allowed' if allowed else 'denied'}",
                backend="opa",
                raw_result=result,
            )
        except subprocess.TimeoutExpired:
            return BackendDecision(
                allowed=False,
                action="deny",
                reason="OPA eval timed out",
                backend="opa",
                error="timeout",
            )
        finally:
            Path(rego_file).unlink(missing_ok=True)

    def _evaluate_builtin(self, context: dict[str, Any]) -> BackendDecision:
        """Built-in simple Rego evaluator for common patterns."""
        target_rule = self._query.split(".")[-1]

        # Parse defaults
        defaults: dict[str, bool] = {}
        for line in self._rego_content.split("\n"):
            stripped = line.strip()
            if stripped.startswith("default "):
                parts = stripped.replace("default ", "").split("=")
                if len(parts) == 2:
                    key = parts[0].strip()
                    val = parts[1].strip().lower()
                    defaults[key] = val == "true"

        result = defaults.get(target_rule, False)
        in_rule = False
        rule_conditions: list[str] = []

        for line in self._rego_content.split("\n"):
            stripped = line.strip()
            if stripped.startswith(f"{target_rule} {{"):
                if stripped.endswith("}"):
                    body = stripped[len(target_rule) + 2 : -1].strip()
                    if self._eval_condition(body, context):
                        result = True
                else:
                    in_rule = True
                    rule_conditions = []
                continue
            if in_rule:
                if stripped == "}":
                    if rule_conditions and all(
                        self._eval_condition(c, context) for c in rule_conditions
                    ):
                        result = True
                    in_rule = False
                    rule_conditions = []
                elif stripped and not stripped.startswith("#"):
                    rule_conditions.append(stripped)

        allowed = bool(result)
        return BackendDecision(
            allowed=allowed,
            action="allow" if allowed else "deny",
            reason=f"OPA builtin ({self._package}): {'allowed' if allowed else 'denied'}",
            backend="opa",
            raw_result={"parsed": True},
        )

    def _eval_condition(self, condition: str, ctx: dict[str, Any]) -> bool:
        condition = condition.strip().rstrip(";")
        if condition.startswith("not "):
            return not self._eval_condition(condition[4:], ctx)
        if "==" in condition:
            left, right = [x.strip() for x in condition.split("==", 1)]
            left_val = self._resolve_path(left, ctx)
            right_val = right.strip('"').strip("'")
            if right_val == "true":
                return left_val is True
            if right_val == "false":
                return left_val is False
            return str(left_val) == right_val
        if "!=" in condition:
            left, right = [x.strip() for x in condition.split("!=", 1)]
            left_val = self._resolve_path(left, ctx)
            right_val = right.strip('"').strip("'")
            return str(left_val) != right_val
        val = self._resolve_path(condition, ctx)
        return bool(val)

    @staticmethod
    def _resolve_path(path: str, data: dict[str, Any]) -> Any:
        parts = path.split(".")
        current: Any = data
        for part in parts:
            if part == "input":
                continue
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current


# ── Cedar Backend ─────────────────────────────────────────────


class CedarBackend:
    """Evaluate Cedar policies for Agent-OS.

    Cedar is AWS's authorization policy language. This backend lets
    enterprises that standardize on Cedar reuse their existing policies
    for agent governance.

    Supports three modes:
      1. **cedarpy** — Python bindings to the Rust Cedar engine (fastest)
      2. **CLI** — ``cedar`` CLI subprocess
      3. **Built-in** — simple pattern matcher for common Cedar patterns

    Args:
        policy_path: Path to a ``.cedar`` policy file.
        policy_content: Inline Cedar policy string.
        entities_path: Path to Cedar entities JSON file.
        entities: Entities list for authorization context.
        schema_path: Path to Cedar schema file.
        mode: ``"auto"`` tries cedarpy → CLI → builtin.
        timeout_seconds: Max evaluation time.

    Example:
        >>> backend = CedarBackend(policy_content='''
        ... permit(
        ...     principal,
        ...     action == Action::"ReadData",
        ...     resource
        ... );
        ... forbid(
        ...     principal,
        ...     action == Action::"DeleteFile",
        ...     resource
        ... );
        ... ''')
        >>> decision = backend.evaluate({
        ...     "tool_name": "read_data",
        ...     "agent_id": "agent-1",
        ... })
        >>> decision.allowed
        True
    """

    def __init__(
        self,
        policy_path: Optional[str] = None,
        policy_content: Optional[str] = None,
        entities_path: Optional[str] = None,
        entities: Optional[list[dict[str, Any]]] = None,
        schema_path: Optional[str] = None,
        mode: Literal["auto", "cedarpy", "cli", "builtin"] = "auto",
        timeout_seconds: float = 5.0,
    ) -> None:
        self._policy_path = policy_path
        self._policy_content = policy_content
        self._entities_path = entities_path
        self._entities = entities or []
        self._schema_path = schema_path
        self._mode = mode
        self._timeout = timeout_seconds

        # Eagerly load policy content from file
        if policy_path and not policy_content and Path(policy_path).exists():
            self._policy_content = Path(policy_path).read_text()

        # Eagerly load entities from file
        if entities_path and not entities and Path(entities_path).exists():
            self._entities = json.loads(Path(entities_path).read_text())

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

    @property
    def name(self) -> str:
        return "cedar"

    def evaluate(self, context: dict[str, Any]) -> BackendDecision:
        start = datetime.now(timezone.utc)
        try:
            if self._mode == "cedarpy" or (
                self._mode == "auto" and self._cedarpy_available
            ):
                result = self._evaluate_cedarpy(context)
            elif self._mode == "cli" or (
                self._mode == "auto" and self._cli_available
            ):
                result = self._evaluate_cli(context)
            else:
                logger.warning(
                    "Neither cedarpy nor Cedar CLI available — falling back to built-in "
                    "pattern evaluation. Install cedar-py or the Cedar CLI for full evaluation."
                )
                result = self._evaluate_builtin(context)
            result.evaluation_ms = (
                datetime.now(timezone.utc) - start
            ).total_seconds() * 1000
            return result
        except Exception as e:
            elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000
            logger.error("Cedar evaluation failed: %s", e)
            return BackendDecision(
                allowed=False,
                action="deny",
                reason=f"Cedar evaluation error: {e}",
                backend="cedar",
                evaluation_ms=elapsed,
                error=str(e),
            )

    def _build_cedar_request(self, context: dict[str, Any]) -> dict[str, Any]:
        """Build a Cedar authorization request from execution context."""
        agent_id = context.get("agent_id", "Agent::\"anonymous\"")
        tool_name = context.get("tool_name", "unknown")
        resource = context.get("resource", "Resource::\"default\"")

        # Normalize to Cedar entity format
        if "::" not in str(agent_id):
            agent_id = f'Agent::"{agent_id}"'
        if "::" not in str(resource):
            resource = f'Resource::"{resource}"'

        # Map tool_name to Cedar action
        action_name = _tool_to_cedar_action(tool_name)

        return {
            "principal": agent_id,
            "action": f'Action::"{action_name}"',
            "resource": resource,
            "context": {k: v for k, v in context.items()
                        if k not in ("agent_id", "tool_name", "resource")},
        }

    def _evaluate_cedarpy(self, context: dict[str, Any]) -> BackendDecision:
        """Evaluate via cedarpy Python bindings."""
        import cedarpy

        request = self._build_cedar_request(context)
        response = cedarpy.is_authorized(
            request=cedarpy.AuthorizationRequest(
                principal=request["principal"],
                action=request["action"],
                resource=request["resource"],
                context=request["context"],
            ),
            policies=self._policy_content or "",
            entities=self._entities,
        )
        allowed = response.decision == cedarpy.Decision.ALLOW
        return BackendDecision(
            allowed=allowed,
            action="allow" if allowed else "deny",
            reason=f"Cedar (cedarpy): {'allowed' if allowed else 'denied'}",
            backend="cedar",
            raw_result={
                "decision": str(response.decision),
                "diagnostics": str(response.diagnostics) if hasattr(response, "diagnostics") else None,
            },
        )

    def _evaluate_cli(self, context: dict[str, Any]) -> BackendDecision:
        """Evaluate via cedar CLI subprocess."""
        request = self._build_cedar_request(context)

        with tempfile.TemporaryDirectory() as tmpdir:
            policy_file = Path(tmpdir) / "policy.cedar"
            policy_file.write_text(self._policy_content or "")

            entities_file = Path(tmpdir) / "entities.json"
            entities_file.write_text(json.dumps(self._entities))

            request_file = Path(tmpdir) / "request.json"
            request_file.write_text(json.dumps(request))

            cmd = [
                "cedar", "authorize",
                "--policies", str(policy_file),
                "--entities", str(entities_file),
                "--request-json", str(request_file),
            ]
            if self._schema_path:
                cmd.extend(["--schema", self._schema_path])

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self._timeout,
                )
                output = proc.stdout.strip().lower()
                allowed = "allow" in output and "deny" not in output
                return BackendDecision(
                    allowed=allowed,
                    action="allow" if allowed else "deny",
                    reason=f"Cedar CLI: {proc.stdout.strip()}",
                    backend="cedar",
                    raw_result={"stdout": proc.stdout, "stderr": proc.stderr},
                )
            except subprocess.TimeoutExpired:
                return BackendDecision(
                    allowed=False,
                    action="deny",
                    reason="Cedar CLI timed out",
                    backend="cedar",
                    error="timeout",
                )

    def _evaluate_builtin(self, context: dict[str, Any]) -> BackendDecision:
        """Built-in Cedar pattern evaluator for common permit/forbid rules.

        Parses simple Cedar policy patterns:
          - permit(principal, action == Action::"X", resource);
          - forbid(principal, action == Action::"X", resource);
          - permit(principal, action, resource);  // catch-all allow
        """
        if not self._policy_content:
            return BackendDecision(
                allowed=False,
                action="deny",
                reason="No Cedar policy content",
                backend="cedar",
                error="No policy content",
            )

        request = self._build_cedar_request(context)
        action_str = request["action"]

        # Parse all permit/forbid statements
        statements = _parse_cedar_statements(self._policy_content)

        # Cedar semantics: default deny, any forbid overrides permit
        has_permit = False

        for stmt in statements:
            if stmt["action_constraint"] and stmt["action_constraint"] != action_str:
                continue  # Action doesn't match this statement

            # Statement applies to this action
            if stmt["effect"] == "forbid":
                return BackendDecision(
                    allowed=False,
                    action="deny",
                    reason=f"Cedar builtin: forbid matched for {action_str}",
                    backend="cedar",
                    raw_result={"matched_statement": stmt},
                )
            elif stmt["effect"] == "permit":
                has_permit = True

        allowed = has_permit
        return BackendDecision(
            allowed=allowed,
            action="allow" if allowed else "deny",
            reason=f"Cedar builtin: {'permit matched' if allowed else 'no permit matched (default deny)'}",
            backend="cedar",
            raw_result={"statements_checked": len(statements)},
        )


# ── Cedar helpers ─────────────────────────────────────────────


def _tool_to_cedar_action(tool_name: str) -> str:
    """Map a toolkit tool_name to a Cedar action identifier.

    Converts snake_case tool names to PascalCase Cedar actions:
    ``file_read`` → ``FileRead``, ``execute_code`` → ``ExecuteCode``.
    """
    return "".join(part.capitalize() for part in tool_name.split("_"))


def _parse_cedar_statements(content: str) -> list[dict[str, Any]]:
    """Parse Cedar permit/forbid statements from policy content.

    Returns a list of dicts with keys: effect, action_constraint.
    """
    import re

    statements: list[dict[str, Any]] = []
    # Match permit(...) or forbid(...) blocks including multiline
    pattern = re.compile(
        r'(permit|forbid)\s*\((.*?)\)\s*;',
        re.DOTALL,
    )

    for match in pattern.finditer(content):
        effect = match.group(1)
        body = match.group(2)

        # Extract action constraint: action == Action::"SomeThing"
        action_match = re.search(
            r'action\s*==\s*Action::"([^"]+)"', body
        )
        action_constraint = (
            f'Action::"{action_match.group(1)}"' if action_match else None
        )

        statements.append({
            "effect": effect,
            "action_constraint": action_constraint,
            "raw": match.group(0),
        })

    return statements
