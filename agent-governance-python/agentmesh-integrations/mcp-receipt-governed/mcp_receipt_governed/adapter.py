# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
MCP Receipt Adapter — wraps MCP tool calls with Cedar policy evaluation
and governance receipt signing.

Usage:
    adapter = McpReceiptAdapter(
        cedar_policy=\"\"\"
            permit(principal, action == Action::"ReadData", resource);
            forbid(principal, action == Action::"DeleteFile", resource);
        \"\"\",
        cedar_policy_id="policy:mcp-tools:v1",
        signing_key_hex="<32-byte-hex-seed>",  # Ed25519 seed
    )

    # Wrap an MCP tool call
    receipt = adapter.govern_tool_call(
        agent_did="did:mesh:agent-1",
        tool_name="read_file",
        tool_args={"path": "/data/report.csv"},
    )

    if receipt.cedar_decision == "allow":
        # Proceed with tool execution
        ...
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

from mcp_receipt_governed.receipt import (
    GovernanceReceipt,
    ReceiptStore,
    hash_tool_args,
    sign_receipt,
)

_logger = logging.getLogger(__name__)


class CedarPolicyEvaluator:
    """Lightweight Cedar policy evaluator for receipt governance.

    Uses the built-in pattern matcher from ``agentmesh.governance.cedar``
    when available, otherwise falls back to a simple permit/forbid parser.

    This avoids hard-coupling to the full CedarEvaluator import path while
    remaining compatible with it.
    """

    def __init__(
        self,
        policy_content: Optional[str] = None,
        policy_id: str = "default",
    ) -> None:
        self.policy_content = policy_content or ""
        self.policy_id = policy_id
        self._evaluator: Any = None
        self._init_evaluator()

    def _init_evaluator(self) -> None:
        """Try to initialize the full CedarEvaluator; fall back to inline."""
        try:
            from agentmesh.governance.cedar import CedarEvaluator

            self._evaluator = CedarEvaluator(
                mode="builtin",
                policy_content=self.policy_content,
            )
            _logger.debug("Using agentmesh CedarEvaluator (builtin mode)")
        except ImportError:
            _logger.debug("agentmesh not available — using inline Cedar evaluator")
            self._evaluator = None

    def evaluate(self, action: str, context: Dict[str, Any]) -> bool:
        """Evaluate a Cedar action against the loaded policy.

        Args:
            action: Cedar action string (e.g., ``"ReadData"``).
            context: Evaluation context with ``agent_did``, ``resource``, etc.

        Returns:
            ``True`` if the action is permitted, ``False`` otherwise.
        """
        if self._evaluator is not None:
            decision = self._evaluator.evaluate(action, context)
            return decision.allowed

        # Inline fallback: simple permit/forbid parsing
        return self._evaluate_inline(action)

    def _evaluate_inline(self, action: str) -> bool:
        """Minimal permit/forbid parser for when agentmesh is not installed."""
        import re

        action_normalized = action
        if "::" not in action:
            action_normalized = f'Action::"{action}"'

        # Check for explicit forbid first (forbid wins)
        forbid_pattern = re.compile(
            r'forbid\s*\(.*?action\s*==\s*Action::"([^"]+)".*?\)\s*;',
            re.DOTALL,
        )
        for match in forbid_pattern.finditer(self.policy_content):
            matched_action = f'Action::"{match.group(1)}"'
            if matched_action == action_normalized:
                return False

        # Check for explicit permit
        permit_pattern = re.compile(
            r'permit\s*\(.*?action\s*==\s*Action::"([^"]+)".*?\)\s*;',
            re.DOTALL,
        )
        for match in permit_pattern.finditer(self.policy_content):
            matched_action = f'Action::"{match.group(1)}"'
            if matched_action == action_normalized:
                return True

        # Check for catch-all permit
        catch_all = re.compile(
            r'permit\s*\(\s*principal\s*,\s*action\s*,\s*resource\s*\)\s*;',
            re.DOTALL,
        )
        if catch_all.search(self.policy_content):
            return True

        # Default deny
        return False


class McpReceiptAdapter:
    """Wraps MCP tool calls with Cedar policy evaluation and receipt signing.

    For every tool call, the adapter:
      1. Evaluates the Cedar policy for the requested action.
      2. Creates a ``GovernanceReceipt`` recording the decision.
      3. Signs the receipt with the provided Ed25519 key.
      4. Stores the receipt in the ``ReceiptStore`` audit trail.

    Args:
        cedar_policy: Cedar policy content string.
        cedar_policy_id: Human-readable identifier for the policy.
        signing_key_hex: Hex-encoded 32-byte Ed25519 seed for receipt signing.
            If ``None``, receipts are created but not signed.
        store: Optional ``ReceiptStore`` instance. Creates a new one if omitted.
    """

    def __init__(
        self,
        cedar_policy: str = "",
        cedar_policy_id: str = "default",
        signing_key_hex: Optional[str] = None,
        store: Optional[ReceiptStore] = None,
    ) -> None:
        self._evaluator = CedarPolicyEvaluator(
            policy_content=cedar_policy,
            policy_id=cedar_policy_id,
        )
        self._policy_id = cedar_policy_id
        self._signing_key = signing_key_hex
        self.store = store or ReceiptStore()

    def govern_tool_call(
        self,
        agent_did: str,
        tool_name: str,
        tool_args: Optional[Dict[str, Any]] = None,
        resource: str = "Resource::\"default\"",
    ) -> GovernanceReceipt:
        """Evaluate policy and create a signed governance receipt.

        Args:
            agent_did: DID of the calling agent.
            tool_name: Name of the MCP tool being invoked.
            tool_args: Arguments to the tool call (hashed, not stored raw).
            resource: Cedar resource string for policy evaluation.

        Returns:
            A signed ``GovernanceReceipt`` recording the policy decision.
        """
        # 1. Evaluate Cedar policy
        context = {"agent_did": agent_did, "resource": resource}
        allowed = self._evaluator.evaluate(tool_name, context)

        # 2. Create receipt
        receipt = GovernanceReceipt(
            tool_name=tool_name,
            agent_did=agent_did,
            cedar_policy_id=self._policy_id,
            cedar_decision="allow" if allowed else "deny",
            args_hash=hash_tool_args(tool_args),
        )

        # 3. Sign receipt (if key provided)
        if self._signing_key:
            try:
                sign_receipt(receipt, self._signing_key)
            except Exception as exc:
                _logger.error(f"Receipt signing failed: {type(exc).__name__}")
                receipt.error = f"signing_failed: {type(exc).__name__}"

        # 4. Store receipt
        self.store.add(receipt)

        return receipt

    def govern_and_execute(
        self,
        agent_did: str,
        tool_name: str,
        tool_fn: Callable[..., Any],
        tool_args: Optional[Dict[str, Any]] = None,
        resource: str = "Resource::\"default\"",
    ) -> tuple[GovernanceReceipt, Any]:
        """Evaluate policy, create receipt, and execute the tool if allowed.

        This is the full lifecycle method: check → receipt → execute (if allowed).

        Args:
            agent_did: DID of the calling agent.
            tool_name: Name of the MCP tool.
            tool_fn: The actual tool function to call.
            tool_args: Arguments to pass to ``tool_fn``.
            resource: Cedar resource for policy evaluation.

        Returns:
            Tuple of (receipt, tool_result). ``tool_result`` is ``None`` if denied.
        """
        receipt = self.govern_tool_call(agent_did, tool_name, tool_args, resource)

        if receipt.cedar_decision == "allow":
            try:
                result = tool_fn(**(tool_args or {}))
            except Exception as exc:
                _logger.error(f"Tool execution failed: {exc}")
                receipt.error = f"execution_failed: {exc}"
                result = None
        else:
            result = None

        return receipt, result

    def get_receipts(self) -> List[GovernanceReceipt]:
        """Return all receipts from the store."""
        return self.store.query()

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregate receipt statistics."""
        return self.store.get_stats()
