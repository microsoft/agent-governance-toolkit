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
        signing_key_hex="<32-byte-hex-seed>",
    )
    receipt = adapter.govern_tool_call(
        agent_did="did:mesh:agent-1",
        tool_name="read_file",
        tool_args={"path": "/data/report.csv"},
    )
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from mcp_receipt_governed.receipt import (
    GovernanceReceipt,
    ReceiptAuthorizationError,
    ReceiptSigningError,
    ReceiptStore,
    hash_tool_args,
    sign_receipt,
    verify_receipt_authorization,
)

_logger = logging.getLogger(__name__)


class CedarPolicyEvaluator:
    """Cedar policy evaluator with agentmesh fallback to inline permit/forbid parsing."""

    def __init__(self, policy_content: Optional[str] = None, policy_id: str = "default") -> None:
        self.policy_content = policy_content or ""
        self.policy_id = policy_id
        self._evaluator: Any = None
        try:
            from agentmesh.governance.cedar import CedarEvaluator
            self._evaluator = CedarEvaluator(mode="builtin", policy_content=self.policy_content)
        except ImportError:
            pass

    def evaluate(self, action: str, context: Dict[str, Any]) -> bool:
        if self._evaluator is not None:
            return self._evaluator.evaluate(action, context).allowed
        return self._evaluate_inline(action)

    def _evaluate_inline(self, action: str) -> bool:
        import re

        normalized = action if "::" in action else f'Action::"{action}"'

        forbid_re = re.compile(r'forbid\s*\(.*?action\s*==\s*Action::"([^"]+)".*?\)\s*;', re.DOTALL)
        if any(f'Action::"{m.group(1)}"' == normalized for m in forbid_re.finditer(self.policy_content)):
            return False

        permit_re = re.compile(r'permit\s*\(.*?action\s*==\s*Action::"([^"]+)".*?\)\s*;', re.DOTALL)
        if any(f'Action::"{m.group(1)}"' == normalized for m in permit_re.finditer(self.policy_content)):
            return True

        catch_all = re.compile(r"permit\s*\(\s*principal\s*,\s*action\s*,\s*resource\s*\)\s*;", re.DOTALL)
        return bool(catch_all.search(self.policy_content))


class McpReceiptAdapter:
    """Wraps MCP tool calls with Cedar policy evaluation and signed receipt creation.

    For every tool call: evaluate Cedar policy → create receipt → sign → store.
    Receipts are hash-chained via ``parent_receipt_hash``. Signing failure raises
    (fail-closed).
    """

    def __init__(
        self,
        cedar_policy: str = "",
        cedar_policy_id: str = "default",
        signing_key_hex: Optional[str] = None,
        store: Optional[ReceiptStore] = None,
        session_id: Optional[str] = None,
        external_authorizer: Optional[Callable[[GovernanceReceipt], GovernanceReceipt]] = None,
        trusted_authorizer_keys: Optional[List[str]] = None,
    ) -> None:
        if external_authorizer is not None and not signing_key_hex:
            raise ValueError("External authorization requires a receipt signing_key_hex.")
        if external_authorizer is not None and not trusted_authorizer_keys:
            raise ValueError("External authorization requires trusted_authorizer_keys.")
        if external_authorizer is None and trusted_authorizer_keys:
            raise ValueError("trusted_authorizer_keys requires an external_authorizer.")

        self._evaluator = CedarPolicyEvaluator(policy_content=cedar_policy, policy_id=cedar_policy_id)
        self._policy_id = cedar_policy_id
        self._signing_key = signing_key_hex
        self._session_id = session_id or str(uuid.uuid4())
        self._external_authorizer = external_authorizer
        self._trusted_authorizer_keys = tuple(trusted_authorizer_keys or ())
        self.store = store or ReceiptStore()

    def govern_tool_call(
        self,
        agent_did: str,
        tool_name: str,
        tool_args: Optional[Dict[str, Any]] = None,
        resource: str = 'Resource::"default"',
    ) -> GovernanceReceipt:
        """Evaluate policy and return a signed governance receipt (fail-closed on signing error)."""
        allowed = self._evaluator.evaluate(tool_name, {"agent_did": agent_did, "resource": resource})

        with self.store._lock:
            parent_hash = self.store._receipts[-1].payload_hash() if self.store._receipts else None

        receipt = GovernanceReceipt(
            tool_name=tool_name,
            agent_did=agent_did,
            cedar_policy_id=self._policy_id,
            cedar_decision="allow" if allowed else "deny",
            args_hash=hash_tool_args(tool_args),
            session_id=self._session_id,
            parent_receipt_hash=parent_hash,
        )

        if self._signing_key:
            try:
                sign_receipt(receipt, self._signing_key)
            except Exception as exc:
                _logger.error(f"Receipt signing failed: {type(exc).__name__}")
                raise ReceiptSigningError(
                    f"Receipt signing failed for tool={tool_name}: {type(exc).__name__}: {exc}"
                ) from exc

        if self._external_authorizer is not None:
            original_receipt = (
                receipt.payload_hash(),
                receipt.signature,
                receipt.signer_public_key,
            )
            signer_public_key = receipt.signer_public_key.lower()
            trusted_authorizer_keys = {
                key.lower() for key in self._trusted_authorizer_keys if isinstance(key, str)
            }
            if signer_public_key in trusted_authorizer_keys:
                raise ReceiptAuthorizationError(
                    "trusted_authorizer_keys must not contain the receipt signer key."
                )

            authorized_receipt = self._external_authorizer(receipt)
            if authorized_receipt is not receipt:
                raise ReceiptAuthorizationError(
                    "External authorizer must return the original receipt after authorizing it."
                )
            if original_receipt != (
                receipt.payload_hash(),
                receipt.signature,
                receipt.signer_public_key,
            ):
                raise ReceiptAuthorizationError(
                    "External authorizer modified the signed receipt or replaced its signer."
                )
            authorization_errors = verify_receipt_authorization(
                receipt,
                trusted_authorizer_keys=list(self._trusted_authorizer_keys),
                now=time.time(),
            )
            if authorization_errors:
                raise ReceiptAuthorizationError(
                    f"External authorization failed for tool={tool_name}: "
                    f"{'; '.join(authorization_errors)}"
                )

        self.store.add(receipt)
        return receipt

    def govern_and_execute(
        self,
        agent_did: str,
        tool_name: str,
        tool_fn: Callable[..., Any],
        tool_args: Optional[Dict[str, Any]] = None,
        resource: str = 'Resource::"default"',
    ) -> tuple[GovernanceReceipt, Any]:
        """Evaluate policy, create receipt, and execute the tool if allowed."""
        receipt = self.govern_tool_call(agent_did, tool_name, tool_args, resource)
        result = None
        if receipt.cedar_decision == "allow":
            try:
                result = tool_fn(**(tool_args or {}))
            except Exception as exc:
                _logger.error(f"Tool execution failed: {exc}")
                receipt.error = f"execution_failed: {exc}"
        return receipt, result

    def get_receipts(self) -> List[GovernanceReceipt]:
        return self.store.query()

    def get_stats(self) -> Dict[str, Any]:
        return self.store.get_stats()
