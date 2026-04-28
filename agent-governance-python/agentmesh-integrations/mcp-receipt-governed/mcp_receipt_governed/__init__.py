# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
mcp-receipt-governed: MCP tool-call receipt signing for AgentMesh governance.

Wraps MCP tool invocations with Cedar policy evaluation and produces signed
governance receipts linking the policy decision to the tool call.

Components:
- McpReceiptAdapter: Policy evaluation + receipt signing for MCP tool calls
- GovernanceReceipt: Signed proof of a governance decision
- ReceiptStore: In-memory audit trail with query capabilities
- verify_receipt_chain: Offline hash-chain and signature verification
"""

from mcp_receipt_governed.adapter import McpReceiptAdapter
from mcp_receipt_governed.receipt import (
    GovernanceReceipt,
    ReceiptSigningError,
    ReceiptStore,
    hash_tool_args,
    sign_receipt,
    verify_receipt,
    verify_receipt_chain,
)

__all__ = [
    "GovernanceReceipt",
    "McpReceiptAdapter",
    "ReceiptSigningError",
    "ReceiptStore",
    "hash_tool_args",
    "sign_receipt",
    "verify_receipt",
    "verify_receipt_chain",
]
