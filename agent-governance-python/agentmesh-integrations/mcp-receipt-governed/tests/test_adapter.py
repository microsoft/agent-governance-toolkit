# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the McpReceiptAdapter.

These tests run without any external MCP SDK or AgentMesh installation.
They validate the governance adapter logic in isolation — policy evaluation,
receipt creation, signing, and the govern-and-execute lifecycle.
"""

import time

import pytest

from mcp_receipt_governed.adapter import McpReceiptAdapter
from mcp_receipt_governed.receipt import ReceiptAuthorizationError, authorize_receipt, sign_receipt


# ── Policy Evaluation ──


class TestPolicyEvaluation:
    """Test Cedar policy evaluation through the adapter."""

    POLICY = """
        permit(principal, action == Action::"ReadData", resource);
        permit(principal, action == Action::"ListFiles", resource);
        forbid(principal, action == Action::"DeleteFile", resource);
        forbid(principal, action == Action::"DropTable", resource);
    """

    def test_allowed_action(self):
        adapter = McpReceiptAdapter(cedar_policy=self.POLICY)
        receipt = adapter.govern_tool_call(
            agent_did="did:mesh:a1",
            tool_name="ReadData",
        )
        assert receipt.cedar_decision == "allow"

    def test_denied_action(self):
        adapter = McpReceiptAdapter(cedar_policy=self.POLICY)
        receipt = adapter.govern_tool_call(
            agent_did="did:mesh:a1",
            tool_name="DeleteFile",
        )
        assert receipt.cedar_decision == "deny"

    def test_unlisted_action_default_deny(self):
        adapter = McpReceiptAdapter(cedar_policy=self.POLICY)
        receipt = adapter.govern_tool_call(
            agent_did="did:mesh:a1",
            tool_name="SomeUnknownTool",
        )
        assert receipt.cedar_decision == "deny"

    def test_catch_all_permit(self):
        policy = "permit(principal, action, resource);"
        adapter = McpReceiptAdapter(cedar_policy=policy)
        receipt = adapter.govern_tool_call(
            agent_did="did:mesh:a1",
            tool_name="AnythingGoesHere",
        )
        assert receipt.cedar_decision == "allow"

    def test_empty_policy_default_deny(self):
        adapter = McpReceiptAdapter(cedar_policy="")
        receipt = adapter.govern_tool_call(
            agent_did="did:mesh:a1",
            tool_name="ReadData",
        )
        assert receipt.cedar_decision == "deny"


# ── Receipt Contents ──


class TestReceiptContents:
    """Verify receipt payloads contain the expected metadata."""

    POLICY = """
        permit(principal, action == Action::"ReadData", resource);
    """

    def test_receipt_has_policy_id(self):
        adapter = McpReceiptAdapter(
            cedar_policy=self.POLICY,
            cedar_policy_id="policy:mcp-tools:v1",
        )
        receipt = adapter.govern_tool_call(
            agent_did="did:mesh:a1",
            tool_name="ReadData",
        )
        assert receipt.cedar_policy_id == "policy:mcp-tools:v1"

    def test_receipt_has_agent_did(self):
        adapter = McpReceiptAdapter(cedar_policy=self.POLICY)
        receipt = adapter.govern_tool_call(
            agent_did="did:mesh:agent-007",
            tool_name="ReadData",
        )
        assert receipt.agent_did == "did:mesh:agent-007"

    def test_receipt_has_tool_name(self):
        adapter = McpReceiptAdapter(cedar_policy=self.POLICY)
        receipt = adapter.govern_tool_call(
            agent_did="did:mesh:a1",
            tool_name="ReadData",
        )
        assert receipt.tool_name == "ReadData"

    def test_receipt_has_args_hash(self):
        adapter = McpReceiptAdapter(cedar_policy=self.POLICY)
        receipt = adapter.govern_tool_call(
            agent_did="did:mesh:a1",
            tool_name="ReadData",
            tool_args={"path": "/data/report.csv"},
        )
        assert receipt.args_hash
        assert len(receipt.args_hash) == 64  # SHA-256 hex

    def test_receipt_has_timestamp(self):
        adapter = McpReceiptAdapter(cedar_policy=self.POLICY)
        receipt = adapter.govern_tool_call(
            agent_did="did:mesh:a1",
            tool_name="ReadData",
        )
        assert receipt.timestamp > 0

    def test_receipt_has_unique_id(self):
        adapter = McpReceiptAdapter(cedar_policy=self.POLICY)
        r1 = adapter.govern_tool_call(agent_did="did:mesh:a1", tool_name="ReadData")
        r2 = adapter.govern_tool_call(agent_did="did:mesh:a1", tool_name="ReadData")
        assert r1.receipt_id != r2.receipt_id


# ── Signing ──


class TestSigning:
    """Test receipt signing through the adapter."""

    POLICY = """
        permit(principal, action == Action::"ReadData", resource);
    """

    @pytest.fixture()
    def signing_key(self):
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            key = Ed25519PrivateKey.generate()
            return key.private_bytes_raw().hex()
        except ImportError:
            pytest.skip("cryptography not installed")

    @pytest.fixture()
    def authorizer_key(self):
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            key = Ed25519PrivateKey.generate()
            return key.private_bytes_raw().hex(), key.public_key().public_bytes_raw().hex()
        except ImportError as exc:
            raise pytest.skip.Exception("cryptography not installed") from exc

    def test_signed_receipt(self, signing_key):
        adapter = McpReceiptAdapter(
            cedar_policy=self.POLICY,
            signing_key_hex=signing_key,
        )
        receipt = adapter.govern_tool_call(
            agent_did="did:mesh:a1",
            tool_name="ReadData",
        )
        assert receipt.signature is not None
        assert receipt.signer_public_key is not None

    def test_unsigned_when_no_key(self):
        adapter = McpReceiptAdapter(cedar_policy=self.POLICY)
        receipt = adapter.govern_tool_call(
            agent_did="did:mesh:a1",
            tool_name="ReadData",
        )
        assert receipt.signature is None

    def test_signed_receipt_verifiable(self, signing_key):
        from mcp_receipt_governed import verify_receipt

        adapter = McpReceiptAdapter(
            cedar_policy=self.POLICY,
            signing_key_hex=signing_key,
        )
        receipt = adapter.govern_tool_call(
            agent_did="did:mesh:a1",
            tool_name="ReadData",
        )
        assert verify_receipt(receipt) is True

    def test_signing_failure_raises(self):
        """Fail-closed: signing failure raises RuntimeError, not silent error."""
        adapter = McpReceiptAdapter(
            cedar_policy=self.POLICY,
            signing_key_hex="invalid_key",
        )
        with pytest.raises(RuntimeError, match="Receipt signing failed"):
            adapter.govern_tool_call(
                agent_did="did:mesh:a1",
                tool_name="ReadData",
            )

    def test_external_authorizer_marks_receipt_and_is_trusted(self, signing_key, authorizer_key):
        authorizer_seed, authorizer_public_key = authorizer_key

        def external_authorizer(receipt):
            return authorize_receipt(
                receipt,
                authorizer_seed,
                authorizer_id="did:example:authorizer",
                expires_at=time.time() + 60,
            )

        adapter = McpReceiptAdapter(
            cedar_policy=self.POLICY,
            signing_key_hex=signing_key,
            external_authorizer=external_authorizer,
            trusted_authorizer_keys=[authorizer_public_key],
        )
        receipt = adapter.govern_tool_call(agent_did="did:mesh:a1", tool_name="ReadData")

        assert receipt.assurance_level == "externally_authorized"
        assert receipt.authorizer_id == "did:example:authorizer"

    def test_invalid_external_authorization_fails_closed(self, signing_key, authorizer_key):
        tool_was_called = False

        def no_op_authorizer(receipt):
            return receipt

        def tool():
            nonlocal tool_was_called
            tool_was_called = True

        adapter = McpReceiptAdapter(
            cedar_policy=self.POLICY,
            signing_key_hex=signing_key,
            external_authorizer=no_op_authorizer,
            trusted_authorizer_keys=[authorizer_key[1]],
        )

        with pytest.raises(ReceiptAuthorizationError, match="External authorization failed"):
            adapter.govern_and_execute(
                agent_did="did:mesh:a1",
                tool_name="ReadData",
                tool_fn=tool,
            )
        assert tool_was_called is False

    def test_authorizer_cannot_modify_signed_receipt(self, signing_key, authorizer_key):
        authorizer_seed, authorizer_public_key = authorizer_key

        def modifying_authorizer(receipt):
            receipt.tool_name = "DeleteFile"
            sign_receipt(receipt, signing_key)
            return authorize_receipt(
                receipt,
                authorizer_seed,
                authorizer_id="did:example:authorizer",
                expires_at=time.time() + 60,
            )

        adapter = McpReceiptAdapter(
            cedar_policy=self.POLICY,
            signing_key_hex=signing_key,
            external_authorizer=modifying_authorizer,
            trusted_authorizer_keys=[authorizer_public_key],
        )

        with pytest.raises(ReceiptAuthorizationError, match="modified the signed receipt"):
            adapter.govern_tool_call(agent_did="did:mesh:a1", tool_name="ReadData")

    def test_receipt_signer_cannot_be_a_trusted_authorizer(self, signing_key):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        def external_authorizer(receipt):
            return receipt

        signer_public_key = (
            Ed25519PrivateKey.from_private_bytes(bytes.fromhex(signing_key))
            .public_key()
            .public_bytes_raw()
            .hex()
        )
        adapter = McpReceiptAdapter(
            cedar_policy=self.POLICY,
            signing_key_hex=signing_key,
            external_authorizer=external_authorizer,
            trusted_authorizer_keys=[signer_public_key],
        )

        with pytest.raises(ReceiptAuthorizationError, match="must not contain"):
            adapter.govern_tool_call(agent_did="did:mesh:a1", tool_name="ReadData")

    def test_external_authorizer_requires_signing_and_trust_configuration(self, authorizer_key):
        def external_authorizer(receipt):
            return receipt

        with pytest.raises(ValueError, match="signing_key_hex"):
            McpReceiptAdapter(external_authorizer=external_authorizer)
        with pytest.raises(ValueError, match="trusted_authorizer_keys"):
            McpReceiptAdapter(
                signing_key_hex=authorizer_key[0],
                external_authorizer=external_authorizer,
            )

# ── Govern and Execute ──


class TestGovernAndExecute:
    """Test the full lifecycle: policy check → receipt → tool execution."""

    POLICY = """
        permit(principal, action == Action::"ReadData", resource);
        forbid(principal, action == Action::"DeleteFile", resource);
    """

    def test_allowed_tool_executes(self):
        adapter = McpReceiptAdapter(cedar_policy=self.POLICY)

        def mock_read_data(path: str = "") -> str:
            return f"data from {path}"

        receipt, result = adapter.govern_and_execute(
            agent_did="did:mesh:a1",
            tool_name="ReadData",
            tool_fn=mock_read_data,
            tool_args={"path": "/data/report.csv"},
        )
        assert receipt.cedar_decision == "allow"
        assert result == "data from /data/report.csv"

    def test_denied_tool_not_executed(self):
        adapter = McpReceiptAdapter(cedar_policy=self.POLICY)
        call_count = 0

        def mock_delete(path: str = "") -> str:
            nonlocal call_count
            call_count += 1
            return "deleted"

        receipt, result = adapter.govern_and_execute(
            agent_did="did:mesh:a1",
            tool_name="DeleteFile",
            tool_fn=mock_delete,
            tool_args={"path": "/sensitive"},
        )
        assert receipt.cedar_decision == "deny"
        assert result is None
        assert call_count == 0  # never called

    def test_tool_exception_captured(self):
        adapter = McpReceiptAdapter(cedar_policy=self.POLICY)

        def failing_tool() -> str:
            raise RuntimeError("disk full")

        receipt, result = adapter.govern_and_execute(
            agent_did="did:mesh:a1",
            tool_name="ReadData",
            tool_fn=failing_tool,
        )
        assert receipt.cedar_decision == "allow"
        assert result is None
        assert "execution_failed" in (receipt.error or "")


# ── Receipt Store via Adapter ──


class TestAdapterStore:
    """Test receipt storage and stats through the adapter."""

    POLICY = """
        permit(principal, action == Action::"ReadData", resource);
        forbid(principal, action == Action::"DeleteFile", resource);
    """

    def test_receipts_stored(self):
        adapter = McpReceiptAdapter(cedar_policy=self.POLICY)
        adapter.govern_tool_call(agent_did="did:mesh:a1", tool_name="ReadData")
        adapter.govern_tool_call(agent_did="did:mesh:a1", tool_name="DeleteFile")
        assert len(adapter.get_receipts()) == 2

    def test_stats_tracked(self):
        adapter = McpReceiptAdapter(cedar_policy=self.POLICY)
        adapter.govern_tool_call(agent_did="did:mesh:a1", tool_name="ReadData")
        adapter.govern_tool_call(agent_did="did:mesh:a2", tool_name="ReadData")
        adapter.govern_tool_call(agent_did="did:mesh:a1", tool_name="DeleteFile")

        stats = adapter.get_stats()
        assert stats["total"] == 3
        assert stats["allowed"] == 2
        assert stats["denied"] == 1
        assert stats["unique_agents"] == 2

    def test_shared_store(self):
        from mcp_receipt_governed import ReceiptStore

        shared = ReceiptStore()
        adapter1 = McpReceiptAdapter(cedar_policy=self.POLICY, store=shared)
        adapter2 = McpReceiptAdapter(cedar_policy=self.POLICY, store=shared)
        adapter1.govern_tool_call(agent_did="did:mesh:a1", tool_name="ReadData")
        adapter2.govern_tool_call(agent_did="did:mesh:a2", tool_name="ReadData")
        assert shared.count == 2
