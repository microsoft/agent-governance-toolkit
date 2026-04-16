# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for ScopeBlind protect-mcp AgentMesh adapter.

Covers:
- Cedar decision parsing and representation
- CedarPolicyBridge: Cedar deny is authoritative, trust layering, receipt requirements
- ReceiptVerifier: structure validation, type checking, AGT context conversion
- SpendingGate: amount limits, category blocks, utilization bands, trust floors
- scopeblind_context: AGT-compatible context shape
"""

import time

import pytest

from scopeblind_protect_mcp import (
    CedarDecision,
    CedarPolicyBridge,
    ReceiptVerifier,
    SpendingGate,
    scopeblind_context,
)


# ---- Fixtures ----


_receipt_counter = 0

def make_receipt(
    effect="allow",
    tool="web_search",
    receipt_type="scopeblind:decision",
    **extra_payload,
):
    """Build a minimal valid receipt for testing. Each call produces a unique receipt."""
    global _receipt_counter
    _receipt_counter += 1
    payload = {"effect": effect, "tool": tool, "timestamp": time.time(), "nonce": _receipt_counter}
    payload.update(extra_payload)
    return {
        "type": receipt_type,
        "payload": payload,
        "signature": "a" * 128,
        "publicKey": "b" * 64,
    }


def make_spending_receipt(amount=50.0, category="cloud_compute", band="low"):
    """Build a spending authority receipt."""
    return make_receipt(
        effect="allow",
        tool="purchase",
        receipt_type="scopeblind:spending_authority",
        amount=amount,
        currency="USD",
        utilization_band=band,
        category=category,
    )


# ---- CedarDecision ----


class TestCedarDecision:
    def test_allow_decision(self):
        d = CedarDecision(effect="allow", tool_name="web_search")
        assert d.allowed is True
        assert d.effect == "allow"

    def test_deny_decision(self):
        d = CedarDecision(effect="deny", tool_name="shell_exec", policy_ids=["sb-001"])
        assert d.allowed is False
        assert d.policy_ids == ["sb-001"]

    def test_to_dict_shape(self):
        d = CedarDecision(effect="allow", tool_name="read_file")
        result = d.to_dict()
        assert set(result.keys()) == {"effect", "tool", "policy_ids", "diagnostics", "evaluated_at"}

    def test_from_receipt(self):
        receipt = make_receipt(effect="deny", tool="shell_exec")
        d = CedarDecision.from_receipt(receipt)
        assert d.effect == "deny"
        assert d.tool_name == "shell_exec"
        assert d.allowed is False

    def test_from_receipt_with_policy_ids(self):
        receipt = make_receipt(effect="deny", tool="bash", policy_ids=["sb-clinejection-001"])
        d = CedarDecision.from_receipt(receipt)
        assert d.policy_ids == ["sb-clinejection-001"]


# ---- CedarPolicyBridge ----


class TestCedarPolicyBridge:
    def test_cedar_deny_is_authoritative(self):
        """Cedar deny must not be overridable by high trust score."""
        bridge = CedarPolicyBridge()
        decision = CedarDecision(effect="deny", tool_name="shell_exec", policy_ids=["sb-001"])
        result = bridge.evaluate(decision, agent_trust_score=999, agent_did="did:mesh:agent-1")
        assert result["allowed"] is False
        assert result["cedar_effect"] == "deny"

    def test_cedar_allow_passes(self):
        bridge = CedarPolicyBridge()
        decision = CedarDecision(effect="allow", tool_name="web_search")
        result = bridge.evaluate(decision, agent_trust_score=500, agent_did="did:mesh:agent-1")
        assert result["allowed"] is True

    def test_cedar_allow_with_trust_floor(self):
        """Cedar allow but trust too low should deny."""
        bridge = CedarPolicyBridge(trust_floor=600)
        decision = CedarDecision(effect="allow", tool_name="web_search")
        result = bridge.evaluate(decision, agent_trust_score=100, agent_did="did:mesh:agent-1")
        assert result["allowed"] is False
        assert "trust score" in result["reason"].lower()

    def test_trust_bonus_applied(self):
        bridge = CedarPolicyBridge(trust_bonus_per_allow=75)
        decision = CedarDecision(effect="allow", tool_name="read_file")
        result = bridge.evaluate(decision, agent_trust_score=400)
        assert result["adjusted_trust"] == 475

    def test_deny_penalty_applied(self):
        bridge = CedarPolicyBridge(deny_penalty=300)
        decision = CedarDecision(effect="deny", tool_name="shell_exec")
        result = bridge.evaluate(decision, agent_trust_score=200)
        assert result["adjusted_trust"] == 0  # clamped at 0

    def test_receipt_required_but_missing(self):
        bridge = CedarPolicyBridge(require_receipt=True)
        decision = CedarDecision(effect="allow", tool_name="web_search")
        result = bridge.evaluate(decision, agent_trust_score=500)
        assert result["allowed"] is False
        assert "receipt required" in result["reason"].lower()

    def test_receipt_provided_when_required(self):
        bridge = CedarPolicyBridge(require_receipt=True)
        decision = CedarDecision(effect="allow", tool_name="web_search")
        receipt = make_receipt()
        result = bridge.evaluate(decision, agent_trust_score=500, receipt=receipt)
        assert result["allowed"] is True
        assert "receipt_ref" in result

    def test_stats_tracking(self):
        bridge = CedarPolicyBridge()
        allow = CedarDecision(effect="allow", tool_name="read_file")
        deny = CedarDecision(effect="deny", tool_name="shell_exec")
        bridge.evaluate(allow, agent_trust_score=500)
        bridge.evaluate(deny, agent_trust_score=500)
        bridge.evaluate(allow, agent_trust_score=500)
        stats = bridge.get_stats()
        assert stats["total_evaluations"] == 3
        assert stats["allowed"] == 2
        assert stats["cedar_denies"] == 1

    def test_trust_capped_at_1000(self):
        bridge = CedarPolicyBridge(trust_bonus_per_allow=200)
        decision = CedarDecision(effect="allow", tool_name="read_file")
        result = bridge.evaluate(decision, agent_trust_score=900)
        assert result["adjusted_trust"] == 1000


# ---- ReceiptVerifier ----


class TestReceiptVerifier:
    def test_valid_receipt(self):
        verifier = ReceiptVerifier()
        receipt = make_receipt()
        result = verifier.validate_structure_only(receipt)
        assert result["valid"] is True
        assert result["receipt_type"] == "scopeblind:decision"

    def test_missing_fields(self):
        verifier = ReceiptVerifier()
        result = verifier.validate_structure_only({"type": "scopeblind:decision"})
        assert result["valid"] is False
        assert "Missing required fields" in result["reason"]

    def test_unknown_type_strict(self):
        verifier = ReceiptVerifier(strict=True)
        receipt = make_receipt()
        receipt["type"] = "unknown:type"
        result = verifier.validate_structure_only(receipt)
        assert result["valid"] is False

    def test_unknown_type_lenient(self):
        verifier = ReceiptVerifier(strict=False)
        receipt = make_receipt()
        receipt["type"] = "custom:type"
        result = verifier.validate_structure_only(receipt)
        assert result["valid"] is True

    def test_spending_authority_receipt(self):
        verifier = ReceiptVerifier()
        receipt = make_spending_receipt(amount=250.0, category="cloud_compute", band="medium")
        result = verifier.validate_structure_only(receipt)
        assert result["valid"] is True
        assert result["amount"] == 250.0
        assert result["utilization_band"] == "medium"

    def test_to_agt_context(self):
        verifier = ReceiptVerifier()
        receipt = make_receipt(effect="allow", tool="web_search")
        ctx = verifier.to_agt_context(receipt)
        assert ctx["receipt_valid"] is True
        assert ctx["issuer_blind"] is True
        assert ctx["cedar_effect"] == "allow"
        assert "receipt_ref" in ctx

    def test_invalid_receipt_agt_context(self):
        verifier = ReceiptVerifier()
        ctx = verifier.to_agt_context({"broken": True})
        assert ctx["receipt_valid"] is False


# ---- SpendingGate ----


class TestSpendingGate:
    def test_basic_spend_allowed(self):
        gate = SpendingGate()
        result = gate.evaluate_spend(amount=50.0, agent_trust_score=500)
        assert result["allowed"] is True

    def test_exceeds_single_limit(self):
        gate = SpendingGate(max_single_amount=100.0)
        result = gate.evaluate_spend(amount=150.0, agent_trust_score=500)
        assert result["allowed"] is False
        assert "exceeds" in result["reason"].lower()

    def test_negative_amount_rejected(self):
        gate = SpendingGate()
        result = gate.evaluate_spend(amount=-10.0)
        assert result["allowed"] is False

    def test_blocked_category(self):
        gate = SpendingGate(blocked_categories=["gambling", "weapons"])
        result = gate.evaluate_spend(amount=50.0, category="gambling", agent_trust_score=999)
        assert result["allowed"] is False
        assert "blocked" in result["reason"].lower()

    def test_exceeded_utilization_band(self):
        gate = SpendingGate()
        result = gate.evaluate_spend(amount=10.0, utilization_band="exceeded", agent_trust_score=999)
        assert result["allowed"] is False
        assert "exceeded" in result["reason"].lower()

    def test_high_utilization_needs_trust(self):
        gate = SpendingGate(high_util_trust_floor=500)
        result = gate.evaluate_spend(
            amount=50.0, utilization_band="high", agent_trust_score=200
        )
        assert result["allowed"] is False
        assert "trust score" in result["reason"].lower()

    def test_high_utilization_with_sufficient_trust(self):
        gate = SpendingGate(high_util_trust_floor=500)
        result = gate.evaluate_spend(
            amount=50.0, utilization_band="high", agent_trust_score=700
        )
        assert result["allowed"] is True

    def test_high_value_requires_receipt(self):
        gate = SpendingGate()
        result = gate.evaluate_spend(amount=2000.0, agent_trust_score=500)
        assert result["allowed"] is False
        assert "receipt" in result["reason"].lower()

    def test_high_value_with_receipt(self):
        gate = SpendingGate()
        receipt = make_spending_receipt(amount=2000.0)
        result = gate.evaluate_spend(amount=2000.0, agent_trust_score=500, receipt=receipt)
        assert result["allowed"] is True

    def test_stats(self):
        gate = SpendingGate()
        gate.evaluate_spend(amount=50.0, agent_trust_score=500)
        gate.evaluate_spend(amount=25.0, agent_trust_score=500)
        stats = gate.get_stats()
        assert stats["total_requests"] == 2
        assert stats["allowed"] == 2
        assert stats["total_authorized_amount"] == 75.0


# ---- scopeblind_context ----


class TestScopeblindContext:
    def test_minimal_context(self):
        ctx = scopeblind_context()
        assert ctx["source"] == "scopeblind:protect-mcp"
        assert ctx["receipt"]["present"] is False

    def test_with_cedar_decision(self):
        decision = CedarDecision(effect="allow", tool_name="read_file", policy_ids=["p1"])
        ctx = scopeblind_context(cedar_decision=decision)
        assert ctx["cedar"]["effect"] == "allow"
        assert ctx["cedar"]["tool"] == "read_file"
        assert ctx["cedar"]["policy_ids"] == ["p1"]

    def test_with_receipt(self):
        receipt = make_receipt(effect="allow", tool="web_search")
        ctx = scopeblind_context(receipt=receipt)
        assert ctx["receipt"]["present"] is True
        assert ctx["receipt"]["issuer_blind"] is True
        assert ctx["receipt"]["type"] == "scopeblind:decision"

    def test_with_spending(self):
        ctx = scopeblind_context(spend_amount=99.50, spend_category="cloud", utilization_band="low")
        assert ctx["spending"]["amount"] == 99.50
        assert ctx["spending"]["category"] == "cloud"
        assert ctx["spending"]["utilization_band"] == "low"

    def test_full_context_shape(self):
        """Full context should be a flat dict compatible with AGT evaluate()."""
        decision = CedarDecision(effect="allow", tool_name="purchase")
        receipt = make_spending_receipt(amount=99.50)
        ctx = scopeblind_context(
            cedar_decision=decision,
            receipt=receipt,
            spend_amount=99.50,
            spend_category="cloud_compute",
            utilization_band="low",
        )
        assert "source" in ctx
        assert "cedar" in ctx
        assert "receipt" in ctx
        assert "spending" in ctx
        assert ctx["receipt"]["present"] is True


# ---- Edge case tests ----


class TestEdgeCases:
    """Edge cases covering missing/invalid fields, boundary trust scores,
    concurrent access, and malformed payloads."""

    # -- Receipts with missing or invalid fields --

    def test_receipt_empty_dict(self):
        verifier = ReceiptVerifier()
        result = verifier.validate_structure_only({})
        assert result["valid"] is False
        assert "Missing required fields" in result["reason"]

    def test_receipt_missing_signature(self):
        verifier = ReceiptVerifier()
        receipt = {"type": "scopeblind:decision", "payload": {}, "publicKey": "pk"}
        result = verifier.validate_structure_only(receipt)
        assert result["valid"] is False
        assert "signature" in str(result["reason"])

    def test_receipt_missing_public_key(self):
        verifier = ReceiptVerifier()
        receipt = {"type": "scopeblind:decision", "payload": {}, "signature": "sig"}
        result = verifier.validate_structure_only(receipt)
        assert result["valid"] is False
        assert "publicKey" in str(result["reason"])

    def test_receipt_payload_not_dict(self):
        verifier = ReceiptVerifier()
        receipt = {
            "type": "scopeblind:decision",
            "payload": "not_a_dict",
            "signature": "sig",
            "publicKey": "pk",
        }
        result = verifier.validate_structure_only(receipt)
        assert result["valid"] is False
        assert "object" in result["reason"].lower()

    def test_receipt_payload_is_list(self):
        verifier = ReceiptVerifier()
        receipt = {
            "type": "scopeblind:decision",
            "payload": [1, 2, 3],
            "signature": "sig",
            "publicKey": "pk",
        }
        result = verifier.validate_structure_only(receipt)
        assert result["valid"] is False

    def test_receipt_empty_signature_rejected(self):
        """Empty signature string should be rejected as invalid."""
        verifier = ReceiptVerifier()
        receipt = {
            "type": "scopeblind:decision",
            "payload": {"effect": "allow", "tool": "test"},
            "signature": "",
            "publicKey": "pk",
        }
        result = verifier.validate_structure_only(receipt)
        assert result["valid"] is False
        assert result["has_signature"] is False

    def test_to_agt_context_malformed_receipt(self):
        verifier = ReceiptVerifier()
        ctx = verifier.to_agt_context({"type": "bad"})
        assert ctx["receipt_valid"] is False

    # -- Trust scores at boundaries --

    def test_trust_score_zero(self):
        bridge = CedarPolicyBridge(trust_floor=0)
        decision = CedarDecision(effect="allow", tool_name="read_file")
        result = bridge.evaluate(decision, agent_trust_score=0)
        assert result["allowed"] is True
        assert result["adjusted_trust"] == 50  # default bonus

    def test_trust_score_1000(self):
        bridge = CedarPolicyBridge(trust_bonus_per_allow=50)
        decision = CedarDecision(effect="allow", tool_name="read_file")
        result = bridge.evaluate(decision, agent_trust_score=1000)
        assert result["adjusted_trust"] == 1000  # capped

    def test_trust_score_zero_with_deny(self):
        bridge = CedarPolicyBridge(deny_penalty=100)
        decision = CedarDecision(effect="deny", tool_name="shell_exec")
        result = bridge.evaluate(decision, agent_trust_score=0)
        assert result["adjusted_trust"] == 0  # clamped, no negative

    def test_trust_score_at_floor_boundary(self):
        """Trust score exactly at floor should pass."""
        bridge = CedarPolicyBridge(trust_floor=550, trust_bonus_per_allow=50)
        decision = CedarDecision(effect="allow", tool_name="read_file")
        result = bridge.evaluate(decision, agent_trust_score=500)
        assert result["adjusted_trust"] == 550
        assert result["allowed"] is True

    def test_trust_score_one_below_floor(self):
        """Trust score one below floor should deny."""
        bridge = CedarPolicyBridge(trust_floor=551, trust_bonus_per_allow=50)
        decision = CedarDecision(effect="allow", tool_name="read_file")
        result = bridge.evaluate(decision, agent_trust_score=500)
        assert result["adjusted_trust"] == 550
        assert result["allowed"] is False

    # -- Concurrent evaluations (thread safety) --

    def test_concurrent_bridge_evaluations(self):
        """Multiple threads appending to bridge history should not lose entries."""
        import threading

        bridge = CedarPolicyBridge()
        decision = CedarDecision(effect="allow", tool_name="read_file")
        n_threads = 10
        n_per_thread = 50
        barrier = threading.Barrier(n_threads)

        def worker():
            barrier.wait()
            for _ in range(n_per_thread):
                bridge.evaluate(decision, agent_trust_score=500)

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(bridge.get_history()) == n_threads * n_per_thread

    def test_concurrent_receipt_verification(self):
        """Multiple threads validating unique receipts should not lose entries."""
        import threading

        verifier = ReceiptVerifier(replay_protection=False)
        n_threads = 10
        n_per_thread = 50
        # Each thread gets its own unique receipts
        all_receipts = [[make_receipt(tool=f"t{t}_{i}") for i in range(n_per_thread)] for t in range(n_threads)]
        barrier = threading.Barrier(n_threads)

        def worker(thread_receipts):
            barrier.wait()
            for r in thread_receipts:
                verifier.validate_structure_only(r)

        threads = [threading.Thread(target=worker, args=(all_receipts[t],)) for t in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(verifier.get_verification_log()) == n_threads * n_per_thread

    def test_concurrent_spending_decisions(self):
        """Multiple threads evaluating spends should not lose entries."""
        import threading

        gate = SpendingGate()
        n_threads = 10
        n_per_thread = 50
        barrier = threading.Barrier(n_threads)

        def worker():
            barrier.wait()
            for _ in range(n_per_thread):
                gate.evaluate_spend(amount=10.0, agent_trust_score=500)

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(gate.get_decisions()) == n_threads * n_per_thread

    # -- Malformed receipt payloads --

    def test_cedar_decision_from_receipt_missing_payload(self):
        """from_receipt with no payload key should use top-level dict."""
        d = CedarDecision.from_receipt({"effect": "deny", "tool": "bash"})
        assert d.effect == "deny"
        assert d.tool_name == "bash"

    def test_cedar_decision_from_receipt_empty(self):
        """from_receipt with empty dict should default to deny."""
        d = CedarDecision.from_receipt({})
        assert d.effect == "deny"
        assert d.tool_name == ""

    def test_spending_gate_zero_amount(self):
        gate = SpendingGate()
        result = gate.evaluate_spend(amount=0.0, agent_trust_score=500)
        assert result["allowed"] is False
        assert "positive" in result["reason"].lower()

    def test_spending_gate_invalid_utilization_band(self):
        gate = SpendingGate()
        result = gate.evaluate_spend(
            amount=10.0, utilization_band="invalid_band", agent_trust_score=500
        )
        assert result["allowed"] is False
        assert "invalid utilization band" in result["reason"].lower()

    def test_receipt_ref_is_full_sha256(self):
        """receipt_ref should be a full 64-char hex SHA-256, not truncated."""
        bridge = CedarPolicyBridge()
        decision = CedarDecision(effect="allow", tool_name="web_search")
        receipt = make_receipt()
        result = bridge.evaluate(decision, agent_trust_score=500, receipt=receipt)
        assert "receipt_ref" in result
        assert len(result["receipt_ref"]) == 64  # full SHA-256 hex

    # -- Ed25519 public key format validation --

    def test_invalid_public_key_too_short(self):
        """Public key with wrong length should be rejected."""
        verifier = ReceiptVerifier()
        receipt = {
            "type": "scopeblind:decision",
            "payload": {"effect": "allow", "tool": "test"},
            "signature": "a" * 128,
            "publicKey": "abcd1234",  # 8 chars, not 64
        }
        result = verifier.validate_structure_only(receipt)
        assert result["valid"] is False
        assert "Invalid publicKey format" in result["reason"]

    def test_invalid_public_key_non_hex(self):
        """Public key with non-hex characters should be rejected."""
        verifier = ReceiptVerifier()
        receipt = {
            "type": "scopeblind:decision",
            "payload": {"effect": "allow", "tool": "test"},
            "signature": "a" * 128,
            "publicKey": "g" * 64,  # 'g' is not hex
        }
        result = verifier.validate_structure_only(receipt)
        assert result["valid"] is False
        assert "Invalid publicKey format" in result["reason"]

    def test_valid_public_key_hex(self):
        """Valid 64-char hex public key should pass."""
        verifier = ReceiptVerifier()
        receipt = make_receipt()
        result = verifier.validate_structure_only(receipt)
        assert result["valid"] is True

    def test_valid_public_key_base64url(self):
        """Valid base64url-encoded public key should pass."""
        verifier = ReceiptVerifier()
        receipt = {
            "type": "scopeblind:decision",
            "payload": {"effect": "allow", "tool": "test", "nonce": 99999},
            "signature": "a" * 128,
            "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",  # 44 chars base64
        }
        result = verifier.validate_structure_only(receipt)
        assert result["valid"] is True

    # -- Replay protection --

    def test_replay_detected(self):
        """Same receipt submitted twice should be rejected the second time."""
        verifier = ReceiptVerifier(replay_protection=True)
        receipt = make_receipt(tool="replay_test")
        result1 = verifier.validate_structure_only(receipt)
        assert result1["valid"] is True
        result2 = verifier.validate_structure_only(receipt)
        assert result2["valid"] is False
        assert result2.get("replay") is True
        assert "Replay detected" in result2["reason"]

    def test_replay_protection_disabled(self):
        """With replay_protection=False, same receipt should pass twice."""
        verifier = ReceiptVerifier(replay_protection=False)
        receipt = make_receipt(tool="no_replay_check")
        result1 = verifier.validate_structure_only(receipt)
        assert result1["valid"] is True
        result2 = verifier.validate_structure_only(receipt)
        assert result2["valid"] is True

    def test_replay_window_bounded(self):
        """Replay window should evict old entries when full."""
        verifier = ReceiptVerifier(replay_protection=True, max_seen_receipts=5)
        receipts = [make_receipt(tool=f"tool_{i}") for i in range(10)]
        for r in receipts:
            verifier.validate_structure_only(r)
        # First receipt should have been evicted from the window
        result = verifier.validate_structure_only(receipts[0])
        assert result["valid"] is True  # Not in window anymore

    def test_different_receipts_not_replay(self):
        """Two different receipts should both pass."""
        verifier = ReceiptVerifier(replay_protection=True)
        r1 = make_receipt(tool="tool_a")
        r2 = make_receipt(tool="tool_b")
        assert verifier.validate_structure_only(r1)["valid"] is True
        assert verifier.validate_structure_only(r2)["valid"] is True
