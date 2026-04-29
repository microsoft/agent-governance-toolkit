#!/usr/bin/env python3
"""Unit tests for pipeline-governance example."""

import json
import sys
from pathlib import Path

# Add parent dir to path
sys.path.insert(0, str(Path(__file__).parent))

from demo import (
    CedarPolicyEvaluator,
    GovernanceReceipt,
    PipelineGovernanceAdapter,
    sign_receipt,
    verify_receipt,
)

# ── Ed25519 key for testing ──
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    KEY = Ed25519PrivateKey.generate()
    HAS_CRYPTO = True
except ImportError:
    KEY = None
    HAS_CRYPTO = False

POLICY_PATH = Path(__file__).parent / "policies" / "pipeline-governance.cedar"
CEDAR_POLICY = POLICY_PATH.read_text()


class TestGovernanceReceipt:
    def test_canonical_payload_deterministic(self):
        r = GovernanceReceipt(receipt_id="test", action="LoadShard", nonce="abc123")
        p1 = r.canonical_payload()
        p2 = r.canonical_payload()
        assert p1 == p2, "canonical payload must be deterministic"

    def test_payload_hash_changes_with_nonce(self):
        r1 = GovernanceReceipt(action="LoadShard", nonce="aaa")
        r2 = GovernanceReceipt(action="LoadShard", nonce="bbb")
        assert r1.payload_hash() != r2.payload_hash(), "different nonce must produce different hash"

    def test_nonce_prevents_replay(self):
        """Two receipts with same action/args but different nonces must differ."""
        r1 = GovernanceReceipt(action="RunInference", args_hash="h1", nonce="n1")
        r2 = GovernanceReceipt(action="RunInference", args_hash="h1", nonce="n2")
        assert r1.canonical_payload() != r2.canonical_payload()


class TestSigning:
    def test_sign_and_verify(self):
        if not HAS_CRYPTO:
            return
        r = GovernanceReceipt(action="LoadShard", principal="r0", nonce="test")
        sign_receipt(r, KEY)
        assert r.signature is not None
        assert verify_receipt(r) is True

    def test_tampered_payload_fails(self):
        if not HAS_CRYPTO:
            return
        r = GovernanceReceipt(action="LoadShard", principal="r0", nonce="orig")
        sign_receipt(r, KEY)
        r.action = "RunInference"  # tamper
        assert verify_receipt(r) is False

    def test_unsigned_receipt_fails(self):
        r = GovernanceReceipt(action="LoadShard")
        assert verify_receipt(r) is False


class TestCedarEvaluator:
    def setup_method(self):
        self.ev = CedarPolicyEvaluator(CEDAR_POLICY)

    def test_r0_can_load(self):
        ctx = {"shard_size_mb": 3000, "memory_budget_mb": 7400}
        assert self.ev.evaluate("LoadShard", 'Rank::"r0"', ctx) is True

    def test_r2_cannot_load(self):
        ctx = {"shard_size_mb": 3000, "memory_budget_mb": 7400}
        assert self.ev.evaluate("LoadShard", 'Rank::"r2"', ctx) is False

    def test_memory_budget_exceeded(self):
        ctx = {"shard_size_mb": 8000, "memory_budget_mb": 7400}
        assert self.ev.evaluate("LoadShard", 'Rank::"r0"', ctx) is False

    def test_approved_model(self):
        assert self.ev.evaluate("RunInference", 'Rank::"r0"', {"model": "gemma-3-12b-qat4"}) is True

    def test_unapproved_model(self):
        assert self.ev.evaluate("RunInference", 'Rank::"r0"', {"model": "llama-4"}) is False

    def test_transfer_with_receipt(self):
        assert self.ev.evaluate("CrossShardTransfer", 'Rank::"r0"', {"has_valid_receipt": True}) is True

    def test_transfer_without_receipt(self):
        assert self.ev.evaluate("CrossShardTransfer", 'Rank::"r0"', {"has_valid_receipt": False}) is False


class TestPipelineGovernanceAdapter:
    def setup_method(self):
        self.adapter = PipelineGovernanceAdapter(
            cedar_policy=CEDAR_POLICY,
            signing_key=KEY if HAS_CRYPTO else None,
            session_id="test-session",
        )

    def test_allowed_step_produces_receipt(self):
        r = self.adapter.govern_step(
            "LoadShard", 'Rank::"r0"',
            {"shard_index": 0},
            {"shard_size_mb": 3000, "memory_budget_mb": 7400},
        )
        assert r.cedar_decision == "allow"
        assert r.step_index == 0

    def test_denied_step_has_no_signature(self):
        r = self.adapter.govern_step(
            "LoadShard", 'Rank::"r2"',
            {"shard_index": 0},
            {"shard_size_mb": 3000, "memory_budget_mb": 7400},
        )
        assert r.cedar_decision == "deny"
        assert r.signature is None

    def test_hash_chain_integrity(self):
        self.adapter.govern_step("LoadShard", 'Rank::"r0"', {}, {"shard_size_mb": 1000, "memory_budget_mb": 7400})
        self.adapter.govern_step("LoadShard", 'Rank::"r1"', {}, {"shard_size_mb": 1000, "memory_budget_mb": 7400})
        self.adapter.govern_step("WriteAudit", 'Rank::"r0"', {}, {})
        assert self.adapter.verify_chain() is True

    def test_chain_break_detected(self):
        self.adapter.govern_step("LoadShard", 'Rank::"r0"', {}, {"shard_size_mb": 1000, "memory_budget_mb": 7400})
        self.adapter.govern_step("WriteAudit", 'Rank::"r0"', {}, {})
        # Tamper with parent hash
        self.adapter.receipts[1].parent_receipt_hash = "deadbeef"
        assert self.adapter.verify_chain() is False


def main():
    tests = [
        TestGovernanceReceipt(),
        TestSigning(),
        TestCedarEvaluator(),
        TestPipelineGovernanceAdapter(),
    ]
    passed = 0
    failed = 0
    for suite in tests:
        setup = getattr(suite, "setup_method", None)
        for name in dir(suite):
            if not name.startswith("test_"):
                continue
            if setup:
                setup()
            try:
                getattr(suite, name)()
                print(f"  PASS  {suite.__class__.__name__}.{name}")
                passed += 1
            except AssertionError as e:
                print(f"  FAIL  {suite.__class__.__name__}.{name}: {e}")
                failed += 1
            except Exception as e:
                print(f"  ERROR {suite.__class__.__name__}.{name}: {e}")
                failed += 1

    print(f"\n{passed} passed, {failed} failed, {passed + failed} total")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
