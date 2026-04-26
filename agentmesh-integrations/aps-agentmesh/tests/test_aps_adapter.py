"""Tests for APS-AgentMesh adapter."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from aps_agentmesh import (
    APSPolicyGate,
    APSTrustBridge,
    APSScopeVerifier,
    aps_context,
    GRADE_TO_TRUST_SCORE,
)
from aps_agentmesh.adapter import APSDecision, APSScopeChain, verify_aps_signature


# ── APSDecision parsing ──

def test_parse_decision_permit():
    dec = APSDecision.from_json({
        "verdict": "permit",
        "scopeUsed": "web_search",
        "agentId": "agent-001",
        "delegationId": "del-abc",
    })
    assert dec.verdict == "permit"
    assert dec.is_permit == True
    assert dec.scope_used == "web_search"
    assert dec.agent_id == "agent-001"


def test_parse_decision_deny():
    dec = APSDecision.from_json({
        "verdict": "deny",
        "scope_used": "admin:delete",
        "agent_id": "agent-bad",
        "constraint_failures": ["scope_exceeded", "spend_limit"],
    })
    assert dec.is_permit == False
    assert len(dec.constraint_failures) == 2


def test_parse_decision_from_json_string():
    import json
    raw = json.dumps({"verdict": "permit", "scopeUsed": "read", "agentId": "a1"})
    dec = APSDecision.from_json(raw)
    assert dec.is_permit == True


# ── APSScopeChain parsing ──

def test_parse_scope_chain():
    sc = APSScopeChain.from_json({
        "scope": ["web_search", "code_execution"],
        "delegatedBy": "pk-principal",
        "delegatedTo": "pk-agent",
        "currentDepth": 1,
        "maxDepth": 3,
        "spendLimit": 500,
        "spentAmount": 100,
    })
    assert sc.scopes == ["web_search", "code_execution"]
    assert sc.spend_remaining == 400
    assert sc.covers_scope("web_search") == True
    assert sc.covers_scope("admin") == False


def test_scope_prefix_match():
    sc = APSScopeChain.from_json({
        "scope": ["commerce"],
        "delegatedBy": "pk1", "delegatedTo": "pk2",
        "currentDepth": 0, "maxDepth": 2,
    })
    assert sc.covers_scope("commerce") == True
    assert sc.covers_scope("commerce:checkout") == True
    assert sc.covers_scope("admin") == False


def test_wildcard_scope():
    sc = APSScopeChain.from_json({
        "scope": ["*"],
        "delegatedBy": "pk1", "delegatedTo": "pk2",
        "currentDepth": 0, "maxDepth": 1,
    })
    assert sc.covers_scope("anything") == True


# ── APSPolicyGate ──

def test_policy_gate_build_context():
    gate = APSPolicyGate()
    ctx = gate.build_context(
        {"verdict": "permit", "scopeUsed": "deploy", "agentId": "a1"},
        {"scope": ["deploy"], "delegatedBy": "p1", "delegatedTo": "a1", "currentDepth": 0, "maxDepth": 2},
        passport_grade=2,
    )
    assert ctx["aps_decision"]["verdict"] == "permit"
    assert ctx["aps_decision"]["is_permit"] == True
    assert ctx["aps_passport_grade"] == 2
    assert ctx["aps_trust_score"] == 700
    assert ctx["aps_grade_label"] == "runtime_bound"
    assert ctx["aps_scope_chain"]["scopes"] == ["deploy"]


def test_policy_gate_is_permitted():
    gate = APSPolicyGate()
    assert gate.is_permitted({"verdict": "permit", "scopeUsed": "x", "agentId": "a"}) == True
    assert gate.is_permitted({"verdict": "deny", "scopeUsed": "x", "agentId": "a"}) == False


# ── APSTrustBridge ──

def test_trust_bridge_default_mapping():
    bridge = APSTrustBridge()
    assert bridge.grade_to_score(0) == 100
    assert bridge.grade_to_score(1) == 400
    assert bridge.grade_to_score(2) == 700
    assert bridge.grade_to_score(3) == 900


def test_trust_bridge_meets_threshold():
    bridge = APSTrustBridge()
    assert bridge.meets_threshold(2, 500) == True
    assert bridge.meets_threshold(0, 500) == False
    assert bridge.meets_threshold(3, 900) == True


def test_trust_bridge_custom_mapping():
    bridge = APSTrustBridge({0: 0, 1: 250, 2: 500, 3: 1000})
    assert bridge.grade_to_score(2) == 500
    assert bridge.grade_to_score(3) == 1000


def test_trust_bridge_labels():
    bridge = APSTrustBridge()
    assert bridge.grade_label(0) == "self_signed"
    assert bridge.grade_label(3) == "principal_bound"
    assert bridge.grade_label(99) == "unknown"


# ── APSScopeVerifier ──

def test_scope_verifier_permits():
    v = APSScopeVerifier()
    ok, reason = v.verify(
        {"scope": ["deploy", "read"], "delegatedBy": "p", "delegatedTo": "a", "currentDepth": 1, "maxDepth": 3},
        required_scope="deploy",
    )
    assert ok == True


def test_scope_verifier_denies_scope():
    v = APSScopeVerifier()
    ok, reason = v.verify(
        {"scope": ["read"], "delegatedBy": "p", "delegatedTo": "a", "currentDepth": 0, "maxDepth": 2},
        required_scope="admin:delete",
    )
    assert ok == False
    assert "not covered" in reason


def test_scope_verifier_denies_depth():
    v = APSScopeVerifier()
    ok, reason = v.verify(
        {"scope": ["*"], "delegatedBy": "p", "delegatedTo": "a", "currentDepth": 5, "maxDepth": 3},
        required_scope="anything",
    )
    assert ok == False
    assert "depth" in reason.lower()


def test_scope_verifier_denies_budget():
    v = APSScopeVerifier()
    ok, reason = v.verify(
        {"scope": ["commerce"], "delegatedBy": "p", "delegatedTo": "a",
         "currentDepth": 0, "maxDepth": 2, "spendLimit": 100, "spentAmount": 90},
        required_scope="commerce",
        required_spend=50,
    )
    assert ok == False
    assert "spend" in reason.lower()


# ── Integration: AGT PolicyEngine context shape ──

def test_agt_context_shape():
    """Verify the context dict matches what AGT PolicyEngine expects."""
    ctx = aps_context(
        {"verdict": "permit", "scopeUsed": "deploy.staging", "agentId": "claude-op"},
        passport_grade=3,
    )
    # AGT rule: conditions.aps_decision.verdict == 'permit'
    assert "aps_decision" in ctx
    assert ctx["aps_decision"]["verdict"] == "permit"
    # AGT can use trust score for soft scoring
    assert ctx["aps_trust_score"] == 900
    # No scope chain = no aps_scope_chain key
    assert "aps_scope_chain" not in ctx


# ── verify_aps_signature ──

def test_verify_signature_fails_closed_without_nacl(monkeypatch):
    """Without PyNaCl, verify_aps_signature must return False (fail closed)."""
    import builtins
    original_import = builtins.__import__
    def mock_import(name, *args, **kwargs):
        if name == "nacl.signing" or name.startswith("nacl"):
            raise ImportError("No nacl")
        return original_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", mock_import)
    # Even a plausible-looking signature must be rejected
    fake_sig = "a" * 128
    fake_key = "b" * 64
    assert verify_aps_signature("payload", fake_sig, fake_key) == False


def test_verify_signature_valid():
    """Valid Ed25519 signature passes verification."""
    try:
        from nacl.signing import SigningKey
    except ImportError:
        import pytest
        pytest.skip("PyNaCl not installed")
    sk = SigningKey.generate()
    payload = "test-payload"
    sig = sk.sign(payload.encode()).signature.hex()
    pk = sk.verify_key.encode().hex()
    assert verify_aps_signature(payload, sig, pk) == True


def test_verify_signature_wrong_key():
    """Signature verified against wrong public key fails."""
    try:
        from nacl.signing import SigningKey
    except ImportError:
        import pytest
        pytest.skip("PyNaCl not installed")
    sk1 = SigningKey.generate()
    sk2 = SigningKey.generate()
    payload = "test-payload"
    sig = sk1.sign(payload.encode()).signature.hex()
    wrong_pk = sk2.verify_key.encode().hex()
    assert verify_aps_signature(payload, sig, wrong_pk) == False


def test_verify_signature_tampered_data():
    """Signature against tampered data fails."""
    try:
        from nacl.signing import SigningKey
    except ImportError:
        import pytest
        pytest.skip("PyNaCl not installed")
    sk = SigningKey.generate()
    sig = sk.sign(b"original").signature.hex()
    pk = sk.verify_key.encode().hex()
    assert verify_aps_signature("tampered", sig, pk) == False


def test_verify_signature_rejects_bad_signature():
    """Bad signature format is rejected regardless of nacl availability."""
    assert verify_aps_signature("payload", "not-hex", "not-a-key") == False


def test_verify_signature_rejects_empty():
    """Empty inputs are rejected."""
    assert verify_aps_signature("", "", "") == False


# ── passport_grade validation ──

def test_invalid_passport_grade_raises():
    """Invalid passport_grade must raise ValueError."""
    import pytest
    with pytest.raises(ValueError, match="Invalid passport_grade"):
        aps_context(
            {"verdict": "permit", "scopeUsed": "x", "agentId": "a"},
            passport_grade=99,
        )


def test_invalid_passport_grade_negative():
    """Negative passport_grade must raise ValueError."""
    import pytest
    with pytest.raises(ValueError, match="Invalid passport_grade"):
        aps_context(
            {"verdict": "permit", "scopeUsed": "x", "agentId": "a"},
            passport_grade=-1,
        )
