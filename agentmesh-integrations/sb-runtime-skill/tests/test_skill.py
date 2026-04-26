# Copyright (c) 2026 Tom Farley (ScopeBlind).
# Licensed under the MIT License.
import pytest
import yaml
from cryptography.hazmat.primitives import serialization

from sb_runtime_agentmesh.receipts import Signer, receipt_hash, verify_receipt
from sb_runtime_agentmesh.skill import GovernanceSkill, SandboxBackend

SAMPLE = {
    "apiVersion": "governance.toolkit/v1",
    "rules": [
        {
            "name": "allow-read",
            "condition": {"field": "action", "operator": "starts_with", "value": "file:read"},
            "action": "allow",
            "priority": 90,
        },
        {
            "name": "allow-shell",
            "condition": {"field": "action", "operator": "in", "value": ["shell:ls", "shell:python", "shell:git"]},
            "action": "allow",
            "priority": 80,
        },
        {
            "name": "block-danger",
            "condition": {"field": "action", "operator": "matches", "value": "shell:(rm|dd|curl)"},
            "action": "deny",
            "priority": 100,
            "message": "Blocked",
        },
    ],
}


@pytest.fixture
def policy_dir(tmp_path):
    with open(tmp_path / "p.yaml", "w", encoding="utf-8") as f:
        yaml.dump(SAMPLE, f)
    return tmp_path


class TestPolicyContract:
    """Mirrors the openshell-skill test suite so the contract is identical."""

    def test_allow_read(self, policy_dir):
        assert GovernanceSkill(policy_dir=policy_dir).check_policy("file:read:/workspace/main.py").allowed

    def test_allow_shell(self, policy_dir):
        assert GovernanceSkill(policy_dir=policy_dir).check_policy("shell:python").allowed

    def test_deny(self, policy_dir):
        decision = GovernanceSkill(policy_dir=policy_dir).check_policy("shell:rm -rf /")
        assert not decision.allowed

    def test_default_deny(self, policy_dir):
        assert not GovernanceSkill(policy_dir=policy_dir).check_policy("unknown").allowed

    def test_trust(self):
        skill = GovernanceSkill()
        assert skill.get_trust_score("x") == 1.0
        skill.adjust_trust("x", -0.3)
        assert skill.get_trust_score("x") == pytest.approx(0.7)

    def test_audit(self, policy_dir):
        skill = GovernanceSkill(policy_dir=policy_dir)
        skill.check_policy("file:read:/t")
        skill.check_policy("shell:rm /")
        log = skill.get_audit_log()
        assert len(log) == 2
        assert log[0]["decision"] == "allow"

    def test_load(self, policy_dir):
        assert GovernanceSkill().load_policies(policy_dir) == 3

    def test_missing(self):
        with pytest.raises(FileNotFoundError):
            GovernanceSkill(policy_dir="/nope")  # type: ignore[arg-type]

    def test_priority(self, policy_dir):
        decision = GovernanceSkill(policy_dir=policy_dir).check_policy("shell:rm")
        assert not decision.allowed
        assert decision.policy_name == "block-danger"


class TestReceipts:
    """Receipt signing is the material addition over openshell-skill."""

    def test_receipt_attached_on_allow(self, policy_dir):
        decision = GovernanceSkill(policy_dir=policy_dir).check_policy("shell:python")
        assert decision.receipt is not None
        payload = decision.receipt["payload"]
        assert payload["decision"] == "allow"
        assert payload["action"] == "shell:python"
        assert payload["type"] == "sb-runtime:decision"
        assert "policy_digest" in payload
        assert payload["policy_digest"].startswith("sha256:")

    def test_receipt_attached_on_deny(self, policy_dir):
        decision = GovernanceSkill(policy_dir=policy_dir).check_policy("shell:rm /")
        assert decision.receipt is not None
        assert decision.receipt["payload"]["decision"] == "deny"
        # The denial is the receipt - deny decisions MUST produce a receipt too,
        # otherwise there is no tamper-evident proof that the block occurred.

    def test_receipt_verifies_with_public_key(self, policy_dir):
        skill = GovernanceSkill(policy_dir=policy_dir)
        decision = skill.check_policy("file:read:/x")
        pub_pem = skill.signer.public_pem()
        pub = serialization.load_pem_public_key(pub_pem)
        assert verify_receipt(decision.receipt, pub)

    def test_receipt_tampering_fails_verification(self, policy_dir):
        skill = GovernanceSkill(policy_dir=policy_dir)
        decision = skill.check_policy("file:read:/x")
        pub = serialization.load_pem_public_key(skill.signer.public_pem())
        # Flip a field
        tampered = {
            "payload": {**decision.receipt["payload"], "decision": "allow_forged"},
            "signature": decision.receipt["signature"],
        }
        assert not verify_receipt(tampered, pub)

    def test_chain_linkage(self, policy_dir):
        """Successive decisions link via previousReceiptHash."""
        skill = GovernanceSkill(policy_dir=policy_dir)
        first = skill.check_policy("file:read:/a")
        second = skill.check_policy("file:read:/b")
        assert "previousReceiptHash" not in first.receipt["payload"]
        assert second.receipt["payload"]["previousReceiptHash"] == receipt_hash(first.receipt)

    def test_no_sign_flag_skips_receipt(self, policy_dir):
        decision = GovernanceSkill(policy_dir=policy_dir).check_policy("file:read:/x", sign=False)
        assert decision.receipt is None


class TestSandboxBackend:
    """Receipt payload records which sandbox layer wrapped the process."""

    def test_default_is_sb_runtime_builtin(self, policy_dir):
        decision = GovernanceSkill(policy_dir=policy_dir).check_policy("file:read:/x")
        assert decision.sandbox_backend == SandboxBackend.SB_RUNTIME_BUILTIN
        assert decision.receipt["payload"]["sandbox_backend"] == "sb_runtime_builtin"

    def test_nono_backend_sets_ring_2(self, policy_dir):
        skill = GovernanceSkill(
            policy_dir=policy_dir,
            sandbox_backend=SandboxBackend.NONO,
            ring=2,
        )
        decision = skill.check_policy("file:read:/x")
        assert decision.sandbox_backend == SandboxBackend.NONO
        assert decision.ring == 2
        assert decision.receipt["payload"]["sandbox_backend"] == "nono"
        assert decision.receipt["payload"]["ring"] == 2

    def test_openshell_backend(self, policy_dir):
        skill = GovernanceSkill(
            policy_dir=policy_dir,
            sandbox_backend=SandboxBackend.OPENSHELL,
            ring=2,
        )
        decision = skill.check_policy("file:read:/x")
        assert decision.receipt["payload"]["sandbox_backend"] == "openshell"

    def test_sandbox_backend_covered_by_signature(self, policy_dir):
        """Forging the sandbox backend after signing breaks verification."""
        skill = GovernanceSkill(policy_dir=policy_dir, sandbox_backend=SandboxBackend.NONO, ring=2)
        decision = skill.check_policy("file:read:/x")
        pub = serialization.load_pem_public_key(skill.signer.public_pem())
        forged = {
            "payload": {**decision.receipt["payload"], "sandbox_backend": "sb_runtime_builtin"},
            "signature": decision.receipt["signature"],
        }
        assert not verify_receipt(forged, pub)


class TestPolicyDigest:
    def test_policy_digest_deterministic(self, tmp_path):
        yaml.safe_dump(SAMPLE, (tmp_path / "p.yaml").open("w"))
        one = GovernanceSkill(policy_dir=tmp_path).policy_digest
        two = GovernanceSkill(policy_dir=tmp_path).policy_digest
        assert one == two
        assert one.startswith("sha256:")

    def test_policy_digest_changes_when_rules_change(self, tmp_path):
        yaml.safe_dump(SAMPLE, (tmp_path / "p.yaml").open("w"))
        before = GovernanceSkill(policy_dir=tmp_path).policy_digest

        modified = {
            "apiVersion": "governance.toolkit/v1",
            "rules": SAMPLE["rules"] + [
                {
                    "name": "extra-rule",
                    "condition": {"field": "action", "operator": "equals", "value": "file:write"},
                    "action": "deny",
                    "priority": 50,
                }
            ],
        }
        (tmp_path / "p.yaml").write_text(yaml.safe_dump(modified))
        after = GovernanceSkill(policy_dir=tmp_path).policy_digest
        assert before != after


class TestSignerKeyLoading:
    def test_generate_produces_deterministic_kid(self, tmp_path):
        signer = Signer.generate()
        pem = signer.private_pem()
        reloaded = Signer.from_pem(pem)
        assert signer.kid == reloaded.kid

    def test_explicit_kid_overrides_thumbprint(self):
        signer = Signer.generate(kid="sb:issuer:test-fixture")
        assert signer.kid == "sb:issuer:test-fixture"
