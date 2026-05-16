# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Pin the ``StepReceipt`` -> ``MerkleAuditChain`` adapter from
``docs/proposals/azure-aca-sandbox.md`` (Step 7) against the real
:class:`~agentmesh.governance.audit.AuditEntry` and
:class:`~agentmesh.governance.audit.MerkleAuditChain` classes.

If this test breaks, the adapter snippet in the docs is stale and must
be updated in lock-step with whichever schema field changed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agentmesh.governance.audit import AuditEntry, MerkleAuditChain


# ---------------------------------------------------------------------------
# StepReceipt is defined inline in the docs (Step 5.2). We mirror the
# exact shape here so this test fails fast if the doc's dataclass drifts.
# ---------------------------------------------------------------------------


@dataclass
class StepReceipt:
    step_index: int
    intent: str
    decision: str
    reason: str | None
    azure_sandbox_id: str | None
    duration_seconds: float
    stdout_excerpt: str
    stderr_excerpt: str
    egress_decisions: list[dict] = field(default_factory=list)


def chain_receipt(
    receipt: StepReceipt,
    agent_id: str,
    ticket_id: str,
    chain: MerkleAuditChain,
) -> AuditEntry:
    """Verbatim adapter from docs/proposals/azure-aca-sandbox.md Step 7."""
    entry = AuditEntry(
        event_type="sandbox.execute",
        agent_did=agent_id,
        action=f"step:{receipt.step_index}",
        resource=f"ticket:{ticket_id}",
        data={
            "intent": receipt.intent,
            "azure_sandbox_id": receipt.azure_sandbox_id,
            "duration_seconds": receipt.duration_seconds,
            "egress_decisions": receipt.egress_decisions,
            "stdout_excerpt": receipt.stdout_excerpt,
            "stderr_excerpt": receipt.stderr_excerpt,
        },
        outcome=receipt.decision,
        policy_decision=receipt.decision,
        matched_rule=receipt.reason,
        session_id=receipt.azure_sandbox_id,
    )
    chain.add_entry(entry)
    return entry


def _receipt(step: int, decision: str = "allowed", reason: str | None = None) -> StepReceipt:
    return StepReceipt(
        step_index=step,
        intent=f"step {step}",
        decision=decision,
        reason=reason,
        azure_sandbox_id=f"sb-{step:04d}",
        duration_seconds=0.5,
        stdout_excerpt="ok",
        stderr_excerpt="",
        egress_decisions=[{"host": "pypi.org", "action": "Allow"}],
    )


class TestStepReceiptToMerkleAdapter:
    def test_single_receipt_chains_and_verifies(self):
        chain = MerkleAuditChain()
        entry = chain_receipt(_receipt(0), "research-agent-1", "TKT-1", chain)
        assert entry.entry_hash, "entry_hash should be populated by add_entry"
        assert entry.previous_hash == ""  # first entry, no parent
        assert chain.get_root_hash() == entry.entry_hash
        ok, err = chain.verify_chain()
        assert ok and err is None

    def test_multiple_receipts_chain_correctly(self):
        chain = MerkleAuditChain()
        entries = [
            chain_receipt(_receipt(i), "research-agent-1", "TKT-2", chain)
            for i in range(5)
        ]
        # Each entry's previous_hash must match the prior entry's entry_hash.
        for prev, curr in zip(entries, entries[1:]):
            assert curr.previous_hash == prev.entry_hash
        ok, err = chain.verify_chain()
        assert ok and err is None
        assert chain.get_root_hash() is not None

    def test_decision_outcomes_are_preserved(self):
        chain = MerkleAuditChain()
        outcomes = ["allowed", "denied-by-policy", "blocked-at-egress",
                    "timeout", "error"]
        entries = [
            chain_receipt(
                _receipt(i, decision=outcome, reason=f"r:{outcome}"),
                "agent-1", "TKT-3", chain,
            )
            for i, outcome in enumerate(outcomes)
        ]
        for entry, outcome in zip(entries, outcomes):
            assert entry.outcome == outcome
            assert entry.policy_decision == outcome
            assert entry.matched_rule == f"r:{outcome}"

    def test_egress_decisions_round_trip_through_data_field(self):
        chain = MerkleAuditChain()
        receipt = _receipt(0)
        receipt.egress_decisions = [
            {"host": "pypi.org", "action": "Allow", "ts": "2026-05-12T00:00:00Z"},
            {"host": "example.com", "action": "Deny", "reason": "not-allowlisted"},
        ]
        entry = chain_receipt(receipt, "agent-1", "TKT-4", chain)
        assert entry.data["egress_decisions"] == receipt.egress_decisions

    def test_resource_field_is_namespaced_to_ticket(self):
        chain = MerkleAuditChain()
        entry = chain_receipt(_receipt(0), "agent-1", "TKT-5", chain)
        assert entry.resource == "ticket:TKT-5"

    def test_action_carries_step_index(self):
        chain = MerkleAuditChain()
        entry = chain_receipt(_receipt(7), "agent-1", "TKT-6", chain)
        assert entry.action == "step:7"

    def test_session_id_links_to_azure_sandbox(self):
        chain = MerkleAuditChain()
        entry = chain_receipt(_receipt(0), "agent-1", "TKT-7", chain)
        assert entry.session_id == "sb-0000"

    def test_tampering_detected_by_verify_chain(self):
        chain = MerkleAuditChain()
        for i in range(3):
            chain_receipt(_receipt(i), "agent-1", "TKT-8", chain)
        # Tamper with a stored entry's data dict; recompute its hash by hand
        # MUST disagree with the chain's recorded entry_hash.
        tampered = chain._entries[1]
        tampered.data["intent"] = "TAMPERED"
        ok, _ = chain.verify_chain()
        assert ok is False

    def test_root_hash_changes_with_each_append(self):
        chain = MerkleAuditChain()
        roots = []
        for i in range(4):
            chain_receipt(_receipt(i), "agent-1", "TKT-9", chain)
            roots.append(chain.get_root_hash())
        assert len(set(roots)) == len(roots), "each append must produce a new root"
