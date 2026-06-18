from typing import List, Optional, Dict, Any
from src.models import (
    ContinuityWitness, CCVResult,
    IdentityTransition, ConstitutionTransition,
    ObserverTransition, DelegationTransition
)
from src.witness_chain import WitnessChain

class CCVEngine:
    def __init__(self):
        self.chain = WitnessChain()

    def verify_continuity(
        self,
        witnesses: List[ContinuityWitness],
        baseline: Optional[ContinuityWitness] = None
    ) -> CCVResult:
        if not witnesses:
            return CCVResult(
                continuity_score=0.0,
                identity_preserved=False,
                constitution_preserved=False,
                delegation_drift=1.0,
                observer_drift=1.0,
                reference_frame_drift=1.0,
                witness_count=0,
                verification_status="FAIL",
                break_reason="No witnesses provided"
            )

        self.chain.witnesses = []
        for w in witnesses:
            self.chain.add_witness(w)

        if not self.chain.verify_chain():
            return CCVResult(
                continuity_score=0.0,
                identity_preserved=False,
                constitution_preserved=False,
                delegation_drift=1.0,
                observer_drift=1.0,
                reference_frame_drift=1.0,
                witness_count=len(witnesses),
                verification_status="FAIL",
                break_reason="Chain integrity verification failed"
            )

        if baseline is None:
            baseline = witnesses[0]

        break_idx = self.chain.detect_break(baseline)

        observer_changes = 0
        ref_changes = 0
        constitution_changes = 0

        for w in witnesses:
            if w.observer_hash != baseline.observer_hash:
                observer_changes += 1
            if w.reference_frame_hash != baseline.reference_frame_hash:
                ref_changes += 1
            if w.constitution_hash != baseline.constitution_hash:
                constitution_changes += 1

        n = len(witnesses)
        observer_drift = observer_changes / n if n > 0 else 0.0
        ref_drift = ref_changes / n if n > 0 else 0.0
        constitution_drift = constitution_changes / n if n > 0 else 0.0

        identity_preserved = observer_drift < 0.1
        constitution_preserved = constitution_drift < 0.1
        delegation_drift = ref_drift

        continuity_score = 1.0 - (
            (observer_drift * 0.4) +
            (ref_drift * 0.3) +
            (constitution_drift * 0.3)
        )

        if continuity_score >= 0.8 and identity_preserved and constitution_preserved:
            status = "PASS"
            break_reason = None
        elif continuity_score >= 0.5:
            status = "PARTIAL"
            break_reason = f"Continuity score {continuity_score:.2f} below threshold"
        else:
            status = "FAIL"
            break_reason = f"Continuity broken at index {break_idx}" if break_idx is not None else "Continuity failed"

        # Build detailed transitions
        last_witness = witnesses[-1]
        identity_transition = IdentityTransition(
            before_hash=baseline.observer_hash,
            after_hash=last_witness.observer_hash,
            preserved=identity_preserved
        )
        constitution_transition = ConstitutionTransition(
            before_hash=baseline.constitution_hash,
            after_hash=last_witness.constitution_hash,
            preserved=constitution_preserved
        )
        observer_transition = ObserverTransition(
            before_hash=baseline.observer_hash,
            after_hash=last_witness.observer_hash,
            drift=observer_drift
        )
        delegation_transition = DelegationTransition(
            before=baseline.reference_frame_hash,
            after=last_witness.reference_frame_hash,
            drift=ref_drift
        )

        return CCVResult(
            continuity_score=continuity_score,
            identity_preserved=identity_preserved,
            constitution_preserved=constitution_preserved,
            delegation_drift=delegation_drift,
            observer_drift=observer_drift,
            reference_frame_drift=ref_drift,
            witness_count=n,
            first_break_index=break_idx,
            break_reason=break_reason,
            verification_status=status,
            identity_transition=identity_transition,
            constitution_transition=constitution_transition,
            observer_transition=observer_transition,
            delegation_transition=delegation_transition
        )

    def export_proof(self, result: CCVResult, witnesses: List[ContinuityWitness]) -> Dict[str, Any]:
        return {
            "verification_result": result.model_dump(mode='json'),
            "witness_chain": [w.model_dump(mode='json') for w in witnesses],
            "chain_root_hash": self.chain.get_latest_witness().witness_hash if self.chain.witnesses else None,
            "proof_signature": None
        }