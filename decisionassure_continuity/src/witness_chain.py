from typing import List, Optional
from src.models import ContinuityWitness
import hashlib
import json

class WitnessChain:
    """Blockchain‑style chain of continuity witnesses."""

    def __init__(self):
        self.witnesses: List[ContinuityWitness] = []

    def add_witness(self, witness: ContinuityWitness) -> ContinuityWitness:
        """Add a witness to the chain, computing its hash."""
        if self.witnesses:
            witness.previous_witness_hash = self.witnesses[-1].witness_hash
        else:
            witness.previous_witness_hash = "0" * 64  # Genesis block
        witness.witness_hash = witness.compute_hash()
        self.witnesses.append(witness)
        return witness

    def verify_chain(self) -> bool:
        """Verify the entire witness chain."""
        if not self.witnesses:
            return True
        for i, witness in enumerate(self.witnesses):
            computed = witness.compute_hash()
            if computed != witness.witness_hash:
                return False
            if i > 0:
                if witness.previous_witness_hash != self.witnesses[i-1].witness_hash:
                    return False
        return True

    def get_latest_witness(self) -> Optional[ContinuityWitness]:
        """Get the most recent witness."""
        return self.witnesses[-1] if self.witnesses else None

    def detect_break(self, baseline: ContinuityWitness) -> Optional[int]:
        """Find the first index where continuity breaks."""
        for i, witness in enumerate(self.witnesses):
            if witness.observer_hash != baseline.observer_hash:
                return i
            if witness.reference_frame_hash != baseline.reference_frame_hash:
                return i
            if witness.constitution_hash != baseline.constitution_hash:
                return i
        return None

    def export_chain(self) -> List[dict]:
        """Export chain as list of dicts."""
        return [w.model_dump(mode='json') for w in self.witnesses]