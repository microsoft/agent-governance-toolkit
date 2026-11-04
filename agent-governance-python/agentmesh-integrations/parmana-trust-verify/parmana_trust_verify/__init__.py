"""Verify Parmana execution trust records before an AgentMesh workflow acts on them."""

from .verifier import RecordVerdict, verify_record

__all__ = ["RecordVerdict", "verify_record"]
