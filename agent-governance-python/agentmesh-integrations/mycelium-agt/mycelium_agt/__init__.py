# Copyright (c) giskard09 (Rama / Mycelium)
# Licensed under the Apache License, Version 2.0.
"""mycelium-agt: Mycelium Trails backend for AGT.

Community integration package — records every agent action as a tamper-evident
TrailRecord anchored on-chain, implementing AGT's EvidenceAnchor contract
without modifying AGT core.

Usage::

    from agent_os.audit import EvidenceCollector
    from mycelium_agt import MyceliumBackend

    collector = EvidenceCollector()
    collector.add_backend(MyceliumBackend(
        agent_id="my-agent-001",
        mycelium_url="https://argentum-api.rgiskard.xyz",
    ))
    receipt = collector.record({"action_type": "file:write", "scope": "audit"})

action_ref derivation — JCS (RFC 8785) + SHA-256:

    preimage  = canonicalize({action_type, agent_id, scope, timestamp})
                → lexicographic key order, no whitespace, UTF-8
    action_ref = SHA-256(preimage) → lowercase hex (64 chars)

Spec: https://github.com/giskard09/argentum-core/blob/main/docs/spec/action-ref.md
"""

from mycelium_agt.backend import MyceliumBackend

__all__ = ["MyceliumBackend"]

__version__ = "0.1.0"
