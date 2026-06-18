# AGT Integration Guide

## Overview

This guide explains how to integrate DecisionAssure Continuity Kernel into the Microsoft Agent Governance Toolkit (AGT).

## Integration Points

### 1. Witness Generation Hook

In AGT's middleware, after each agent action, generate a continuity witness:

```python
from decisionassure_continuity.src.agt_adapter import AGTAdapter

adapter = AGTAdapter()
witness = adapter.generate_continuity_witness(
    agent_id=agent_id,
    session_id=session_id,
    constitution_hash=constitution_hash,
    observer_hash=observer_hash,
    reference_frame_hash=reference_frame_hash,
    action_hash=action_hash
)

2. Continuity Verification

Before allowing a high‑risk action, verify continuity:

python
result = adapter.verify_continuity(witness_chain)
if result["verification_result"]["verification_status"] != "PASS":
    raise GovernanceDenied("Continuity verification failed")
3. Collusion Interception

During multi‑agent execution, check for collusion:

python
result = adapter.check_collusion(agent_activations)
if result["collusion_detected"]:
    raise GovernanceDenied("Collusion detected")
4. Jailbreak Detection

Before model generation, run the deception probe:

python
result = adapter.scan_jailbreak(hidden_state)
if result["generation_denied"]:
    return "I cannot process that request."
Configuration

Add the following to your AGT policy.yaml:

yaml
extensions:
  - decisionassure-continuity
Example

See examples/basic_continuity.py for a full integration example.