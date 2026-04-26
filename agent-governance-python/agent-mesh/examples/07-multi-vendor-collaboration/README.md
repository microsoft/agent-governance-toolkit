# Example 07: Multi-Vendor Agent Collaboration

This example demonstrates **trust-gated handoffs** between agents from different AI vendors, orchestrated through AgentMesh's governance layer.

## Scenario

A customer support pipeline where three vendor-specific agents collaborate:

```
Customer Query
      │
      ▼
┌─────────────┐   trust handoff   ┌─────────────┐   trust handoff   ┌─────────────┐
│  Agent A     │ ───────────────▶  │  Agent B     │ ───────────────▶  │  Agent C     │
│  (OpenAI)    │                   │  (Anthropic) │                   │  (Google)    │
│  Customer    │                   │  Research    │                   │  Summary     │
│  Queries     │                   │  Analysis    │                   │  Generation  │
└─────────────┘                   └─────────────┘                   └─────────────┘
      │                                  │                                  │
      └──────────────────────────────────┼──────────────────────────────────┘
                                         ▼
                              ┌─────────────────────┐
                              │   AgentMesh          │
                              │   Trust & Governance │
                              │   ─────────────────  │
                              │   • Trust scoring    │
                              │   • Audit trail      │
                              │   • Policy engine    │
                              │   • Capability scope │
                              └─────────────────────┘
```

## What It Shows

| Feature | Description |
|---|---|
| **Cross-vendor trust** | Agents from OpenAI, Anthropic, and Google verify each other before handoffs |
| **Adaptive trust scores** | Trust increases on success, degrades on failure or policy violations |
| **Trust-gated delegation** | Tasks only route to agents meeting minimum trust thresholds |
| **Cross-vendor audit trail** | Every handoff logged with vendor, timestamp, trust score, and outcome |
| **Untrusted agent handling** | Demonstrates graceful degradation when a vendor's trust drops below threshold |

## Running the Demo

No API keys required — all vendor agents are mocked.

```bash
cd examples/07-multi-vendor-collaboration
python demo.py
```

### Expected Output

The demo runs three rounds:

1. **Round 1** — All agents trusted, full pipeline succeeds
2. **Round 2** — Agent C (Google) produces poor results, trust degrades
3. **Round 3** — Agent C's trust drops below threshold, handoff is denied and fallback activates

After all rounds, a full cross-vendor audit trail is printed.

## Key Concepts

### Trust-Gated Handoffs

Before delegating work to another vendor's agent, AgentMesh verifies:

```python
handshake = TrustHandshake(min_score=700)
result = handshake.verify_peer(target_agent)
if result.trusted:
    delegate(task, target_agent)
else:
    activate_fallback(task)
```

### Adaptive Trust Scoring

Trust scores update after every interaction:

- **Success** → trust increases (e.g., +50 points)
- **Slow response** → minor trust penalty (e.g., −30 points)
- **Policy violation** → major trust penalty (e.g., −200 points)
- **Failure** → significant trust penalty (e.g., −300 points)

### Cross-Vendor Audit Trail

Every handoff is recorded with full provenance:

```
[2024-01-15 10:00:01] HANDOFF agent-a-openai → agent-b-anthropic | trust: 850 | status: APPROVED
[2024-01-15 10:00:02] HANDOFF agent-b-anthropic → agent-c-google  | trust: 800 | status: APPROVED
[2024-01-15 10:00:03] TASK_COMPLETE agent-c-google | trust_delta: -150 | reason: poor_quality
```

## Extending This Example

- **Add more vendors** — Register additional agents with different vendor tags
- **Custom trust policies** — Adjust `MIN_TRUST_SCORE` or add vendor-specific thresholds
- **Real API integration** — Replace mock agents with live OpenAI/Anthropic/Google calls
- **Persistent audit** — Export the audit trail to a database or SIEM

## Production Considerations

| Concern | Recommendation |
|---|---|
| Trust persistence | Store trust scores in a durable backend across restarts |
| Vendor SLAs | Set per-vendor trust thresholds matching contractual SLAs |
| Audit compliance | Export audit trail to immutable storage for regulatory review |
| Fallback chains | Define fallback agents for every vendor in the pipeline |

## Learn More

- [Trust Architecture](../../docs/TRUST.md)
- [Governance Model](../../GOVERNANCE.md)
- [AgentMesh Security](../../SECURITY.md)
