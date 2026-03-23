# Proposal: Haystack Integration

**Status:** ✅ Shipped — Integration package implemented, upstream collaboration active  
**Author:** Imran Siddique (Microsoft)  
**Created:** 2026-03-08  
**Target:** deepset-ai/haystack

## Summary

Integration adapter connecting Haystack pipelines with AGT governance. Implements GovernancePolicyChecker, TrustGate, and AuditLogger as Haystack SuperComponents.

## External Engagement

- Issue: [deepset-ai/haystack#10769](https://github.com/deepset-ai/haystack/issues/10769) — Collaboration proposal accepted
- PR: [openlit/openlit#1062](https://github.com/openlit/openlit/pull/1062) — Documentation submitted
- Haystack team recommended standalone integration package (`governance-haystack`)

## Implementation

- **Package:** `packages/agentmesh-integrations/haystack-agentmesh/`
- **Module:** `src/haystack_agentmesh/`

### Components

| Component | File | Description |
|-----------|------|-------------|
| **GovernancePolicyChecker** | `governance.py` | Enforces governance policies on agent actions — tool allowlist/blocklist, content pattern filtering (substring, regex, glob), token limit enforcement, per-agent rate limiting with time-based windows. Outputs `decision` (allow/deny/audit), `reason`, and `passed` flag. |
| **TrustGate** | `trust_gate.py` | Evaluates agent trust scores (0.0–1.0) and routes decisions based on configurable thresholds. Tracks success/failure with reward/penalty adjustments and time-based trust decay. Outputs `trusted` flag, `score`, and `action` (pass/review/block). |
| **AuditLogger** | `audit.py` | Append-only tamper-evident audit logging with SHA-256 hash chain integrity. Each entry hashes to the previous for immutability verification. Supports JSONL export for offline analysis. Outputs `entry_id` and `chain_hash`. |

### Internal Data Classes

| Class | File | Description |
|-------|------|-------------|
| `AgentTrustRecord` | `trust_gate.py` | Internal state container for per-agent trust data (score, successes, failures, last_update) |
| `AuditEntry` | `audit.py` | Immutable audit record container (entry_id, timestamp, action, agent_id, decision, metadata, prev_hash, chain_hash) |

### Graceful Fallback

All three components implement identical fallback logic when `haystack-ai` is not installed:

```python
try:
    from haystack import component
except ImportError:  # pragma: no cover
    class _ComponentShim:
        def __call__(self, cls):
            return cls
        @staticmethod
        def input_types(**kwargs):
            def decorator(func): return func
            return decorator
        @staticmethod
        def output_types(**kwargs):
            def decorator(func): return func
            return decorator
    component = _ComponentShim()
```

This ensures components function as regular Python classes even without Haystack installed, while registering as proper SuperComponents when Haystack is available.

## References

- [Haystack SuperComponents docs](https://docs.haystack.deepset.ai/docs/supercomponents)
- [Contributing guide](https://github.com/deepset-ai/haystack-core-integrations/blob/main/CONTRIBUTING.md)
- [Package README](../../packages/agentmesh-integrations/haystack-agentmesh/README.md)
