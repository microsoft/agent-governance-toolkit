# Microsoft Agent Framework — Governance Middleware Integration

**Submission:** [microsoft/agent-framework#4440](https://github.com/microsoft/agent-framework/issues/4440)
**Status:** ✅ Implemented (Level 1) — Middleware adapter with 18 passing tests. Awaiting MAF team for Level 2/3.
**Type:** Feature proposal (3-level integration)
**Sponsor:** Patrick Chanezon (VP DevRel) — "+@ShawnHenry to integrate with MAF before you ship this."
**Date Submitted:** March 3, 2026

---

## Context

As part of the OSS approval for [microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit), VP Developer Relations Patrick Chanezon specifically requested MAF integration before public release:

> "+@Shawn Henry to integrate with MAF before you ship this."

This document outlines the existing integration and proposed deeper collaboration.

## What We Built

Three middleware classes that plug directly into Agent Framework's middleware pipeline:

### GovernancePolicyMiddleware
- **Hook:** `process()` — intercepts before agent execution
- **Capabilities:** Token limits, rate limiting, blocked patterns (regex/glob), content safety
- **OWASP:** Mitigates ASI-01 (Agent Hijacking), ASI-02 (Excessive Capabilities)

### CapabilityGuardMiddleware
- **Hook:** `process()` — blocks unauthorized tool calls
- **Capabilities:** Tool-level allow/deny lists, capability sandboxing
- **OWASP:** Mitigates ASI-02 (Excessive Capabilities), ASI-06 (Confused Deputy)

### OutputValidationMiddleware
- **Hook:** `process()` — validates agent responses
- **Capabilities:** PII detection, output length limits, blocked output patterns
- **OWASP:** Mitigates ASI-05 (Insecure Output)

### MAFKernel Convenience Class
Configures all three middleware with a single policy object:

```python
from agent_os.integrations.maf_adapter import maf_govern

kernel = maf_govern(agent, policy="policy.yaml")
result = await kernel.invoke(task)
```

## Test Coverage

**18 tests passing** covering:
- Policy enforcement (token limits, rate limiting, blocked patterns)
- Capability guards (tool allow/deny, unknown tool blocking)
- Output validation (PII detection, length limits)
- Goal drift detection
- Middleware chaining and error handling

## Integration Proposal

### Level 1: Documentation (Immediate)
- Add Agent Governance Toolkit to Agent Framework's ecosystem/integrations docs
- Show how governance middleware slots into existing middleware pipeline
- **Effort:** 1-2 days
- **Owner:** Agent Governance Toolkit team

### Level 2: Sample (Short-term)
- Contribute a governance sample to [Agent-Framework-Samples](https://github.com/microsoft/Agent-Framework-Samples)
- End-to-end example: policy YAML → middleware → agent with audit trail
- **Effort:** 1 week
- **Owner:** Joint (Agent Governance + MAF team)

### Level 3: Native Support (Medium-term)
- Governance middleware as an optional package (`agent-framework[governance]`)
- Policy schema validation integrated with Agent Framework's config system
- Built-in OWASP Agentic Top 10 compliance checks
- **Effort:** 2-4 weeks
- **Owner:** Joint (requires MAF team architecture guidance)

## Why This Matters

1. **Enterprise readiness** — Customers need governance before deploying agents in production. This makes MAF enterprise-ready out of the box.
2. **OWASP coverage** — The middleware covers 10/10 OWASP Agentic Top 10 risks at the framework level.
3. **VP-approved OSS** — This project has been approved for open-source release under microsoft/ org by VP Developer Relations.
4. **Standards alignment** — Active proposals at AAIF, LF AI, CoSAI WS4, and OWASP for governance standards.

## Existing Code

| File | Location |
|------|----------|
| MAF Adapter | `packages/agent-os/src/agent_os/integrations/maf_adapter.py` |
| MAF Tests | `packages/agent-os/tests/test_maf_adapter.py` (18/18 passing) |
| README | MAF listed as primary integration in toolkit README |

## Related Proposals

| Stakeholder | Action | Link |
|-------------|--------|------|
| **Marco Casalaina** | Foundry governance integration | Pending discussion |
| **Chris DiBona / Caitie** | AAIF project candidacy | [docs/AAIF-PROPOSAL.md](./AAIF-PROPOSAL.md) |
| **Shawn Henry** | MAF integration (this document) | [microsoft/agent-framework#4440](https://github.com/microsoft/agent-framework/issues/4440) |

## Next Steps

1. Await MAF team response on preferred integration approach
2. Submit governance sample to Agent-Framework-Samples
3. Coordinate with Shawn Henry per VP's direction
4. Iterate on middleware API based on MAF team feedback
