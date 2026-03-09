# Google ADK — GovernancePlugin Proposal

**Submission:** [google/adk-python#4543](https://github.com/google/adk-python/issues/4543)
**Status:** Open — under Google team review
**Type:** Feature request (BasePlugin implementation)
**Date Submitted:** March 2, 2026

---

## Summary

Proposal to contribute a `GovernancePlugin` for Google's Agent Development Kit (ADK) that provides policy-based access control, threat detection, and audit trails. The plugin leverages ADK's existing `BasePlugin` hook architecture — no framework changes needed.

## Problem

ADK's plugin architecture (`BasePlugin`) has all the right hooks for governance enforcement — `before_tool_callback`, `before_agent_callback`, `on_user_message_callback` — but there's no built-in governance plugin. The existing plugins cover analytics (BigQuery), logging, context filtering, and retry, but nothing for **policy-based access control, threat detection, or audit trails**.

Enterprise teams building multi-agent systems need to enforce who can call what tools, detect dangerous prompts before they reach agents, and maintain compliance-grade audit logs.

## Proposed GovernancePlugin

A `BasePlugin` implementation providing four capabilities:

### 1. Tool-Level Policy Enforcement (`before_tool_callback`)
- Allowlist/blocklist tools per policy
- Block on content patterns (credentials, PII)
- Enforce rate limits per agent/tool combination

### 2. Prompt Threat Detection (`on_user_message_callback`)
- Scan user messages for data exfiltration signals
- Detect privilege escalation attempts
- Identify prompt injection patterns
- Block system destruction signals
- All scanning happens *before* messages reach the agent

### 3. Agent-Level Trust Gating (`before_agent_callback`)
- Verify trust scores before allowing agent delegation
- Enforce trust thresholds in multi-agent systems
- DID-based identity verification (optional)

### 4. Audit Trail (`after_tool_callback` + `after_agent_callback`)
- Append-only log of all governance decisions
- SHA-256 hash chain for tamper evidence
- JSON Lines format for log aggregation compatibility

## Example API

```python
from google.adk.runners import Runner
from governance_plugin import GovernancePlugin, GovernancePolicy

policy = GovernancePolicy(
    name="production",
    allowed_tools=["search_docs", "query_db", "create_ticket"],
    blocked_tools=["shell_exec", "delete_records"],
    blocked_patterns=[r"(?i)(api[_-]?key|password)\s*[:=]"],
    max_calls_per_request=25,
    require_human_approval=["create_ticket"],
)

runner = Runner(
    agent=root_agent,
    plugins=[GovernancePlugin(policy=policy)],
)
```

## Design Decisions

| Decision | Approach | Rationale |
|----------|----------|-----------|
| **Policy source** | YAML/JSON config files | Policies change without deploys |
| **Composition** | Most-restrictive-wins merging | Org → Team → Agent layering |
| **Fail mode** | Closed (deny on error) | Safety-first for production |
| **Audit format** | JSON Lines | Compatible with log aggregation |
| **Threat detection** | Regex pattern matching | Deterministic, auditable, no LLM dependency |

## Why Not Existing Samples?

| Existing | Limitation |
|----------|-----------|
| `safety-plugins` | Focuses on Google Model Armor (cloud-dependent content safety) |
| `policy-as-code` | Focuses on infrastructure policy checking (Terraform/OPA) |
| **This proposal** | **Runtime tool-level governance** — controlling what agents can do within execution, independent of cloud services |

## Cross-Framework Validation

This pattern has been validated across multiple frameworks:

| Framework | Package | Tests |
|-----------|---------|-------|
| PydanticAI | [pydantic-ai-governance](https://github.com/microsoft/agent-governance-toolkit/tree/master/pydantic-ai-governance) | 57 |
| CrewAI | [crewai-agentmesh](https://github.com/microsoft/agent-governance-toolkit/tree/master/crewai-agentmesh) | — |
| Microsoft Agent Framework | MAF middleware adapter | 18 |
| Mastra | [@agentmesh/mastra](https://github.com/microsoft/agent-governance-toolkit/tree/master/mastra-agentmesh) | 19 |
| **Agent OS** (core) | [agent-os](https://github.com/microsoft/agent-governance-toolkit) | 1,327 |

## OWASP Coverage

The GovernancePlugin covers 10/10 OWASP Agentic Top 10 risks through ADK's native hooks:

- `before_tool_callback` → ASI-01 (Hijacking), ASI-02 (Excessive Capabilities), ASI-06 (Confused Deputy)
- `on_user_message_callback` → ASI-01 (Hijacking), ASI-05 (Insecure Output)
- `before_agent_callback` → ASI-03 (Insecure Communication), ASI-07 (Identity Spoofing)
- `after_tool_callback` → ASI-09 (Missing Audit Trails)

## Links

- [Google ADK](https://github.com/google/adk-python)
- [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
- [OWASP Compliance Mapping](https://github.com/microsoft/agent-governance-toolkit/blob/master/docs/OWASP-COMPLIANCE.md)
