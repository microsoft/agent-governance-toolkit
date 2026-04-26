# Multi-Agent Customer Service Demo

A self-contained example showing how **Agent OS governance** protects a
multi-agent customer-service system.  No real LLM calls are made — every
response is simulated so you can focus on the governance layer.

## What It Does

Three mock agents collaborate to handle customer support tickets:

| Agent | Role |
|---|---|
| **RouterAgent** | Inspects the incoming message and routes it to `SupportAgent` or `EscalationAgent` based on keyword matching. |
| **SupportAgent** | Answers routine questions (refunds, shipping, passwords) using a simulated knowledge base. |
| **EscalationAgent** | Creates priority tickets and notifies supervisors for urgent or sensitive cases. |

## Governance Features Demonstrated

### 1. Rate Limiting (`max_tool_calls`)
Each agent is limited to **5 tool calls** per session.  The demo shows what
happens when SupportAgent exceeds this limit — the governance layer blocks
the call and logs the violation.

### 2. PII Redaction (`blocked_patterns` with regex)
Two regex patterns are configured to detect personally identifiable
information before it reaches any tool:

- **SSN** — `\b\d{3}-\d{2}-\d{4}\b` (e.g. `123-45-6789`)
- **Credit card** — `\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`

When a customer message contains a matching pattern the call is blocked and
an audit event is emitted.

### 3. Allowed Tools (`allowed_tools`)
Only a specific set of tools is permitted:
`lookup_customer`, `search_kb`, `create_ticket`, `escalate`, `send_reply`.
Any attempt to call an unlisted tool (e.g. `delete_account`) is denied.

### 4. Audit Logging (`log_all_calls`, event listeners)
Every governance decision — allowed, blocked, or checkpointed — is recorded
in an in-memory audit log.  At the end of the run the demo prints a full
summary of all audit entries.

### 5. Checkpoints (`checkpoint_frequency`)
A governance checkpoint is automatically created every 3 tool calls,
providing periodic snapshots of agent progress.

## How to Run

```bash
# From the repository root
cd examples/multi-agent-support
python demo.py
```

No extra dependencies are required beyond the `agent-os` source tree (the
script adds `src/` to `sys.path` automatically).

## Example Output

```
================================================================
  Multi-Agent Customer Service Demo
================================================================

  Policy: customer_support (v1.0.0)
  Max tool calls per agent: 5
  Allowed tools: lookup_customer, search_kb, create_ticket, escalate, send_reply
  ...

--- Scenario 1: Normal support request ---
  ✔ ALLOWED  | tool=lookup_customer (call 1/5)
  ✔ ALLOWED  | tool=search_kb (call 2/5)
  ○ CHECKPOINT created: cp-3 (after 3 calls)
  ✔ ALLOWED  | tool=send_reply (call 3/5)

--- Scenario 2: PII redaction (SSN blocked) ---
  ✘ BLOCKED  | tool=lookup_customer
             | reason: Blocked pattern '...' detected in tool arguments

--- Scenario 4: Rate limiting (max 5 calls) ---
  ✘ BLOCKED  | tool=search_kb
             | reason: Max tool calls exceeded (5)
```

## Key API Concepts Used

| Class / Field | Module | Purpose |
|---|---|---|
| `GovernancePolicy` | `agent_os.integrations.base` | Declarative policy: limits, patterns, audit settings |
| `PatternType.REGEX` | `agent_os.integrations.base` | Regex matching for `blocked_patterns` |
| `BaseIntegration` | `agent_os.integrations.base` | Base class providing `create_context`, `emit`, `on` |
| `ExecutionContext` | `agent_os.integrations.base` | Per-agent state: call count, checkpoints, tool history |
| `PolicyInterceptor` | `agent_os.integrations.base` | Evaluates a `ToolCallRequest` against the policy |
| `ToolCallRequest` | `agent_os.integrations.base` | Vendor-neutral representation of a tool call |
| `GovernanceEventType` | `agent_os.integrations.base` | Event types for audit listeners |
