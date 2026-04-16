# Supplemental: MCP Governance Policies

This guide moves one layer outward to **Model Context Protocol (MCP)**, where
agents discover and call tools exposed by external servers.

**What you'll learn:**

| Section | Topic |
|---------|-------|
| [Introduction](#introduction) | Why MCP needs governance |
| [The MCP Proxy](#the-mcp-proxy) | How `@microsoft/agentmesh-mcp-proxy` intercepts tool calls |
| [Policy YAML format](#policy-yaml-format) | How proxy policies are structured |
| [Built-in policies](#built-in-policies) | Minimal, standard, strict, enterprise |
| [Writing custom rules](#writing-custom-rules) | Path filters, regex filters, and rate limits |
| [OWASP alignment](#owasp-alignment) | How rules map to ASI-01 through ASI-10 |
| [Trust-gated MCP access](#trust-gated-mcp-access) | DID- and trust-based access gates |
| [Next steps](#next-steps) | Where to go from here |

---

## Introduction

MCP is the protocol that lets an agent connect to tools such as filesystems,
databases, GitHub APIs, or custom business services:

`agent -> MCP client -> MCP server -> tool`

By default, MCP does not decide whether a tool call is *safe*. If an agent has a
handle to `run_shell`, `query_database`, or `read_file`, a prompt injection or
over-permissive workflow can turn that into code execution, data exfiltration, or
runaway automation. Governance answers which tools and arguments are allowed and
what gets logged for audit.

---

## The MCP Proxy

[`@microsoft/agentmesh-mcp-proxy`](../../../packages/agent-mesh/packages/mcp-proxy/README.md)
sits **between the agent and the original MCP server**. The proxy intercepts
requests and either forwards or blocks the call.

The proxy only intercepts `tools/call` messages. Other MCP traffic passes through
unchanged. For every tool call, it:

1. **Sanitizes inputs** for dangerous patterns.
2. **Applies a CLI rate limit** if you passed `--rate-limit`.
3. **Evaluates policy rules**.
4. **Audits the decision** and either forwards or denies.

Run it like this:

```bash
npx @microsoft/agentmesh-mcp-proxy protect --policy standard @anthropic/mcp-server-filesystem /workspace
```

That makes the proxy the enforcement point in front of the MCP server.

---

## Policy YAML format

Use [`standard.yaml`](../../../packages/agent-mesh/packages/mcp-proxy/policies/standard.yaml)
as the reference shape. Proxy policies are intentionally small: a header, a list
of rules, and optional schema fields for rate limiting.

```yaml
version: "1.0"
mode: enforce

rules:
  - tool: "run_shell"
    action: deny
    reason: "Shell execution not permitted"

  - tool: "read_file"
    action: allow
    conditions:
      - path_not_contains: [".env", ".secret", "credentials"]

  - tool: "http_request"
    action: allow
    rate_limit:
      requests: 30
      per: minute

  - tool: "*"
    action: allow

rate_limits:
  global:
    requests: 100
    per: minute
```

The important pieces are `mode`, ordered `rules`, and per-rule `conditions`. The
schema also supports per-rule `rate_limit` and top-level `rate_limits`, and the
proxy also accepts a global `--rate-limit` CLI option.

Two details matter in practice: **first match wins**, and an explicit `*` rule
keeps your intent obvious during review.

In the current code, rate limiting exists both in the policy shape and in the
proxy runtime path. If you want an explicit global limit from the CLI, use
`--rate-limit`.

For the built-in `minimal` tier, the policy is effectively just:

```yaml
version: "1.0"
mode: enforce
rules:
  - tool: "*"
    action: allow
```

Useful for demos and auditing, but not for containment.

---

## Built-in policies

The proxy ships with four policy tiers:

| Tier | Best for | Behavior |
|------|----------|----------|
| `minimal` | Demos and visibility-first testing | Allow everything |
| `standard` | Development and staging | Block obviously dangerous tools, allow most others |
| `strict` | High-security environments | Allowlist-only behavior with explicit read-focused rules |
| `enterprise` | Production starting point | Denials, path filters, regex guards, and stronger database/file constraints |

`standard` is the balanced default. `strict` flips to allowlist-only behavior.
`enterprise` adds stronger patterns for tools like `query_database`.

---

## Writing custom rules

The schema gives you four practical levers:

1. **Deny dangerous tools** such as shell or eval.
2. **Scope file access by path**.
3. **Reject suspicious argument patterns** such as destructive SQL.
4. **Add rate limits** for expensive or sensitive tools.

Here is a copy-paste-ready example with OWASP annotations as YAML comments:

```yaml
version: "1.0"
mode: enforce

rules:
  # ASI-02, ASI-05
  - tool: "run_shell"
    action: deny
    reason: "Shell access is blocked"

  - tool: "eval"
    action: deny
    reason: "Dynamic evaluation is blocked"

  # ASI-02, ASI-06
  - tool: "read_file"
    action: allow
    conditions:
      - path_starts_with: "C:\\workspace\\docs\\"
      - path_not_contains: [".env", ".pem", "secrets", "credentials"]
    rate_limit:
      requests: 30
      per: minute

  # ASI-02, ASI-06
  - tool: "query_database"
    action: allow
    conditions:
      - argument_not_matches:
          query: "(?i)\\b(DROP|DELETE|TRUNCATE|ALTER)\\b"
    rate_limit:
      requests: 10
      per: minute

  # ASI-10
  - tool: "*"
    action: deny
    reason: "Tool not approved for this agent"

rate_limits:
  global:
    requests: 60
    per: minute
```

This one file says: no shell, no eval, no secrets, and no destructive SQL. It
also shows how to declare rate limits in the policy file, while `--rate-limit`
remains useful when you want an explicit global CLI limit.

---

## OWASP alignment

The detailed evidence lives in
[`docs/compliance/owasp-llm-top10-mapping.md`](../../compliance/owasp-llm-top10-mapping.md)
and [`docs/OWASP-COMPLIANCE.md`](../../OWASP-COMPLIANCE.md). For MCP governance,
the practical alignment looks like this:

| OWASP risk | How proxy policies help |
|------------|-------------------------|
| **ASI-01 Agent Goal Hijack** | Allow/deny rules stop hijacked prompts from reaching unapproved tools |
| **ASI-02 Tool Misuse & Exploitation** | Tool allowlists, denylists, path filters, and argument regexes constrain tool behavior |
| **ASI-03 Identity & Privilege Abuse** | Pair proxy rules with DID-based trust checks so access is tied to agent identity |
| **ASI-04 Supply Chain Vulnerabilities** | Reviewable built-in tiers and checked-in YAML reduce surprise exposure from third-party MCP tools |
| **ASI-05 Unexpected Code Execution** | Deny `run_shell`, `execute_command`, `eval`, and `spawn_process` |
| **ASI-06 Memory & Context Poisoning** | Secret-path blocking and argument filtering prevent poisoned context from turning into exfiltration |
| **ASI-07 Insecure Inter-Agent Communication** | Trust-gated MCP endpoints add authentication and trust checks before agents collaborate |
| **ASI-08 Cascading Failures** | CLI rate limits and deny rules reduce runaway call chains |
| **ASI-09 Human-Agent Trust Exploitation** | Audit visibility helps, and this guide naturally leads into approval workflows for sensitive actions |
| **ASI-10 Rogue Agents** | Catch-all deny rules and rate caps confine agents that drift out of scope |

The important pattern is **enforcement, not just detection**. A good policy
blocks risky tool calls before they reach the server.

---

## Trust-gated MCP access

For some environments, allow/deny rules are not enough. You also want to know
*who* is asking. This repo has two related Python packages:

- [`mcp-trust-proxy`](../../../packages/agentmesh-integrations/mcp-trust-proxy/README.md)
  is the inline trust-gating layer.
- [`mcp-trust-server`](../../../packages/agent-mesh/packages/mcp-trust-server/README.md)
  is an MCP server that exposes trust-management tools such as `check_trust`,
  `get_trust_score`, `establish_handshake`, and `verify_delegation`.

If you want a **trust proxy**, use `mcp-trust-proxy`. If you want an MCP surface
that lets clients query and manage trust, use `mcp-trust-server`.

```python
from mcp_trust_proxy import TrustProxy, ToolPolicy

proxy = TrustProxy(
    default_min_trust=300,
    tool_policies={
        "file_write": ToolPolicy(min_trust=800, required_capabilities=["fs_write"]),
        "shell_exec": ToolPolicy(min_trust=900, blocked=True),
    },
)

result = proxy.authorize(
    agent_did="did:agentmesh:agent-1",
    agent_trust_score=600,
    agent_capabilities=["fs_read", "search"],
    tool_name="file_read",
)

assert result.allowed
```

Use `mcp-trust-server` alongside that when you want trust operations over MCP.
**Policy** decides what can happen; **trust** helps decide who gets to ask.

---

## Next steps

1. Read [`enterprise.yaml`](../../../packages/agent-mesh/packages/mcp-proxy/policies/enterprise.yaml).
2. Review [`docs/compliance/owasp-llm-top10-mapping.md`](../../compliance/owasp-llm-top10-mapping.md)
   and [`docs/OWASP-COMPLIANCE.md`](../../OWASP-COMPLIANCE.md).
3. Start with `standard`, then move to `strict` or custom rules.

---

Some actions are too risky to decide with automation alone. In the main series,
the next planned topic is **approval workflows**.

**Previous:** [Chapter 3 — Rate Limiting](03-rate-limiting.md)
**Next:** [Chapter 5 — Approval Workflows](05-approval-workflows.md)
