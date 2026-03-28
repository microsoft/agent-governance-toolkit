# Agent OS for VS Code -- Help

## Overview

Agent OS provides kernel-level governance for AI coding assistants running inside VS Code.
It enforces policies in real time, audits every AI suggestion, and visualizes the health
of your agent mesh through a set of sidebar panels and detail views.

---

## Panels

### SLO Dashboard (Sidebar)

Displays Service Level Objective health for the governance kernel. Four metric groups:

| Metric | Meaning |
|---|---|
| Availability | Percentage of successful governance evaluations over the current window. |
| Latency P50 / P95 / P99 | Response time percentiles for policy evaluation calls (milliseconds). |
| Compliance | Percentage of tool calls that passed policy evaluation without violations. |
| Trust Score | Mean and minimum trust scores across all registered agents (0--1000 scale). |

Click the panel header to open the **SLO Detail** view with burn-rate sparklines and error budget gauges.

### Topology (Sidebar)

Shows the agent mesh as a list of registered agents, protocol bridges (A2A, MCP, IATP),
and delegation chains. Each agent entry displays its DID, trust score, and execution ring.

Click the panel header to open the **Topology Detail** view with a force-directed graph.

### Audit Log (Sidebar)

Scrollable list of recent governance events: tool calls evaluated, blocked, warned, or allowed.
Each entry shows timestamp, action, agent DID, affected file, and severity badge.

### Policies (Sidebar)

Lists all active policy rules with their action (ALLOW / DENY / AUDIT / BLOCK), match pattern,
evaluation count, and violation count for the current day.

### Stats (Sidebar)

Aggregate counters: total tool calls blocked, warnings issued, CMVK reviews triggered,
and total log entries. Refreshes on the same tick as all other panels.

### Kernel Debugger (Sidebar)

Live view of kernel internals: registered agents, active violations, saga checkpoints,
and kernel uptime. Useful for diagnosing why a tool call was blocked or escalated.

### Memory Browser (Sidebar)

Virtual filesystem browser showing the episodic memory kernel (EMK) contents.
Navigate directories and inspect files stored by agents during execution.

### Governance Hub (Detail)

Composite view combining SLO, topology, audit, and policy data in a tabbed interface.
Provides a single-pane-of-glass overview of governance health. Tabs: Overview, SLO,
Topology, Audit, Policy.

### SLO Detail (Detail)

Full SLO view with:
- Availability and latency gauges against their targets.
- Error budget remaining bars for availability and latency.
- 24-point burn-rate sparkline showing consumption trend.
- Trust score distribution histogram (4 buckets: 0--250, 251--500, 501--750, 751--1000).

### Topology Detail (Detail)

Force-directed graph of the agent mesh. Nodes are agents colored by trust tier.
Edges represent delegation chains labeled with the delegated capability.
Bridge status indicators show connected protocol bridges.

### Policy Detail (Detail)

Table of all policy rules with columns: name, action, pattern, enabled, evaluations today,
violations today. Sortable and filterable.

---

## Glossary

| Term | Definition |
|---|---|
| SLO | Service Level Objective -- a target for a measurable reliability metric. |
| SLI | Service Level Indicator -- the measured value that an SLO tracks. |
| P50 / P95 / P99 | Latency percentiles. P99 = 99% of requests are faster than this value. |
| Burn Rate | How fast the error budget is being consumed. 1.0 = on pace to exhaust exactly at window end. |
| Error Budget | Allowed unreliability. If target is 99.9%, the budget is 0.1% of total requests. |
| Trust Score | Numeric reputation of an agent (0--1000). Derived from behavioral signals via reward scoring. |
| Trust Ring | Concentric tiers grouping agents by trust level for visualization (high, medium, low). |
| DID | Decentralized Identifier. Format: `did:mesh:<hash>` (toolkit) or `did:myth:<persona>:<hash>` (FailSafe). |
| CMVK | Constitutional Multi-Model Verification Kernel. Cross-checks AI output with multiple models. |
| Delegation Chain | A directed trust relationship where one agent grants a capability to another. |
| Bridge | Protocol adapter connecting Agent Mesh to external systems (A2A, MCP, IATP). |
| CSP | Content Security Policy. HTTP header restricting resource loading in webviews. |
| Policy Action | Evaluation result: ALLOW (permit), DENY (reject), AUDIT (permit + log), BLOCK (reject + alert). |
| Execution Ring | Privilege tier from hypervisor: Ring 0 (root), Ring 1 (supervisor), Ring 2 (user), Ring 3 (sandbox). |
| Agent Mesh | The network of registered agents, their identities, trust scores, and interconnections. |
| Saga | A multi-step workflow with checkpoints and compensating actions managed by the hypervisor. |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Status bar shows **Disconnected** | WebSocket connection to local governance server dropped. | Check that the server is running (`Agent OS: Start Server` command). Verify port 9845 is not blocked. |
| Panel header shows **Stale** | Last data refresh was more than 2 tick intervals ago. | Click the refresh icon on the panel. If persistent, restart the extension host. |
| Panel shows **Waiting for data...** | First data fetch has not completed yet. | Wait 10 seconds for the first broadcast cycle. If it persists, the mock backend may have failed to initialize. |
| Topology graph is empty | No agents are registered in the mock or live backend. | Ensure the topology data provider is configured. In dev mode, the mock backend seeds 4 agents automatically. |
| SLO shows 0% availability | The SLO provider returned a zeroed snapshot. | This usually means the provider has not received any evaluation events. Trigger a policy evaluation or restart. |
| Browser dashboard not loading | Server failed to bind to 127.0.0.1. | Run `Agent OS: Start Server` and check the Output panel for port conflict messages. |

---

## Security Design Decisions

| Decision | Rationale | Risk Level |
|---|---|---|
| `'unsafe-inline'` for `style-src` in CSP | Required for VS Code theme CSS variable injection (`var(--vscode-*)`). Scripts remain nonce-gated. | Low -- style-only; no script injection vector. |
| `retainContextWhenHidden: true` on Topology Detail | Preserves force-simulation state across tab switches (~120 animation frames). | Low -- adds ~2 MB memory when backgrounded. |
| Session token via `Sec-WebSocket-Protocol` subprotocol | Token sent as subprotocol (not URL query string) to avoid proxy/debug logging. 128-bit `crypto.randomBytes`. | Low -- server binds to 127.0.0.1; token never leaves loopback. |
| Rate limiter Map with TTL eviction | Stale entries evicted on each request. Server is loopback-only, so the map holds at most one entry (127.0.0.1). | Negligible -- no memory growth risk. |
| `Math.random()` for burn-rate sparkline jitter | Synthetic demo data only, not used for any security or cryptographic purpose. | None -- replaced by real SRE data when backend connects. |
| `axios` not used; `http` module for server | The governance server uses Node built-in `http`. No external HTTP client dependency. | N/A |

---

## Configuration Reference

All extension settings are documented in the [README](README.md) under the **Extension Settings** section.
Key settings are prefixed with `agent-os.` in VS Code's Settings UI.

For policy file configuration, see the Agent OS documentation on policy schemas:
`packages/agent-os/src/agent_os/policies/schema.py`.
