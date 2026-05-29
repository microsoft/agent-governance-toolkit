# ADR 0028: AGT Studio, a single unified UI for governance

- Status: proposed
- Date: 2026-05-29

## Context

AGT currently ships seven separate UI surfaces that each cover a slice of the
product:

- Six Streamlit dashboards (governance, trust, SRE, hypervisor, SCAK,
  observability) that mostly use simulated data and are rarely consumed in
  production.
- IDE extensions (Cursor, Copilot, JetBrains) whose UI panels duplicate parts
  of the dashboards.
- A Chrome extension targeted at browsing safety on GitHub, Jira, and AWS.
- A static `console.html` pitch asset.

This creates three problems:

1. **No front door for evaluators or customers.** Sales and demo conversations
   require diagrams and verbal explanation because there is no single place to
   see what AGT does. The CLI plus YAML workflow does not land.
2. **The policy lifecycle has no UI.** AGT ships 70+ example policies and 14
   templates and has a full replay/test engine via `agt test`, but provides no
   visual way to author, lint, simulate, diff, or version policies. Policy is
   the project's core IP.
3. **Surfaces drift.** Each extension and dashboard exposes overlapping
   concepts (active policies, audit, decisions) with inconsistent shapes, no
   shared contract, and no canonical experience.

A separate review considered building a full operator/SOC console with
approvals, quarantine, and runtime control. That option was rejected: the
write-path requires SSO, RBAC, multi-tenancy, audit non-repudiation, and 24/7
support that AGT cannot sustain, and Azure Sentinel, Defender, and Foundry
already own that space.

## Decision

Build **AGT Studio** as the single first-class UI for AGT.

- Launched standalone with `agt ui`. A local sidecar (`agt serve`) exposes the
  engine over HTTP/WebSocket. The browser opens to the SPA.
- Same SPA packaged as a VS Code and Cursor webview. One code base, two
  shells. The shells inject a transport (HTTP for standalone, postMessage for
  webview) so the SPA is host-agnostic.
- Policy-first scope. Authoring, testing, simulation, and visibility for AGT
  policies. Modelled on the Azure Policy experience in the Azure Portal:
  browse definitions, see active assignments, author, test, assign.

### In scope

| Capability | Phase |
|---|---|
| Browse all policies (70+ examples, 14 templates, plus Copilot, Claude, and Antigravity CLI policy configs) | MVP |
| Author policies with schema-aware editing and inline lint | MVP |
| Test and validate policies (wraps `agent_compliance.policy_test.replay`) | MVP |
| What-if simulator (action + identity + context to decision and rule) | MVP |
| Regression view (rule change to fixture pass/fail diff) | MVP |
| Version both engine and policies; test against either | MVP |
| Live decisions feed (from `agentmesh.dashboard.api.DashboardAPI`) | V1 |
| Shadow-agent and credential lifecycle signals | V1 |
| Trust network, scores, and decay views | V1 |
| Audit log viewer with chain-integrity badge and evidence export | V1 |

### Explicitly out of scope

- Operator/SOC console capabilities: approvals queue, quarantine, hot-reload
  to production, write-path runtime control.
- SSO, SAML, OIDC, RBAC, and multi-tenancy. Studio is an authoring and
  visibility tool. Production deployments wrap the engine API behind their
  own auth.
- Replacement for runtime enforcement hooks in the IDE extensions or the
  Chrome extension. Only the UI surfaces collapse into Studio. The
  interception logic stays where it is.
- SRE, FinOps, incident management, deployment tooling. These belong in
  Grafana, Sentinel, Datadog, PagerDuty, ServiceNow, Argo, and similar.

## Triage of existing dashboards

| # | Dashboard | Current purpose | Disposition |
|---|---|---|---|
| 1 | `examples/demos/governance-dashboard` | Fleet, shadow agents, lifecycle funnel, allow/deny feed, trust heatmap (simulated) | Partial port to Studio: policy feed, shadow agents. Drop fleet table and lifecycle funnel. |
| 2 | `agent-mesh/examples/06-trust-score-dashboard` | Trust graph, scores, credentials, protocol traffic, compliance | Mostly port to Studio: trust graph, credentials, compliance. Protocol traffic moves to a Grafana template. |
| 3 | `agent-sre/examples/dashboard` | SLOs, cost, chaos, incidents, progressive delivery | Replace with Grafana templates. |
| 4 | `agent-hypervisor/examples/dashboard` | Sessions, rings, sagas, liability, events | Archive. Niche runtime supervision. |
| 5 | `agent-os/modules/scak/dashboard.py` | SCAK memory and telemetry | Archive with module. |
| 6 | `agent-os/modules/observability/dashboards.py` | Pre-built Grafana JSON templates | Keep and expand. This is the embed-first integration story. |

Net effect: six dashboards collapse to one UI plus one Grafana template pack.
`console.html` is deleted.

## Alternatives considered

1. **Full operator/SOC console.** Rejected. Write-path risk, auth surface,
   and ongoing support cost are out of scale for AGT, and Sentinel, Defender,
   and Foundry are better homes for that telemetry.
2. **Embed-only via Grafana, Sentinel, and Foundry plugins.** Useful and
   continues alongside Studio (item 6 above), but does not solve the policy
   authoring and demo gaps that motivated this decision.
3. **Status quo.** Six surfaces stay scattered, the policy lifecycle stays
   CLI-only, demos keep failing to land.

## Consequences

- **One canonical surface for AGT.** New features land in Studio, not in a
  new dashboard. The contributor question "where does this UI go" has one
  answer.
- **Forces an engine API contract.** Studio needs a stable HTTP/WebSocket
  surface from the engine. This contract benefits every SDK, not just the
  UI, and unblocks a future conformance test suite for cross-SDK parity.
- **Demos improve immediately.** Sales, evaluator, and customer conversations
  gain a visual surface that does not require CLI familiarity.
- **Ongoing cost.** A real product surface to maintain: accessibility,
  browser matrix, dependency hygiene, release cadence, security review of a
  new API. Owners and release cadence must be named before code lands.
- **Deprecation work.** Six dashboards must be deprecated in sequence with
  clear migration notes and at least one release of overlap.
- **Marketplace is a separate, later decision.** Studio is the prerequisite.
  A policy marketplace (curated AGT packs, enterprise distribution,
  "awesome-policy" community hub) will be proposed as a follow-up ADR once
  Studio is shipping.

## References

- Policy replay engine: `agent-governance-python/agent-compliance/src/agent_compliance/policy_test.py`.
- Dashboard backend: `agent-governance-python/agent-mesh/src/agentmesh/dashboard/api.py`.
- Existing IDE extension UI surfaces under `agent-governance-python/agent-os/extensions/`.
- Existing Streamlit dashboards listed in the triage table above.
- Related ADR-0015 (pluggable external policy backends) and ADR-0022
  (compliance framework auto-mapping).
