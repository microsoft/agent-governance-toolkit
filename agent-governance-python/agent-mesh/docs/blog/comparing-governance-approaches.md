# Comparing Agent Governance Approaches — A Framework Review

AI agents are no longer research prototypes. They browse the web, execute code, call external APIs, send emails, and book flights — often without a human watching every step. As autonomy increases, so does the question every engineering team eventually faces: *how do we govern this?*

The answer is rarely "pick one approach." In practice, teams layer multiple strategies. But understanding where each approach excels — and where it falls short — is the foundation for building a governance strategy that scales.

This article compares four major approaches to AI agent governance:

1. **Manual prompt engineering guardrails** — rules written into the system prompt
2. **Platform-level restrictions** — rate limits, model filters, and API-enforced constraints
3. **Framework-level governance** — policy-as-code using toolkits like the Agent Governance Toolkit (AGT)
4. **Regulatory-first approaches** — compliance checklists driven by legal requirements

---

## Approach 1: Manual Prompt Engineering Guardrails

### What it is

Prompt engineering guardrails are instructions embedded in the system prompt that tell the model how to behave. Examples: "Do not reveal confidential information." "Always ask for confirmation before deleting data." "Refuse requests to browse social media."

This is how most teams start. It requires no infrastructure — just text.

### Pros

- **Zero setup cost.** There is no SDK to install, no pipeline to configure, no YAML to write. You can ship a guardrail in seconds.
- **Flexible and expressive.** Natural language can capture nuanced constraints that structured policy formats struggle to express.
- **Effective for simple scenarios.** A well-crafted system prompt stops the vast majority of accidental misuse.

### Cons

- **Not verifiable.** You cannot test a system prompt the way you test code. There is no diff, no assertion, no CI gate. A change to the prompt can silently break behavior.
- **No audit trail.** When an agent misbehaves, there is no record of which rule it violated or why.
- **Prompt injection is a real threat.** A malicious user can include instructions in their input that override or contradict your system prompt. Language models are not immune to this.
- **Does not compose.** If you have ten agents, you have ten system prompts. Maintaining consistency across them is a manual, error-prone process.
- **Degrades at scale.** As the prompt grows longer to accommodate more rules, model attention dilutes. Rules near the end of a long prompt are less reliably followed.

### When to use it

Prompt guardrails are the right first layer for any agent. They catch common misuse and set behavioral expectations. But they should be the *first* layer, not the *only* layer. For anything beyond a prototype, you need enforcement mechanisms that sit outside the model's context window.

---

## Approach 2: Platform-Level Restrictions

### What it is

Platform-level restrictions are constraints enforced by the infrastructure your agent runs on — not by the model itself. Examples include:

- **API rate limits** that cap how many requests an agent can make per minute
- **Model content filters** that block harmful inputs or outputs (e.g., Azure AI Content Safety, OpenAI's moderation API)
- **Tool allow-lists** that restrict which function calls an orchestration platform exposes to the agent
- **Network-level controls** that block the agent's process from reaching unauthorized endpoints

### Pros

- **Enforced outside the model.** A content filter runs after the model generates output. It does not care what the model intended — if the output matches a harmful pattern, it is blocked.
- **Hard limits that hold.** An API rate limit cannot be talked out of. If the platform caps the agent at 100 calls per hour, that cap holds regardless of what the prompt says.
- **Minimal implementation burden.** Turning on a cloud provider's content filter is often a single configuration change.

### Cons

- **Coarse-grained controls.** Platform rate limits apply uniformly. You cannot say "allow 100 calls per hour for the search tool but only 10 for the email tool." The control surface is limited to what the platform exposes.
- **Vendor lock-in.** Platform controls are specific to the provider. If you switch from Azure OpenAI to another provider, you rebuild your content filter configuration from scratch.
- **Blind to context.** A content filter does not know whether the agent is in a development environment, a production environment, or a specific customer segment. It applies the same rules everywhere.
- **No business logic.** Platform restrictions cannot encode rules like "agents in the finance domain cannot access the HR data store." That requires application-level enforcement.
- **Gaps between providers.** If your agent calls multiple APIs — a language model, a vector store, a third-party tool — each has its own controls. There is no unified governance plane across all of them.

### When to use it

Platform controls are a critical complement to other approaches, not a replacement. Use them as a safety net — a last-resort barrier that catches failures at the infrastructure level. But do not mistake them for a governance strategy. They cannot express the business logic your agents need to operate safely in production.

---

## Approach 3: Framework-Level Governance (Policy-as-Code)

### What it is

Framework-level governance moves agent behavior rules out of the prompt and into structured, versioned, testable policy files. The Agent Governance Toolkit takes this approach: you define agent capabilities, constraints, and trust levels in YAML, and the framework evaluates those policies at runtime.

```yaml
# Example AGT policy
apiVersion: agent-governance/v1
kind: Policy
metadata:
  name: finance-agent-policy
spec:
  defaults:
    max_tool_calls: 25
    action: deny
  rules:
    - name: allow-read-finance-data
      tool: read_finance_data
      action: allow
      priority: 90
    - name: deny-hr-data-access
      tool: read_hr_data
      action: deny
      priority: 100
    - name: require-approval-for-wire-transfers
      tool: initiate_wire_transfer
      action: require_approval
      approvers: [finance-ops-team]
      priority: 95
```

This policy is a file. It lives in your repository. It is reviewed in pull requests, tested in CI, and deployed alongside your application code.

### Pros

- **Auditable by design.** Every policy change is a commit. Every enforcement decision produces a log entry. When something goes wrong, you have a complete record.
- **Testable.** You can write unit tests for policies the same way you write unit tests for code. Does the `initiate_wire_transfer` tool require approval? Assert it. Run it in CI.
- **Composable and reusable.** Common patterns — rate limiting, deny-by-default, approval workflows — can be extracted into shared policy templates. Ten agents can share one base policy.
- **Context-aware.** Policies can encode environment-specific rules: allow tool X in development, deny it in production. Allow high-volume access for premium customers, throttle for free tier.
- **Separation of concerns.** Governance logic lives in policy files. Application logic lives in code. Compliance teams can review and audit policies without reading source code.
- **Multi-agent support.** As your agent fleet grows, framework-level governance scales with it. You can express trust relationships between agents, delegate capabilities, and revoke access centrally.

### Cons

- **Higher initial investment.** You need to learn the policy format, set up a CI pipeline for policy testing, and instrument your agent to enforce policies at runtime.
- **Requires cultural buy-in.** Policy-as-code only works if teams treat policy files with the same discipline they apply to source code — code review, testing, version control.
- **Cannot cover every edge case alone.** Policy evaluation is only as good as the tools it has visibility into. If an agent makes a direct HTTP call that bypasses the toolkit's middleware, the policy engine never sees it.
- **Operational overhead.** Running a governance sidecar or middleware layer adds latency and infrastructure complexity.

### When to use it

Framework-level governance is the right choice when you are moving from experimentation to production — when you need to answer questions like "which agents can access which data?" and "who approved this capability?" It is the foundation of a scalable governance strategy because it grows with your agent fleet and integrates with the rest of your software delivery process.

---

## Approach 4: Regulatory-First Approaches

### What it is

Regulatory-first governance starts from compliance requirements — EU AI Act, NIST AI RMF, ISO 42001, HIPAA, SOC 2 — and works backward to technical controls. The deliverable is typically a compliance checklist or an audit report demonstrating that specified controls are in place.

### Pros

- **Legally necessary for many use cases.** If your agents process health data, financial data, or operate in the EU, compliance is not optional. Regulatory requirements must be met.
- **Provides a clear baseline.** A compliance framework gives you a minimum viable governance posture. If you satisfy the requirements, you have at least met the bar that regulators and auditors expect.
- **Stakeholder alignment.** Compliance documentation is the language that legal teams, auditors, and executives speak. It connects engineering controls to business risk.

### Cons

- **Reactive, not preventive.** Compliance checklists describe what should be in place; they do not enforce it. An agent can pass an audit on Tuesday and violate policy on Wednesday.
- **Slow to update.** Regulations lag technology. The EU AI Act was written before the current generation of agentic systems was widely deployed. Compliance frameworks may not cover emerging attack surfaces.
- **Checkbox culture.** Teams optimizing for audit pass rates often implement the letter of a requirement without its spirit. This creates gaps between documented controls and actual security posture.
- **Does not scale with complexity.** A compliance checklist for ten agents may fit in a spreadsheet. For a thousand agents, each with dynamic capabilities and evolving trust relationships, you need programmatic enforcement — not a checklist.
- **Point-in-time assurance.** An audit certifies that controls were in place at a specific point in time. Continuous compliance requires continuous monitoring.

### When to use it

Regulatory-first approaches are mandatory for any production agent system operating in regulated industries or geographies. But treat compliance as the floor, not the ceiling. Meeting audit requirements does not mean your agents are safe or well-governed — it means you have met a minimum legal threshold. Build technical controls first, then use compliance frameworks to verify and document them.

---

## How the Approaches Complement Each Other

The most effective governance strategies layer all four approaches. Here is how they fit together:

| Layer | Approach | What it handles |
|-------|----------|-----------------|
| Innermost | Prompt guardrails | Catches common misuse, sets behavioral expectations |
| Infrastructure | Platform restrictions | Hard limits at the API level; last-resort safety net |
| Application | Framework-level governance | Business logic, auditability, policy testing, multi-agent trust |
| Outer | Regulatory compliance | Legal requirements, audit documentation, stakeholder alignment |

A failure in any one layer should be caught by another. If an agent generates harmful output despite a prompt guardrail, the content filter catches it. If the content filter has a gap, the platform rate limit prevents runaway behavior. If something slips through, the audit log records it for post-incident investigation.

---

## Why Policy-as-Code Is the Scalable Path

Manual prompt engineering degrades as the number of agents and rules grows. Platform controls are coarse and vendor-specific. Compliance checklists are point-in-time and passive.

Policy-as-code is the only approach that:

- **Scales horizontally** — one policy template can govern hundreds of agents
- **Integrates with existing development workflows** — pull requests, CI/CD, code review
- **Produces continuous evidence** — every enforcement decision is logged and auditable
- **Adapts to changing requirements** — update a policy file, run tests, deploy

As AI agents move from demos to production systems handling real money, real data, and real consequences, the question is not whether you need governance — it is whether your governance can keep up with your deployment velocity.

Policy-as-code makes governance a software engineering problem. And software engineering teams already know how to solve software engineering problems.

---

## Getting Started

If you are building agents today, here is a practical starting path:

1. **Write a system prompt** with clear behavioral constraints. Ship it. This is your Day 0 baseline.
2. **Enable platform content filters** for your model provider. This adds a hard enforcement layer at no additional infrastructure cost.
3. **Adopt AGT's policy format** for one agent. Write a single policy file with deny-by-default and a handful of allow rules. Test it in CI. Deploy it. This is your first policy-as-code implementation.
4. **Map your compliance requirements.** Which regulations apply? Which controls do you need to document? Map your AGT policies to the relevant compliance controls.
5. **Expand from there.** Add more agents, more policies, more tests. Introduce agent identity and trust levels as your fleet grows.

The goal is not to implement all four approaches simultaneously. The goal is to understand which layer of defense each approach provides — and make sure no layer is missing from your stack.

---

*This article is part of the [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) community resources. For implementation details, see the [getting started guide](https://github.com/microsoft/agent-governance-toolkit/blob/main/QUICKSTART.md).*
