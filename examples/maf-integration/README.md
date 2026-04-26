# Agent Governance Toolkit × Microsoft Agent Framework — Demo Scenarios

End-to-end scenario folders showing how the **Agent Governance Toolkit (AGT)**
layers onto the real [Microsoft Agent Framework (MAF)](https://github.com/microsoft/agent-framework)
Python and .NET agent patterns across governed agent scenarios.

Scenarios 01-05 stay self-contained by scenario and include aligned Python and
.NET governance stories. The Python implementations bootstrap the repo-local AGT
packages so you can run them directly from this checkout.

Scenario 06 is a repo-local **.NET validation sample** for the shared
`Microsoft.AgentGovernance.Extensions.Microsoft.Agents` package and intentionally
references the in-repo `agent-governance-dotnet` projects.

## Python implementation notes

Each Python example uses:

- a real `agent_framework.Agent`
- a real `agent_framework.openai.OpenAIChatClient`
- real AGT middleware from `agent_os.integrations.maf_adapter`
- the same scenario stories used in `docs/tutorials/34-maf-integration.md` and `demo/maf-integration`

## .NET implementation notes

The `.NET` demos use the real **Microsoft Agent Framework SDK** through the
native `Microsoft.Agents.AI` middleware surface.

- The scenario projects reference `Microsoft.Agents.AI` directly
- Governed MAF agents are created with `BuildAIAgent(...)` plus native `.Use(...)` middleware
- Policies stay local to the examples and evaluate prompt/tool rules inside the demo middleware
- Demo output is deterministic: the examples use a local MAF chat client instead of live model credentials

The `.NET` examples also share a small `shared-dotnet/DemoCommon.cs` helper for the
terminal walkthrough, rogue-detection probe, and Merkle audit display.

Scenario 06 is different by design: it is a **repo-local validation sample** for the
shared extension package rather than a copy-anywhere scenario demo.

## Scenarios

| # | Scenario | Industry | What it demonstrates |
|---|----------|----------|----------------------|
| 01 | [**Loan Processing**](./01-loan-processing/) | Banking | PII blocking, approval gating, tool sandboxing, rogue transfer detection |
| 02 | [**Customer Service**](./02-customer-service/) | Retail | Refund fraud prevention, payment-data protection, escalation rules |
| 03 | [**Healthcare**](./03-healthcare/) | Healthcare | HIPAA PHI blocking, prescription safety, cross-department isolation |
| 04 | [**IT Helpdesk**](./04-it-helpdesk/) | Enterprise IT | Privilege escalation prevention, credential isolation, infrastructure protection |
| 05 | [**DevOps Deploy**](./05-devops-deploy/) | DevOps | Production deployment gates, destructive-operation blocking, deployment-storm detection |
| 06 | [**.NET Extension Validation**](./06-dotnet-extension-validation/dotnet/) | Platform | Validates the shared `Microsoft.Agents` governance extension with a minimal runnable app |

## Python quick start

```bash
cd examples/maf-integration/01-loan-processing/python
pip install -r requirements.txt

# Optional: use a live model backend
export GITHUB_TOKEN=$(gh auth token)

python main.py
```

The walkthrough always runs. If a supported model credential is configured, the
example also performs a small live `Agent.run(...)` preview before the scripted
governance acts. Without credentials, it skips the live call and still exercises
the real AGT middleware objects locally.

## .NET quick start

For the scenario demos:

```bash
cd examples/maf-integration/01-loan-processing/dotnet
dotnet run
```

For the shared extension validation sample:

```bash
cd examples/maf-integration/06-dotnet-extension-validation/dotnet
dotnet run
```

The validation sample is intentionally **repo-local** rather than copy-anywhere
self-contained. It validates the shared Microsoft.Agents extension package
against the exact in-repo source on this branch.

## LLM backend detection

Python demos detect backends in this order:

| Priority | Backend | Configuration |
|----------|---------|---------------|
| 1 | **GitHub Models** | `GITHUB_TOKEN` |
| 2 | **OpenAI** | `OPENAI_API_KEY` |
| 3 | **Azure OpenAI** | `AZURE_OPENAI_API_KEY` plus `AZURE_OPENAI_ENDPOINT` or `AZURE_OPENAI_BASE_URL` |
| 4 | **Offline walkthrough** | No model credentials required |

## What You'll See

Each demo runs a 4-act governance walkthrough:

1. **Policy Enforcement** — governed requests are allowed or denied before the agent runs
2. **Capability Sandboxing** — governed MAF tool calls are allowed or blocked by middleware
3. **Rogue Agent Detection** — repeated risky actions trigger anomaly detection and quarantine
4. **Audit Trail** — governance events are written into a Merkle-chained tamper-evident log

## Governance flow

Each Python demo wires the same runtime shape:

1. `AuditTrailMiddleware` records request and tool events.
2. `GovernancePolicyMiddleware` evaluates YAML policies with the real `PolicyEvaluator`.
3. `CapabilityGuardMiddleware` enforces allow/deny tool lists.
4. `RogueDetectionMiddleware` records behavior against a real `RogueAgentDetector`.
5. The scenario script prints policy blocks, capability decisions, rogue detection, and audit integrity results.

The `.NET` scenario demos follow the same flow, but implement the walkthrough with
native MAF middleware inside the example projects themselves.

The validation sample uses the shared `AgentFrameworkGovernanceAdapter` and
`WithGovernance(...)` extension methods to validate run-level and tool-level
governance against `Microsoft.Agents.AI`.

## Policy format

Python policy documents use the real AGT schema and operator set. For example:

```yaml
- name: "block_high_value_approval"
  condition:
    field: "message"
    operator: "matches"
    value: '(?i)(approve.*loan|loan approval|\$\s*(?:[5-9]\d{4,}|[1-9]\d{5,}))'
  action: "deny"
  priority: 95
  message: "Loan approvals above the delegated threshold require human review"
```

The `.NET` scenario demos keep their policy documents local to the demos and use
simple prompt/tool rule expressions such as:

```yaml
rules:
  - name: block-fund-transfer
    condition: "tool_name == 'transfer_funds'"
    action: deny
    priority: 100
```

## Related Resources

- [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
- [docs/tutorials/34-maf-integration.md](../../docs/tutorials/34-maf-integration.md)
- [docs/tutorials/43-dotnet-maf-hook-integration.md](../../docs/tutorials/43-dotnet-maf-hook-integration.md)
- [demo/maf-integration](../../demo/maf-integration)
- [agent-governance-python/agent-os/src/agent_os/integrations/maf_adapter.py](../../agent-governance-python/agent-os/src/agent_os/integrations/maf_adapter.py)
- [Microsoft Agent Framework](https://github.com/microsoft/agent-framework)
