# Agent Governance Toolkit × Microsoft Agent Framework — Demo Scenarios

End-to-end samples showing how the **Agent Governance Toolkit (AGT)** works with the
[Microsoft Agent Framework (MAF)](https://github.com/microsoft/agent-framework) in
five governed agent scenarios.

## Scenarios

| # | Scenario | Industry | What it demonstrates |
|---|----------|----------|----------------------|
| 01 | [**Loan Processing**](./01-loan-processing/) | Banking | PII blocking, governed loan approvals, transfer abuse detection |
| 02 | [**Customer Service**](./02-customer-service/) | Retail | Refund fraud prevention, payment PII protection, escalation rules |
| 03 | [**Healthcare**](./03-healthcare/) | Healthcare | HIPAA PHI blocking, prescription safety, bulk record access detection |
| 04 | [**IT Helpdesk**](./04-it-helpdesk/) | Enterprise IT | Privilege escalation prevention, credential access blocking, infrastructure protection |
| 05 | [**DevOps Deploy**](./05-devops-deploy/) | DevOps | Production deployment gates, destructive operation blocking, deployment storm detection |

Each scenario includes both **Python** and **.NET** implementations with aligned
governance stories.

## .NET implementation notes

The `.NET` demos now use the real **Microsoft Agent Framework SDK** through the
native `Microsoft.Agents.AI` middleware surface.

- The scenario projects reference `Microsoft.Agents.AI` directly
- Governed MAF agents are created with `BuildAIAgent(...)` plus native `.Use(...)` middleware
- Policies stay local to the examples and evaluate prompt/tool rules inside the demo middleware
- Demo output is deterministic: the examples use a local MAF chat client instead of live model credentials

The `.NET` examples also share a small `shared-dotnet/DemoCommon.cs` helper for the
terminal walkthrough, rogue-detection probe, and Merkle audit display.

## Quick Start

### Python

```bash
cd 01-loan-processing/python
pip install -r requirements.txt
python main.py
```

### .NET

```bash
cd 01-loan-processing/dotnet
dotnet run
```

## What You'll See

Each demo runs a 4-act governance walkthrough:

1. **Policy Enforcement** — governed requests are allowed or denied before the agent runs
2. **Capability Sandboxing** — governed MAF tool calls are allowed or blocked by local middleware
3. **Rogue Agent Detection** — repeated risky actions trigger anomaly detection and quarantine
4. **Audit Trail** — governance events are written into a Merkle-chained tamper-evident log

## Customization

Edit the YAML policy files to change governance behavior. The `.NET` examples use
simple local rule expressions:

```yaml
rules:
  - name: block-fund-transfer
    condition: "tool_name == 'transfer_funds'"
    action: deny
    priority: 100
```

## Related Resources

- [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
- [Microsoft Agent Framework](https://github.com/microsoft/agent-framework)
