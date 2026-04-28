# 🚀 DeployBot — CI/CD Pipeline Safety Governance Demo (.NET)

This example uses a **real Microsoft Agent Framework agent** with native
`Microsoft.Agents.AI` middleware to demonstrate governed DevOps automation.

## What it demonstrates

1. **Policy Enforcement** — production deploy, secret access, and destructive database prompts are denied before the agent runs
2. **Capability Sandboxing** — governed MAF tools allow safe CI/staging operations and block production-only controls
3. **Rogue Agent Detection** — deployment storms trigger anomaly scoring and quarantine
4. **Audit Trail** — governance events are mirrored into a Merkle-chained compliance log

## Runtime model

- `Program.cs` builds the DevOps agent with `BuildAIAgent(...)` plus native `.Use(...)` middleware
- `policies/devops_governance.yaml` uses simple local rule expressions for prompt and tool checks
- Output is deterministic and requires no live LLM credentials

## Run it

```bash
dotnet run
```
