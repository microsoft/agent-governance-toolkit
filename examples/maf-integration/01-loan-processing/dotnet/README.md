# 🏦 Contoso Bank — Loan Processing Governance Demo (.NET)

This example shows a **real Microsoft Agent Framework agent** with native
`Microsoft.Agents.AI` middleware in the demo project itself.

## What it demonstrates

1. **Policy Enforcement** — governed loan prompts are denied before the agent runs
2. **Capability Sandboxing** — governed MAF tool calls block tax-record access, large approvals, and fund transfers
3. **Rogue Agent Detection** — repeated transfer attempts trigger anomaly scoring
4. **Audit Trail** — governance events are mirrored into a Merkle-chained compliance log

## Runtime model

- `Program.cs` builds a real MAF agent with `BuildAIAgent(...)` plus native `.Use(...)` middleware
- `policies/loan_governance.yaml` uses simple local rule expressions for prompt and tool checks
- Output is deterministic: the demo uses a local MAF chat client instead of external model credentials

## Run it

```bash
dotnet run
```

## Files

- `Program.cs` — scenario walkthrough and domain tools
- `policies/loan_governance.yaml` — local policy rules for the walkthrough prompts and tools
- `LoanGovernance.csproj` — package references for `Microsoft.Agents.AI` and `YamlDotNet`

## Example policy rule

```yaml
- name: block-fund-transfer
  condition: "tool_name == 'transfer_funds'"
  action: deny
  priority: 100
```
