# 🎧 Contoso Support — Customer Service Governance Demo (.NET)

This example uses a **real Microsoft Agent Framework agent** with native
`Microsoft.Agents.AI` middleware to demonstrate retail support governance.

## What it demonstrates

1. **Policy Enforcement** — large refunds, payment-card requests, and billing changes are denied before execution
2. **Capability Sandboxing** — governed MAF tools allow order/refund workflows and block sensitive account operations
3. **Rogue Agent Detection** — refund-farming behaviour triggers anomaly scoring and quarantine
4. **Audit Trail** — governance events are mirrored into a Merkle-chained tamper-evident log

## Runtime model

- `Program.cs` builds the support agent with `BuildAIAgent(...)` plus native `.Use(...)` middleware
- `policies/support_governance.yaml` uses simple local rule expressions for prompt and tool checks
- Output is deterministic and does not require GitHub Models or Azure OpenAI credentials

## Run it

```bash
dotnet run
```

## Files

- `Program.cs` — scenario walkthrough and support tool definitions
- `policies/support_governance.yaml` — local prompt and tool rules for the demo
- `CustomerServiceGovernance.csproj` — package references for `Microsoft.Agents.AI`, `YamlDotNet`, and shared demo support
