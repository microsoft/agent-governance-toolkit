# 🏥 MedAssist — HIPAA Patient Data Governance Demo (.NET)

This example uses a **real Microsoft Agent Framework agent** with native
`Microsoft.Agents.AI` middleware to demonstrate HIPAA-focused governance controls.

## What it demonstrates

1. **Policy Enforcement** — PHI requests are denied before the clinical assistant runs
2. **Capability Sandboxing** — governed MAF tools allow symptom and guideline lookups while blocking patient record access
3. **Rogue Agent Detection** — bulk patient-record access attempts trigger anomaly scoring and quarantine
4. **Audit Trail** — governance events are mirrored into a Merkle-chained HIPAA-friendly audit log

## Runtime model

- `Program.cs` builds the agent with `BuildAIAgent(...)` plus native `.Use(...)` middleware
- `policies/healthcare_governance.yaml` uses simple local rule expressions for prompt and tool checks
- Output is deterministic and requires no live LLM credentials

## Run it

```bash
dotnet run
```
