# .NET records agent example

This .NET SDK example wraps a medical records loop with `RunAsync`, `RunModelAsync`, and `RunToolAsync`. It uses deterministic annotators, an OPA policy dispatcher, and an approval resolver.

## Threat or governance need

Medical records workflows need input screening, record access checks, PHI redaction, and approval for sensitive records or export actions. The example keeps those controls in ACS policy while the host owns model and tool execution.

## Run

```sh
dotnet run --project examples/records_agent/app/RecordsAgentDemo.csproj
```

`opa` must be available on `PATH`.

## Expected verdicts

The runner prints allowed record fetch, denied prompt injection, denied unauthorized record, escalated sensitive record, escalated export, and post-model PHI redaction.

## Where to look

`manifest.yaml` binds all guarded points. `policy/medical_records_assistant_guardrails.rego` contains the rules. `app/Program.cs` shows .NET typed orchestration, redaction handling, and approval resolution.
