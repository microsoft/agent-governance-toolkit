# Medical records assistant ACS .NET demo

This folder contains a runnable C# console app in `app/` that loads `manifest.yaml`, evaluates `policy/medical_records_assistant_guardrails.rego` through OPA, supplies host-side classifier annotations, and enforces input/model/tool/output decisions with the ACS .NET SDK.

Run from the repository root:

```bash
export PATH="$HOME/.dotnet:$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
dotnet run --project examples/records_agent/app/RecordsAgentDemo.csproj
```

The demo prints allowed, denied, escalated-with-approval, and redacted flows for the simulated `fetch_record` and `export_data` tools.

This is an advanced custom-dispatcher example. It supplies its own annotator dispatcher because the classifier annotations are produced by local deterministic host heuristics rather than a reachable endpoint, so it does not use the bundled zero-config annotator default. A host whose manifest uses Rego policies and either declares no annotators or points them at configured endpoints integrates in roughly three lines with `FromPath`. See [Zero-config construction](../../README.md#zero-config-construction).
