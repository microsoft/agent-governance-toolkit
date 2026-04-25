# Microsoft.Agents governance extension validation (.NET)

This minimal app validates the shared AGT `Microsoft.Agents` extension against a runnable `Microsoft.Agents.AI` sample.

It is a **repo-local validation sample**, not a copy-anywhere standalone demo: the project file references the in-repo `agent-governance-dotnet` projects so it can validate the exact adapter code on this branch.

It demonstrates:

1. the **hook option** via `agent.WithGovernance(...)`
2. the **governance middleware option** via `AgentFrameworkGovernanceAdapter`
3. blocked run behavior and blocked tool behavior using the same shared extension package

## Why this example exists

The larger `examples/maf-integration/*/dotnet` samples still contain scenario-specific governance code. This app is smaller on purpose: it proves the reusable extension package works without pulling in the extra scenario scaffolding.

## Files

- `Program.cs` — runnable validation app
- `policies/maf_validation.yaml` — minimal allow/deny rules
- `MicrosoftAgentsExtensionValidation.csproj` — local project that references the in-repo AGT projects

## Run

```bash
cd examples/maf-integration/06-dotnet-extension-validation/dotnet
dotnet run
```

Run it from this repository checkout so the `ProjectReference` paths resolve correctly.

## Expected output

You should see:

- an **allowed** run request passing through the wrapped MAF agent
- a **blocked** run request returning `Blocked by governance policy: ...`
- an **allowed** tool invocation returning the simulated tool result
- a **blocked** tool invocation returning `Blocked by governance policy: ...`

## Notes

- This sample uses a small in-process `AIAgent` implementation so the extension can be exercised without external model configuration.
- The run path executes through a real wrapped `Microsoft.Agents.AI` agent.
- The function example demonstrates the real middleware callback shape used by the extension; a full `FunctionInvokingChatClient` pipeline is intentionally out of scope for this minimal validation app.
