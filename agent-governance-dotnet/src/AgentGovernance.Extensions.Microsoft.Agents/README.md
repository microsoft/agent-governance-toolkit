# Microsoft.AgentGovernance.Extensions.Microsoft.Agents

Public Preview companion package for `Microsoft.AgentGovernance` that makes it easy to hook the real [microsoft/agent-framework](https://github.com/microsoft/agent-framework) .NET pipeline exposed through `Microsoft.Agents.AI` into AGT governance.

## Install

```bash
dotnet add package Microsoft.AgentGovernance
dotnet add package Microsoft.AgentGovernance.Extensions.Microsoft.Agents
```

## What this package does

This package does **not** create a Microsoft Agent Framework agent for you. It assumes you already have a real `Microsoft.Agents.AI` `AIAgent` or `AIAgentBuilder`, then attaches AGT governance middleware around it.

The integration surface is:

- `AgentFrameworkGovernanceAdapter`
- `AgentFrameworkGovernanceOptions`
- `AIAgentBuilder.WithGovernance(...)`
- `AIAgent.WithGovernance(...)`

## OSS expectations

- wraps an existing MAF agent or builder; it does not replace the MAF runtime
- translates MAF messages and function invocations into AGT policy/audit inputs
- keeps limitations explicit: function middleware only works when the underlying MAF pipeline supports function invocation middleware
- stays intentionally thin so MAF applications can share one governance hook instead of copying custom translation code

## Integration options

This package supports two equally valid ways to wire AGT into a real MAF agent:

1. **Hook option** - call `WithGovernance(...)` on an existing `AIAgent` or `AIAgentBuilder`
2. **Governance middleware option** - create an `AgentFrameworkGovernanceAdapter` explicitly and reuse it anywhere you need the run/function middleware bridge

## Hook option

```csharp
using AgentGovernance;
using AgentGovernance.Extensions.Microsoft.Agents;
using Microsoft.Agents.AI;

var kernel = new GovernanceKernel(new GovernanceOptions
{
    PolicyPaths = new() { "policies/loan-governance.yaml" },
    EnablePromptInjectionDetection = true,
});

AIAgent agent = GetYourExistingMafAgent();

var governedAgent = agent.WithGovernance(
    kernel,
    new AgentFrameworkGovernanceOptions
    {
        DefaultAgentId = "did:agentmesh:loan-processor",
        EnableFunctionMiddleware = true,
    });
```

## Governance middleware option

Construct the adapter explicitly when you want a reusable governance middleware object:

```csharp
var adapter = new AgentFrameworkGovernanceAdapter(
    kernel,
    new AgentFrameworkGovernanceOptions
    {
        DefaultAgentId = "did:agentmesh:loan-processor",
        EnableFunctionMiddleware = true,
    });

var governedBuilder = agent.AsBuilder().WithGovernance(adapter);
var governedAgent = governedBuilder.Build();
```

This makes the MAF-to-AGT middleware bridge explicit while still using the same `WithGovernance(...)` extension point to attach it.

## Hook points

- **Run middleware** via `AgentFrameworkGovernanceAdapter.RunAsync(...)`
  - evaluates message input against AGT policy
  - emits AGT audit events
  - returns a blocked `AgentResponse` when denied

- **Function middleware** via `AgentFrameworkGovernanceAdapter.InvokeFunctionAsync(...)`
  - maps MAF tool calls into `GovernanceKernel.EvaluateToolCall(...)`
  - sets `FunctionInvocationContext.Terminate = true` when denied
  - returns a blocked tool result payload

## Important constraint

`EnableFunctionMiddleware = true` only works for MAF agents backed by a function-calling pipeline that supports function invocation middleware (for example agents using a `FunctionInvokingChatClient`-compatible stack).

If you only need message/run governance, set:

```csharp
EnableFunctionMiddleware = false
```

That keeps the adapter on the run middleware path only.
