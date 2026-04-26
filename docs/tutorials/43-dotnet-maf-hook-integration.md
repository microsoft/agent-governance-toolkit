# Tutorial 43 — .NET MAF Hook Integration

> **Level:** Intermediate · **Prerequisites:** Tutorial 01 (Policy Engine), .NET 8.0+, an existing `Microsoft.Agents.AI` agent

This tutorial shows how to add AGT governance to a real .NET agent built with the [Microsoft Agent Framework](https://github.com/microsoft/agent-framework). The goal is not to replace MAF. The goal is to hook AGT policy, audit, and tool-call controls into MAF's existing run and function middleware pipeline.

## Why this exists

MAF already gives you the runtime:

- agent construction
- run and function middleware hooks
- tool orchestration
- session and response types

AGT adds the governance layer:

- policy evaluation over messages and tool calls
- audit events and metrics
- consistent deny behavior
- translation from MAF-native types into AGT policy inputs

The .NET extension package exists so every MAF application does **not** need to re-implement that translation by hand.

## Install the packages

```bash
dotnet add package Microsoft.AgentGovernance
dotnet add package Microsoft.AgentGovernance.Extensions.Microsoft.Agents
```

## Step 1 — Start from an existing MAF agent

This package assumes you already have a real `AIAgent` from `Microsoft.Agents.AI`.

**Before governance**, your app usually just runs the agent directly:

```csharp
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

AIAgent agent = GetYourExistingMafAgent();

AgentResponse response = await agent.RunAsync(
[
    new ChatMessage(ChatRole.User, "transfer funds")
]);
```

At this point, every app that wants governance has to manually:

1. extract message content
2. map tool calls into AGT inputs
3. call `GovernanceKernel`
4. decide how to block
5. emit audit and metrics consistently

## Step 2 — Add a real AGT policy

Create `policies/maf.yaml`:

```yaml
apiVersion: governance.toolkit/v1
version: "1.0"
name: maf-governance-policy
default_action: allow
rules:
  - name: block-transfers
    condition: "message == 'transfer funds'"
    action: deny
    priority: 100

  - name: block-prod-deploy
    condition: "tool_name == 'deploy_prod'"
    action: deny
    priority: 100
```

## Step 3 — Choose your integration shape

This package supports two integration styles:

- **Hook option** for the shortest path: call `WithGovernance(...)` directly on your existing `AIAgent`
- **Governance middleware option** when you want the reusable adapter object to be explicit in your composition root

Both end up attaching the same AGT run and function middleware to the real MAF pipeline.

## Step 4 — Add the AGT hook

**After governance**, you keep the same MAF agent but wrap it with the extension package:

```csharp
using AgentGovernance;
using AgentGovernance.Extensions.Microsoft.Agents;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

var kernel = new GovernanceKernel(new GovernanceOptions
{
    PolicyPaths = new() { "policies/maf.yaml" },
    EnablePromptInjectionDetection = true,
});

AIAgent agent = GetYourExistingMafAgent();

var governedAgent = agent.WithGovernance(
    kernel,
    new AgentFrameworkGovernanceOptions
    {
        DefaultAgentId = "did:agentmesh:payments-agent",
        EnableFunctionMiddleware = true,
    });

AgentResponse response = await governedAgent.RunAsync(
[
    new ChatMessage(ChatRole.User, "transfer funds")
]);
```

That one call adds the governance hook without replacing the MAF runtime.

## Step 5 — Use the explicit governance middleware option

If you want the reusable governance middleware object to be explicit, construct the adapter first:

```csharp
var adapter = new AgentFrameworkGovernanceAdapter(
    kernel,
    new AgentFrameworkGovernanceOptions
    {
        DefaultAgentId = "did:agentmesh:payments-agent",
        EnableFunctionMiddleware = true,
    });

var governedAgent = agent
    .AsBuilder()
    .WithGovernance(adapter)
    .Build();
```

Use this shape when multiple builders or agents in the same process should share the same governance adapter configuration.

## What the hooks do

### Before run

```text
User message
  -> MAF RunAsync(...)
    -> AGT before-run hook
       - map ChatMessage to AGT policy context
       - evaluate policy
       - emit AGT audit and metrics
       - if denied, return blocked AgentResponse
    -> inner MAF agent runs
```

### Before tool execution

```text
Tool call inside MAF
  -> AGT before-function hook
     - map function name + arguments to EvaluateToolCall(...)
     - if denied, set FunctionInvocationContext.Terminate = true
     - return blocked tool result payload
  -> actual tool executes
```

This is the value of the adapter package: MAF still owns orchestration, but AGT now has reusable interception points before the run and before tool execution.

## Step 6 — Know when to disable function middleware

`EnableFunctionMiddleware = true` only works when the underlying MAF stack supports function invocation middleware.

If your agent only needs run/message governance, or if it is not backed by a function-invocation-capable pipeline, disable function middleware:

```csharp
var governedAgent = agent.WithGovernance(
    kernel,
    new AgentFrameworkGovernanceOptions
    {
        DefaultAgentId = "did:agentmesh:reader-agent",
        EnableFunctionMiddleware = false,
    });
```

That keeps the integration on the run hook only.

## What this package does not do

- It does **not** create or configure a MAF agent for you.
- It does **not** replace MAF middleware with an AGT-specific runtime.
- It does **not** promise function middleware support on every MAF pipeline.

It is intentionally a thin bridge between `Microsoft.Agents.AI` and AGT governance primitives.

## Next steps

- [Tutorial 19 — .NET package](19-dotnet-sdk.md)
- [Tutorial 28 — Build Custom Integration](28-build-custom-integration.md)
- [Package page — .NET SDK](../packages/dotnet-sdk.md)
- [Deployment — Azure Foundry Agent Service](../deployment/azure-foundry-agent-service.md)
