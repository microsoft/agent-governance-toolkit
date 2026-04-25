// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using AgentGovernance;
using AgentGovernance.Extensions.Microsoft.Agents;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

var policyPath = Path.Combine(AppContext.BaseDirectory, "policies", "maf_validation.yaml");
var kernel = new GovernanceKernel(new GovernanceOptions
{
    PolicyPaths = new() { policyPath },
    EnablePromptInjectionDetection = true,
});

Console.WriteLine("=== Microsoft.Agents governance extension validation ===");
Console.WriteLine("Validates the shared AGT bridge against a runnable Microsoft.Agents.AI sample.");

await RunHookDemoAsync(kernel);
await RunExplicitAdapterDemoAsync(kernel);
await RunFunctionDemoAsync(kernel);

static async Task RunHookDemoAsync(GovernanceKernel kernel)
{
    Console.WriteLine();
    Console.WriteLine("[1] Hook option: agent.WithGovernance(...)");

    var innerAgent = new DemoAgent("hook-agent");
    var governedAgent = innerAgent.WithGovernance(
        kernel,
        new AgentFrameworkGovernanceOptions
        {
            DefaultAgentId = "did:agentmesh:hook-agent",
            EnableFunctionMiddleware = false,
        });

    await ShowRunAsync(governedAgent, "summarize approved account activity");
    await ShowRunAsync(governedAgent, "transfer funds");
}

static async Task RunExplicitAdapterDemoAsync(GovernanceKernel kernel)
{
    Console.WriteLine();
    Console.WriteLine("[2] Governance middleware option: explicit adapter + builder");

    var innerAgent = new DemoAgent("builder-agent");
    var adapter = new AgentFrameworkGovernanceAdapter(
        kernel,
        new AgentFrameworkGovernanceOptions
        {
            DefaultAgentId = "did:agentmesh:builder-agent",
            EnableFunctionMiddleware = false,
        });

    var governedAgent = innerAgent
        .AsBuilder()
        .WithGovernance(adapter)
        .Build();

    await ShowRunAsync(governedAgent, "summarize approved account activity");
    await ShowRunAsync(governedAgent, "transfer funds");
}

static async Task RunFunctionDemoAsync(GovernanceKernel kernel)
{
    Console.WriteLine();
    Console.WriteLine("[3] Function middleware callback shape");

    var adapter = new AgentFrameworkGovernanceAdapter(
        kernel,
        new AgentFrameworkGovernanceOptions
        {
            DefaultAgentId = "did:agentmesh:tool-agent",
            EnableFunctionMiddleware = true,
        });

    await ShowFunctionAsync(adapter, "lookup_rate", "4.5% apr");
    await ShowFunctionAsync(adapter, "deploy_prod", "deployment started");
}

static async Task ShowRunAsync(AIAgent agent, string input)
{
    Console.WriteLine($"  Request: {input}");

    var response = await agent.RunAsync(
        [new ChatMessage(ChatRole.User, input)],
        session: null,
        options: null,
        cancellationToken: CancellationToken.None);

    var blocked = response.Text.Contains("Blocked by governance policy", StringComparison.OrdinalIgnoreCase);
    Console.WriteLine(blocked
        ? $"  BLOCKED: {response.Text}"
        : $"  ALLOWED: {response.Text}");
}

static async Task ShowFunctionAsync(
    AgentFrameworkGovernanceAdapter adapter,
    string functionName,
    object allowedResult)
{
    var context = new FunctionInvocationContext
    {
        Function = AIFunctionFactory.Create(
            (Action)(() => { }),
            functionName,
            $"Validation function for {functionName}",
            serializerOptions: null),
        Arguments = new AIFunctionArguments
        {
            ["environment"] = functionName == "deploy_prod" ? "prod" : "test",
        }
    };

    var result = await adapter.InvokeFunctionAsync(
        new DemoAgent("tool-agent"),
        context,
        (_, _) => ValueTask.FromResult<object?>(allowedResult),
        CancellationToken.None);

    Console.WriteLine($"  Tool: {functionName}()");
    Console.WriteLine(context.Terminate
        ? $"  BLOCKED: {result}"
        : $"  ALLOWED: {result}");
}

sealed class DemoAgent : AIAgent
{
    public DemoAgent(string name)
    {
        Name = name;
    }

    public override string Name { get; }

    protected override string IdCore => $"did:demo:{Name}";

    protected override Task<AgentResponse> RunCoreAsync(
        IEnumerable<ChatMessage> messages,
        AgentSession? session,
        AgentRunOptions? options,
        CancellationToken cancellationToken)
    {
        var lastMessage = messages.LastOrDefault()?.Text ?? "no input";
        return Task.FromResult(new AgentResponse(
            new ChatMessage(ChatRole.Assistant, $"Inner MAF agent handled: {lastMessage}")));
    }

    protected override async IAsyncEnumerable<AgentResponseUpdate> RunCoreStreamingAsync(
        IEnumerable<ChatMessage> messages,
        AgentSession? session,
        AgentRunOptions? options,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var lastMessage = messages.LastOrDefault()?.Text ?? "no input";
        yield return new AgentResponseUpdate(ChatRole.Assistant, $"Inner MAF agent handled: {lastMessage}");
        await Task.CompletedTask;
    }

    protected override ValueTask<AgentSession> CreateSessionCoreAsync(CancellationToken cancellationToken)
        => throw new NotSupportedException();

    protected override ValueTask<JsonElement> SerializeSessionCoreAsync(
        AgentSession session,
        JsonSerializerOptions? options,
        CancellationToken cancellationToken)
        => throw new NotSupportedException();

    protected override ValueTask<AgentSession> DeserializeSessionCoreAsync(
        JsonElement sessionState,
        JsonSerializerOptions? options,
        CancellationToken cancellationToken)
        => throw new NotSupportedException();
}
