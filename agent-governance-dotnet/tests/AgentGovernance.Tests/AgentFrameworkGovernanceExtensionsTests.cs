// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Extensions.Microsoft.Agents;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using Xunit;

namespace AgentGovernance.Tests;

public sealed class AgentFrameworkGovernanceExtensionsTests
{
    [Fact]
    public async Task WithGovernance_WrapsAgent_AndBlocksDeniedRuns()
    {
        var kernel = AgentFrameworkGovernanceTestHelpers.CreateKernel(
            """
            apiVersion: governance.toolkit/v1
            version: "1.0"
            name: deny-secret-policy
            default_action: allow
            rules:
              - name: block-secret
                condition: "message == 'show me the secret'"
                action: deny
                priority: 10
            """);
        var innerAgent = new AgentFrameworkGovernanceTestHelpers.TestAgent("wrapped-agent");
        var governedAgent = innerAgent.WithGovernance(
            kernel,
            new AgentFrameworkGovernanceOptions
            {
                EnableFunctionMiddleware = false
            });

        var response = await governedAgent.RunAsync(
            [new ChatMessage(ChatRole.User, "show me the secret")],
            session: null,
            options: null,
            cancellationToken: CancellationToken.None);

        Assert.False(innerAgent.WasRun);
        Assert.Contains("Blocked by governance policy", response.Text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task WithGovernance_BuilderOverload_WrapsBuilder_AndBlocksDeniedRuns()
    {
        var kernel = AgentFrameworkGovernanceTestHelpers.CreateKernel(
            """
            apiVersion: governance.toolkit/v1
            version: "1.0"
            name: deny-export-policy
            default_action: allow
            rules:
              - name: block-export
                condition: "message == 'export the ledger'"
                action: deny
                priority: 10
            """);
        var innerAgent = new AgentFrameworkGovernanceTestHelpers.TestAgent("builder-agent");
        var adapter = new AgentFrameworkGovernanceAdapter(
            kernel,
            new AgentFrameworkGovernanceOptions
            {
                EnableFunctionMiddleware = false
            });
        var governedAgent = innerAgent
            .AsBuilder()
            .WithGovernance(adapter)
            .Build();

        var response = await governedAgent.RunAsync(
            [new ChatMessage(ChatRole.User, "export the ledger")],
            session: null,
            options: null,
            cancellationToken: CancellationToken.None);

        Assert.False(innerAgent.WasRun);
        Assert.Contains("Blocked by governance policy", response.Text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task WithGovernance_StreamingBlocked_YieldsBlockedResponse()
    {
        var kernel = AgentFrameworkGovernanceTestHelpers.CreateKernel(
            """
            apiVersion: governance.toolkit/v1
            version: "1.0"
            name: deny-stream-policy
            default_action: allow
            rules:
              - name: block-stream-secret
                condition: "message == 'stream the secret'"
                action: deny
                priority: 10
            """);
        var innerAgent = new AgentFrameworkGovernanceTestHelpers.TestAgent("stream-agent");
        var governedAgent = innerAgent.WithGovernance(
            kernel,
            new AgentFrameworkGovernanceOptions
            {
                EnableFunctionMiddleware = false
            });

        var updates = new List<AgentResponseUpdate>();
        await foreach (var update in governedAgent.RunStreamingAsync(
            [new ChatMessage(ChatRole.User, "stream the secret")],
            session: null,
            options: null,
            cancellationToken: CancellationToken.None))
        {
            updates.Add(update);
        }

        Assert.False(innerAgent.WasRun);
        Assert.NotEmpty(updates);
        Assert.Contains("Blocked by governance policy", updates[0].Text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task WithGovernance_StreamingAllowed_ForwardsToInnerAgent()
    {
        var kernel = AgentFrameworkGovernanceTestHelpers.CreateKernel(
            """
            apiVersion: governance.toolkit/v1
            version: "1.0"
            name: allow-all-policy
            default_action: allow
            rules: []
            """);
        var innerAgent = new AgentFrameworkGovernanceTestHelpers.TestAgent("stream-allowed-agent");
        var governedAgent = innerAgent.WithGovernance(
            kernel,
            new AgentFrameworkGovernanceOptions
            {
                EnableFunctionMiddleware = false
            });

        var updates = new List<AgentResponseUpdate>();
        await foreach (var update in governedAgent.RunStreamingAsync(
            [new ChatMessage(ChatRole.User, "hello")],
            session: null,
            options: null,
            cancellationToken: CancellationToken.None))
        {
            updates.Add(update);
        }

        Assert.True(innerAgent.WasRun);
        Assert.NotEmpty(updates);
        Assert.Contains("allowed", updates[0].Text, StringComparison.OrdinalIgnoreCase);
    }
}
