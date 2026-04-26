// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Agents.AI;

namespace AgentGovernance.Extensions.Microsoft.Agents;

/// <summary>
/// Builder helpers for attaching AGT governance to Microsoft Agent Framework agents.
/// </summary>
public static class AgentFrameworkGovernanceExtensions
{
    /// <summary>
    /// Adds AGT governance middleware to an existing MAF builder.
    /// </summary>
    public static AIAgentBuilder WithGovernance(
        this AIAgentBuilder builder,
        AgentFrameworkGovernanceAdapter adapter)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(adapter);

        var governedBuilder = builder.Use(runFunc: adapter.RunAsync, runStreamingFunc: null);

        return adapter.Options.EnableFunctionMiddleware
            ? governedBuilder.Use(adapter.InvokeFunctionAsync)
            : governedBuilder;
    }

    /// <summary>
    /// Wraps an existing MAF agent with AGT governance middleware.
    /// </summary>
    public static AIAgent WithGovernance(
        this AIAgent agent,
        AgentFrameworkGovernanceAdapter adapter)
    {
        ArgumentNullException.ThrowIfNull(agent);
        ArgumentNullException.ThrowIfNull(adapter);

        return agent
            .AsBuilder()
            .WithGovernance(adapter)
            .Build();
    }

    /// <summary>
    /// Wraps an existing MAF agent with AGT governance middleware backed by a governance kernel.
    /// </summary>
    public static AIAgent WithGovernance(
        this AIAgent agent,
        GovernanceKernel kernel,
        AgentFrameworkGovernanceOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(agent);
        ArgumentNullException.ThrowIfNull(kernel);

        return agent.WithGovernance(new AgentFrameworkGovernanceAdapter(kernel, options));
    }
}
