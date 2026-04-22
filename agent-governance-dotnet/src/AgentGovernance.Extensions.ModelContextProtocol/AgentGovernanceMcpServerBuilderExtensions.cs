// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Mcp;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Server;

namespace AgentGovernance.Extensions.ModelContextProtocol;

/// <summary>
/// Extension methods for adding Agent Governance to Model Context Protocol servers.
/// </summary>
public static class AgentGovernanceMcpServerBuilderExtensions
{
    /// <summary>
    /// Adds Microsoft.AgentGovernance enforcement to an MCP server builder.
    /// </summary>
    /// <param name="builder">The MCP server builder to extend.</param>
    /// <param name="configure">Optional configuration for MCP governance behavior.</param>
    /// <returns>The same builder instance for chaining.</returns>
    public static IMcpServerBuilder WithGovernance(
        this IMcpServerBuilder builder,
        Action<McpGovernanceOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.AddOptions<McpGovernanceOptions>();
        if (configure is not null)
        {
            builder.Services.Configure(configure);
        }

        builder.Services.TryAddSingleton(static serviceProvider =>
            new GovernanceKernel(serviceProvider.GetRequiredService<IOptions<McpGovernanceOptions>>().Value.ToGovernanceOptions()));
        builder.Services.TryAddSingleton<McpResponseSanitizer>();
        builder.Services.TryAddSingleton<McpSecurityScanner>();
        builder.Services.TryAddSingleton<McpGovernanceRuntime>();
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IPostConfigureOptions<McpServerOptions>, GovernanceMcpServerOptionsSetup>());

        return builder;
    }
}
