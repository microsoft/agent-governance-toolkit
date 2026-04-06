// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Mcp;
using AgentGovernance.Mcp.Abstractions;
using AgentGovernance.Telemetry;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AgentGovernance.Extensions;

/// <summary>
/// Extension methods for registering MCP governance services in an
/// <see cref="IServiceCollection"/>. Works with ASP.NET Core, Worker Services,
/// Azure Functions, and any host that uses the Generic Host.
/// </summary>
public static class McpServiceCollectionExtensions
{
    /// <summary>
    /// Registers MCP governance services in the DI container.
    /// </summary>
    /// <param name="services">The service collection to register into.</param>
    /// <param name="mcpOptions">
    /// Options for MCP-specific governance. When <c>null</c>, default options are used.
    /// </param>
    /// <returns>The same <see cref="IServiceCollection"/> for chaining.</returns>
    public static IServiceCollection AddMcpGovernance(
        this IServiceCollection services,
        McpGovernanceOptions? mcpOptions = null)
    {
        var options = mcpOptions ?? new McpGovernanceOptions();

        // Register options and core singletons (thread-safe, meant to be shared)
        services.AddSingleton(options);
        services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        services.TryAddSingleton<IMcpSessionStore, InMemoryMcpSessionStore>();
        services.TryAddSingleton<IMcpNonceStore, InMemoryMcpNonceStore>();
        services.TryAddSingleton<IMcpRateLimitStore, InMemoryMcpRateLimitStore>();
        services.TryAddSingleton<IMcpAuditSink, InMemoryMcpAuditSink>();
        services.AddSingleton<GovernanceMetrics>();
        services.AddSingleton<GovernanceKernel>();
        services.AddSingleton(sp =>
        {
            var kernel = sp.GetRequiredService<GovernanceKernel>();
            var metrics = sp.GetRequiredService<GovernanceMetrics>();
            var timeProvider = sp.GetRequiredService<TimeProvider>();
            var gateway = new McpGateway(
                kernel,
                deniedTools: options.DeniedTools,
                allowedTools: options.AllowedTools,
                sensitiveTools: options.SensitiveTools,
                approvalCallback: options.ApprovalCallback,
                enableCredentialRedaction: options.EnableCredentialRedaction,
                enableBuiltinSanitization: options.EnableBuiltinSanitization,
                requireHumanApproval: options.RequireHumanApproval,
                auditSink: sp.GetRequiredService<IMcpAuditSink>(),
                timeProvider: timeProvider);

            // Wire metrics and rate limiter if configured
            gateway.Metrics = metrics;
            if (options.MaxToolCallsPerAgent > 0)
            {
                gateway.RateLimiter = new McpSlidingRateLimiter(
                    sp.GetRequiredService<IMcpRateLimitStore>(),
                    timeProvider)
                {
                    MaxCallsPerWindow = options.MaxToolCallsPerAgent,
                    WindowSize = options.RateLimitWindow
                };
            }

            return gateway;
        });
        services.AddSingleton<McpSecurityScanner>(sp =>
        {
            var scanner = new McpSecurityScanner();
            scanner.Metrics = sp.GetRequiredService<GovernanceMetrics>();
            return scanner;
        });
        services.AddSingleton(sp => new McpToolMapper(options.CustomToolMappings));
        services.AddSingleton(sp => new McpMessageHandler(
            sp.GetRequiredService<McpGateway>(),
            sp.GetRequiredService<McpToolMapper>(),
            options.AgentId));

        if (options.EnableResponseScanning)
            services.AddSingleton<McpResponseScanner>();

        if (options.SessionTtl.HasValue)
            services.AddSingleton(sp => new McpSessionAuthenticator(
                sp.GetRequiredService<IMcpSessionStore>(),
                sp.GetRequiredService<TimeProvider>())
            {
                SessionTtl = options.SessionTtl.Value,
                MaxSessionsPerAgent = options.MaxSessionsPerAgent
            });

        if (options.MessageSigningKey is not null)
            services.AddSingleton(sp => new McpMessageSigner(
                options.MessageSigningKey,
                sp.GetRequiredService<IMcpNonceStore>(),
                sp.GetRequiredService<TimeProvider>())
            {
                ReplayWindow = options.MessageReplayWindow
            });

        // Register middleware as transient for IMiddleware pattern
        services.AddTransient<McpGovernanceMiddleware>();

        return services;
    }
}
