// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Mcp;
using AgentGovernance.Telemetry;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace AgentGovernance.Extensions;

/// <summary>
/// Extension methods that integrate Agent Governance MCP security into the
/// official ModelContextProtocol C# SDK's server pipeline.
/// </summary>
/// <remarks>
/// <para>
/// This bridges the governance components (<see cref="McpGateway"/>,
/// <see cref="McpSecurityScanner"/>, <see cref="McpResponseScanner"/>,
/// <see cref="McpSessionAuthenticator"/>, <see cref="McpMessageSigner"/>,
/// <see cref="CredentialRedactor"/>) into the official SDK's filter system.
/// </para>
/// <para>
/// <b>Dependency:</b> Requires the <c>ModelContextProtocol</c> NuGet package (≥ 1.2.0).
/// </para>
/// <para><b>Usage:</b></para>
/// <code>
/// builder.Services
///     .AddMcpServer(options =&gt; { options.ServerInfo = new() { Name = "my-server" }; })
///     .WithGovernance(opts =&gt;
///     {
///         opts.DeniedTools = McpGovernanceDefaults.DeniedTools.ToList();
///         opts.SensitiveTools = McpGovernanceDefaults.SensitiveTools.ToList();
///         opts.EnableResponseScanning = true;
///     })
///     .WithToolsFromAssembly();
/// </code>
/// </remarks>
public static class McpSdkGovernanceExtensions
{
    /// <summary>
    /// Adds MCP governance security to the official MCP server pipeline.
    /// Registers all governance services in DI and hooks into the SDK's filter system
    /// so that every <c>tools/call</c> request passes through the 5-stage
    /// <see cref="McpGateway"/> pipeline before reaching the tool handler.
    /// </summary>
    /// <param name="builder">
    /// The <see cref="IMcpServerBuilder"/> returned by <c>AddMcpServer()</c>.
    /// </param>
    /// <param name="configure">
    /// Optional callback to configure <see cref="McpGovernanceOptions"/>.
    /// When <c>null</c>, default options are used.
    /// </param>
    /// <returns>The same builder for fluent chaining.</returns>
    public static IMcpServerBuilder WithGovernance(
        this IMcpServerBuilder builder,
        Action<McpGovernanceOptions>? configure = null)
    {
        var options = new McpGovernanceOptions();
        configure?.Invoke(options);

        // Register all governance services in DI (gateway, scanner, etc.)
        builder.Services.AddMcpGovernance(options);

        // Wire governance filters into McpServerOptions via PostConfigure.
        // PostConfigure runs after the DI container is fully built,
        // giving us access to the resolved governance singletons.
        builder.Services.AddSingleton<IPostConfigureOptions<McpServerOptions>>(sp =>
        {
            var gateway = sp.GetRequiredService<McpGateway>();
            var scanner = sp.GetService<McpSecurityScanner>();
            var responseScanner = sp.GetService<McpResponseScanner>();
            var logger = sp.GetService<ILogger<McpGateway>>();

            return new PostConfigureOptions<McpServerOptions>(
                Options.DefaultName,
                serverOptions =>
                {
                    EnsureFilterContainers(serverOptions);
                    AddCallToolGovernanceFilter(
                        serverOptions, gateway, responseScanner, options, logger);
                });
        });

        return builder;
    }

    /// <summary>
    /// Ensures all filter container objects are initialized on the server options.
    /// </summary>
    private static void EnsureFilterContainers(McpServerOptions serverOptions)
    {
        serverOptions.Filters ??= new McpServerFilters();
        serverOptions.Filters.Request ??= new McpRequestFilters();
        serverOptions.Filters.Message ??= new McpMessageFilters();
    }

    /// <summary>
    /// Adds the main CallTool governance filter. This is the primary enforcement
    /// point: every <c>tools/call</c> request passes through the <see cref="McpGateway"/>
    /// 5-stage pipeline (deny-list → allow-list → sanitization → policy → rate-limit).
    /// </summary>
    private static void AddCallToolGovernanceFilter(
        McpServerOptions serverOptions,
        McpGateway gateway,
        McpResponseScanner? responseScanner,
        McpGovernanceOptions governanceOptions,
        ILogger? logger)
    {
        var agentId = governanceOptions.AgentId;

        serverOptions.Filters!.Request!.CallToolFilters ??=
            new List<McpRequestFilter<CallToolRequestParams, CallToolResult>>();

        serverOptions.Filters.Request.CallToolFilters.Add(next =>
            async (context, cancellationToken) =>
            {
                var toolName = context.Params?.Name ?? "unknown";

                // Extract parameters from the SDK request
                var parameters = ExtractParameters(context.Params);

                // ── Stage 1: Pre-execution governance check (fail-closed) ──
                bool allowed;
                string reason;
                try
                {
                    (allowed, reason) = gateway.InterceptToolCall(agentId, toolName, parameters);
                }
                catch (Exception ex)
                {
                    // Fail-closed: any governance exception → deny
                    logger?.LogError(
                        ex,
                        "MCP governance threw during tool interception for {ToolName} ({AgentId}); denying",
                        toolName, agentId);
                    throw new McpException("Governance error: tool call denied (fail-closed).");
                }

                if (!allowed)
                {
                    logger?.LogWarning(
                        "MCP governance denied tool call: {ToolName} for {AgentId} — {Reason}",
                        toolName, agentId, reason);
                    throw new McpException($"Governance denied: {reason}");
                }

                logger?.LogInformation(
                    "MCP governance allowed tool call: {ToolName} for {AgentId}",
                    toolName, agentId);

                // ── Stage 2: Execute the tool ──
                var result = await next(context, cancellationToken);

                // ── Stage 3: Post-execution — scan and redact response ──
                if (result is not null && result.Content is not null)
                {
                    result = ScanAndRedactResponse(
                        result, toolName, responseScanner, governanceOptions, logger);
                }

                return result ?? new CallToolResult { IsError = true };
            });
    }

    /// <summary>
    /// Extracts a <see cref="Dictionary{TKey,TValue}"/> of parameters from the
    /// SDK's <see cref="CallToolRequestParams.Arguments"/>.
    /// </summary>
    private static Dictionary<string, object> ExtractParameters(
        CallToolRequestParams? requestParams)
    {
        var parameters = new Dictionary<string, object>();
        if (requestParams?.Arguments is null)
            return parameters;

        foreach (var kvp in requestParams.Arguments)
        {
            parameters[kvp.Key] = kvp.Value.ToString() ?? string.Empty;
        }

        return parameters;
    }

    /// <summary>
    /// Scans tool response content for threats and redacts credentials.
    /// Operates on <see cref="TextContentBlock"/> items within the result.
    /// </summary>
    private static CallToolResult ScanAndRedactResponse(
        CallToolResult result,
        string toolName,
        McpResponseScanner? responseScanner,
        McpGovernanceOptions options,
        ILogger? logger)
    {
        if (result.Content is not IList<ContentBlock> contentList)
            return result;

        for (var i = 0; i < contentList.Count; i++)
        {
            if (contentList[i] is not TextContentBlock textBlock)
                continue;

            var text = textBlock.Text;
            if (string.IsNullOrEmpty(text))
                continue;

            // Response scanning (§5/§12)
            if (responseScanner is not null)
            {
                var scanResult = responseScanner.ScanResponse(text, toolName);
                if (!scanResult.IsSafe)
                {
                    logger?.LogWarning(
                        "MCP governance detected threats in response from {ToolName}: {Threats}",
                        toolName,
                        string.Join("; ", scanResult.Threats.Select(t => t.Description)));

                    // Replace with sanitized content
                    var (sanitized, _) = responseScanner.SanitizeResponse(text, toolName);
                    contentList[i] = new TextContentBlock { Text = sanitized };
                }
            }

            // Credential redaction (§10)
            if (options.EnableCredentialRedaction)
            {
                var currentText = (contentList[i] as TextContentBlock)?.Text ?? text;
                if (CredentialRedactor.ContainsCredentials(currentText))
                {
                    logger?.LogWarning(
                        "MCP governance redacting credentials in response from {ToolName}",
                        toolName);
                    contentList[i] = new TextContentBlock
                    {
                        Text = CredentialRedactor.Redact(currentText)
                    };
                }
            }
        }

        return result;
    }
}
