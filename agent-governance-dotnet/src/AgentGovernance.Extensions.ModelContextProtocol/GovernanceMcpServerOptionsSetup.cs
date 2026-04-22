// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Mcp;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Microsoft.Extensions.Options;

namespace AgentGovernance.Extensions.ModelContextProtocol;

internal sealed class GovernanceMcpServerOptionsSetup : IPostConfigureOptions<McpServerOptions>
{
    private readonly McpGovernanceOptions _options;
    private readonly McpGovernanceRuntime _runtime;
    private readonly McpSecurityScanner _scanner;

    public GovernanceMcpServerOptionsSetup(
        IOptions<McpGovernanceOptions> options,
        McpGovernanceRuntime runtime,
        McpSecurityScanner scanner)
    {
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        _scanner = scanner ?? throw new ArgumentNullException(nameof(scanner));
    }

    public void PostConfigure(string? name, McpServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (_options.GovernFallbackHandlers)
        {
            options.Filters.Request.CallToolFilters.Add(next => async (request, cancellationToken) =>
            {
                if (!_runtime.IsAllowed(request, out var reason))
                {
                    return _runtime.CreateDeniedResult(reason);
                }

                var result = await next(request, cancellationToken).ConfigureAwait(false);
                return _runtime.Sanitize(result);
            });
        }

        if (options.ToolCollection is null || options.ToolCollection.Count == 0)
        {
            return;
        }

        var governedTools = new McpServerPrimitiveCollection<McpServerTool>();
        foreach (var tool in options.ToolCollection)
        {
            ScanTool(tool.ProtocolTool);
            governedTools.TryAdd(new GovernedMcpServerTool(tool, _runtime));
        }

        options.ToolCollection = governedTools;
    }

    private void ScanTool(Tool tool)
    {
        if (!_options.ScanToolsOnStartup)
        {
            return;
        }

        var definition = new McpToolDefinition
        {
            Name = tool.Name,
            Description = tool.Description ?? string.Empty,
            InputSchema = tool.InputSchema.GetRawText(),
            ServerName = _options.ServerName
        };

        _scanner.RegisterTool(definition);
        var scan = _scanner.Scan(definition);
        if (scan.Safe || !_options.FailOnUnsafeTools)
        {
            return;
        }

        var findings = string.Join("; ", scan.Threats.Select(threat => $"{threat.Type}: {threat.Description}"));
        throw new InvalidOperationException($"Unsafe MCP tool definition detected for '{tool.Name}': {findings}");
    }
}
