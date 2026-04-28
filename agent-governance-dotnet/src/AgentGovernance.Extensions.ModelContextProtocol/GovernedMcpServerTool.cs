// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace AgentGovernance.Extensions.ModelContextProtocol;

internal sealed class GovernedMcpServerTool : McpServerTool
{
    private readonly McpServerTool _inner;
    private readonly McpGovernanceRuntime _runtime;

    public GovernedMcpServerTool(McpServerTool inner, McpGovernanceRuntime runtime)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
    }

    public override Tool ProtocolTool => _inner.ProtocolTool;

    public override IReadOnlyList<object> Metadata => _inner.Metadata;

    public override async ValueTask<CallToolResult> InvokeAsync(
        RequestContext<CallToolRequestParams> request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!_runtime.IsAllowed(request, out var reason))
        {
            return _runtime.CreateDeniedResult(reason);
        }

        var result = await _inner.InvokeAsync(request, cancellationToken).ConfigureAwait(false);
        return _runtime.Sanitize(result);
    }
}
