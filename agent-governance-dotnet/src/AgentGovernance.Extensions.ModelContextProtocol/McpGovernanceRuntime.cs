// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Security.Claims;
using System.Text.Json;
using AgentGovernance.Mcp;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Microsoft.Extensions.Options;

namespace AgentGovernance.Extensions.ModelContextProtocol;

internal sealed class McpGovernanceRuntime
{
    private readonly GovernanceKernel _kernel;
    private readonly McpResponseSanitizer _sanitizer;
    private readonly McpGovernanceOptions _options;

    public McpGovernanceRuntime(
        GovernanceKernel kernel,
        McpResponseSanitizer sanitizer,
        IOptions<McpGovernanceOptions> options)
    {
        _kernel = kernel ?? throw new ArgumentNullException(nameof(kernel));
        _sanitizer = sanitizer ?? throw new ArgumentNullException(nameof(sanitizer));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
    }

    public string ResolveAgentId(MessageContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return TryGetAgentId(context.User)
            ?? TryGetAgentId(context.Items)
            ?? _options.DefaultAgentId;
    }

    public bool IsAllowed(RequestContext<CallToolRequestParams> request, out string? reason)
    {
        ArgumentNullException.ThrowIfNull(request);

        var evaluation = _kernel.EvaluateToolCall(
            ResolveAgentId(request),
            request.Params.Name,
            ConvertArguments(request.Params.Arguments));

        reason = evaluation.Reason;
        return evaluation.Allowed;
    }

    public CallToolResult CreateDeniedResult(string? reason)
    {
        return new CallToolResult
        {
            IsError = true,
            Content =
            [
                new TextContentBlock
                {
                    Text = string.IsNullOrWhiteSpace(reason)
                        ? "Tool call blocked by governance policy."
                        : $"Tool call blocked by governance policy: {reason}"
                }
            ]
        };
    }

    public CallToolResult Sanitize(CallToolResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        if (!_options.SanitizeResponses || result.Content.Count == 0)
        {
            return result;
        }

        var modified = false;
        var sanitizedBlocks = new List<ContentBlock>(result.Content.Count);

        foreach (var block in result.Content)
        {
            if (block is TextContentBlock textBlock && !string.IsNullOrWhiteSpace(textBlock.Text))
            {
                var sanitized = _sanitizer.ScanText(textBlock.Text);
                if (sanitized.Modified)
                {
                    modified = true;
                    sanitizedBlocks.Add(new TextContentBlock
                    {
                        Text = sanitized.Sanitized,
                        Annotations = textBlock.Annotations,
                        Meta = textBlock.Meta
                    });
                    continue;
                }
            }

            sanitizedBlocks.Add(block);
        }

        if (!modified)
        {
            return result;
        }

        return new CallToolResult
        {
            Content = sanitizedBlocks,
            StructuredContent = result.StructuredContent,
            IsError = result.IsError
        };
    }

    private static string? TryGetAgentId(ClaimsPrincipal? principal)
    {
        if (principal is null)
        {
            return null;
        }

        return principal.FindFirst("agent_id")?.Value
            ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? principal.Identity?.Name;
    }

    private static string? TryGetAgentId(IDictionary<string, object?> items)
    {
        if (items.TryGetValue("agent_id", out var agentId) && agentId is string agentIdValue && !string.IsNullOrWhiteSpace(agentIdValue))
        {
            return agentIdValue;
        }

        return null;
    }

    private static Dictionary<string, object>? ConvertArguments(IDictionary<string, JsonElement>? arguments)
    {
        if (arguments is null || arguments.Count == 0)
        {
            return null;
        }

        var converted = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var (key, value) in arguments)
        {
            converted[key] = ConvertElement(value);
        }

        return converted;
    }

    private static object ConvertElement(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.Object => element.EnumerateObject()
                .ToDictionary(property => property.Name, property => ConvertElement(property.Value), StringComparer.Ordinal),
            JsonValueKind.Array => element.EnumerateArray().Select(ConvertElement).ToList(),
            JsonValueKind.String => element.GetString() ?? string.Empty,
            JsonValueKind.Number => element.TryGetInt64(out var longValue)
                ? longValue
                : element.TryGetDecimal(out var decimalValue)
                    ? decimalValue
                    : element.GetDouble(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => null!,
            _ => element.GetRawText()
        };
    }
}
