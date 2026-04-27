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

        if (TryResolveAgentId(context, out var agentId, out var reason))
        {
            return agentId;
        }

        throw new InvalidOperationException(reason);
    }

    public bool IsAllowed(RequestContext<CallToolRequestParams> request, out string? reason)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryResolveAgentId(request, out var agentId, out reason))
        {
            return false;
        }

        var evaluation = _kernel.EvaluateToolCall(
            agentId,
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

    private bool TryResolveAgentId(MessageContext context, out string agentId, out string? reason)
    {
        var resolved = TryGetAuthenticatedAgentId(context.User);
        if (!string.IsNullOrWhiteSpace(resolved))
        {
            agentId = resolved;
            reason = null;
            return true;
        }

        if (_options.RequireAuthenticatedAgentId)
        {
            agentId = string.Empty;
            reason = "Authenticated agent identity is required for MCP governance. Configure AgentIdResolver to map authenticated principals or set RequireAuthenticatedAgentId = false to allow DefaultAgentId fallback.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(_options.DefaultAgentId))
        {
            agentId = string.Empty;
            reason = "MCP governance could not resolve an authenticated agent identity and DefaultAgentId is not configured.";
            return false;
        }

        agentId = _options.DefaultAgentId;
        reason = null;
        return true;
    }

    private string? TryGetAuthenticatedAgentId(ClaimsPrincipal? principal)
    {
        if (principal?.Identity?.IsAuthenticated != true)
        {
            return null;
        }

        var resolved = _options.AgentIdResolver?.Invoke(principal);
        if (!string.IsNullOrWhiteSpace(resolved))
        {
            return resolved;
        }

        return principal.FindFirst("agent_id")?.Value
            ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? principal.Identity?.Name;
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
            if (TryConvertElement(value, out var convertedValue))
            {
                converted[key] = convertedValue;
            }
        }

        return converted.Count == 0 ? null : converted;
    }

    private static bool TryConvertElement(JsonElement element, out object value)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                var objectValue = new Dictionary<string, object>(StringComparer.Ordinal);
                foreach (var property in element.EnumerateObject())
                {
                    if (TryConvertElement(property.Value, out var propertyValue))
                    {
                        objectValue[property.Name] = propertyValue;
                    }
                }

                value = objectValue;
                return true;

            case JsonValueKind.Array:
                var arrayValue = new List<object>();
                foreach (var item in element.EnumerateArray())
                {
                    if (TryConvertElement(item, out var itemValue))
                    {
                        arrayValue.Add(itemValue);
                    }
                }

                value = arrayValue;
                return true;

            case JsonValueKind.String:
                value = element.GetString() ?? string.Empty;
                return true;

            case JsonValueKind.Number:
                value = element.TryGetInt64(out var longValue)
                    ? longValue
                    : element.TryGetDecimal(out var decimalValue)
                        ? decimalValue
                        : element.GetDouble();
                return true;

            case JsonValueKind.True:
                value = true;
                return true;

            case JsonValueKind.False:
                value = false;
                return true;

            case JsonValueKind.Null:
            case JsonValueKind.Undefined:
                value = string.Empty;
                return false;

            default:
                value = element.GetRawText();
                return true;
        }
    }
}
