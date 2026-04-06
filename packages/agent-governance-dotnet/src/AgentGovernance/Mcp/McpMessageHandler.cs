// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace AgentGovernance.Mcp;

/// <summary>
/// JSON-RPC message handler for the Model Context Protocol.
/// Routes incoming MCP messages to the appropriate handler based on their method type
/// and enforces governance checks through the <see cref="McpGateway"/> and
/// <see cref="McpToolMapper"/>.
/// <para>
/// Supported methods: <c>tools/list</c>, <c>tools/call</c>, <c>resources/list</c>,
/// <c>resources/read</c>, <c>prompts/list</c>, <c>prompts/get</c>.
/// </para>
/// </summary>
/// <remarks>
/// Ported from the Python <c>MCPAdapter</c> in <c>agent_control_plane/mcp_adapter.py</c>.
/// </remarks>
public sealed class McpMessageHandler
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false
    };

    private readonly McpGateway _gateway;
    private readonly McpToolMapper _toolMapper;
    private readonly string _agentId;
    private readonly Dictionary<string, Dictionary<string, object>> _registeredTools = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Dictionary<string, object>> _registeredResources = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Optional delegate invoked when a tool call or resource read is blocked by governance.
    /// Parameters: (toolName, arguments, blockReason).
    /// </summary>
    public Action<string, Dictionary<string, object>, string>? OnBlock { get; init; }

    /// <summary>
    /// Optional logger for recording message routing decisions.
    /// When <c>null</c>, no logging occurs — the handler operates silently.
    /// </summary>
    public ILogger<McpMessageHandler>? Logger { get; set; }

    /// <summary>
    /// Initializes a new <see cref="McpMessageHandler"/>.
    /// </summary>
    /// <param name="gateway">The MCP governance gateway for policy enforcement.</param>
    /// <param name="toolMapper">The tool-to-action-type mapper.</param>
    /// <param name="agentId">The DID of the agent using this handler.</param>
    public McpMessageHandler(McpGateway gateway, McpToolMapper toolMapper, string agentId)
    {
        ArgumentNullException.ThrowIfNull(gateway);
        ArgumentNullException.ThrowIfNull(toolMapper);
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);

        _gateway = gateway;
        _toolMapper = toolMapper;
        _agentId = agentId;
    }

    /// <summary>
    /// Registers a tool that this handler can list and invoke.
    /// </summary>
    /// <param name="toolName">Name of the tool.</param>
    /// <param name="toolInfo">Tool metadata (description, inputSchema, etc.).</param>
    public void RegisterTool(string toolName, Dictionary<string, object> toolInfo)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(toolName);
        ArgumentNullException.ThrowIfNull(toolInfo);
        _registeredTools[toolName] = toolInfo;
    }

    /// <summary>
    /// Registers a resource that this handler can list and read.
    /// </summary>
    /// <param name="uriPattern">The resource URI pattern.</param>
    /// <param name="resourceInfo">Resource metadata.</param>
    public void RegisterResource(string uriPattern, Dictionary<string, object> resourceInfo)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(uriPattern);
        ArgumentNullException.ThrowIfNull(resourceInfo);
        _registeredResources[uriPattern] = resourceInfo;
    }

    /// <summary>
    /// Handles an incoming MCP JSON-RPC message and returns a JSON-RPC response.
    /// </summary>
    /// <param name="message">
    /// A dictionary representing a JSON-RPC 2.0 request with keys:
    /// <c>jsonrpc</c>, <c>method</c>, <c>params</c>, <c>id</c>.
    /// </param>
    /// <returns>A JSON-RPC 2.0 response dictionary.</returns>
    public Dictionary<string, object?> HandleMessage(Dictionary<string, object?> message)
    {
        ArgumentNullException.ThrowIfNull(message);

        var id = message.TryGetValue("id", out var idObj) ? idObj : null;
        var method = message.TryGetValue("method", out var methodObj) ? methodObj?.ToString() : null;
        var msgParams = ExtractParams(message);

        if (string.IsNullOrWhiteSpace(method))
        {
            return JsonRpcError(id, -32600, "Invalid Request: missing 'method'");
        }

        var messageType = McpMessageTypeExtensions.FromMethod(method);
        if (messageType is null)
        {
            Logger?.LogWarning("MCP unknown method: {Method}", method);
            return JsonRpcError(id, -32601, $"Method not found: '{method}'");
        }

        try
        {
            Logger?.LogDebug("MCP message routed: {Method}", method);
            var result = messageType.Value switch
            {
                McpMessageType.ToolsList => HandleToolsList(),
                McpMessageType.ToolsCall => HandleToolsCall(msgParams),
                McpMessageType.ResourcesList => HandleResourcesList(),
                McpMessageType.ResourcesRead => HandleResourcesRead(msgParams),
                McpMessageType.PromptsList => HandlePromptsList(),
                McpMessageType.PromptsGet => HandlePromptsGet(msgParams),
                _ => throw new NotSupportedException($"Unhandled message type: {messageType}")
            };

            return JsonRpcSuccess(id, result);
        }
        catch (UnauthorizedAccessException ex)
        {
            Logger?.LogWarning(ex, "MCP message denied by governance");
            return JsonRpcError(id, -32003, "Access denied by governance policy.");
        }
        catch (Exception ex)
        {
            Logger?.LogError(ex, "MCP message handling failed");
            return JsonRpcError(id, -32603, "Internal error.");
        }
    }

    // ── Method handlers ──────────────────────────────────────────────────

    private Dictionary<string, object> HandleToolsList()
    {
        var allowedTools = new List<Dictionary<string, object>>();

        foreach (var (toolName, toolInfo) in _registeredTools)
        {
            var actionType = _toolMapper.MapTool(toolName);
            if (actionType is not null)
            {
                // Check if the agent has permission via the gateway.
                var (allowed, _) = _gateway.InterceptToolCall(_agentId, toolName, new Dictionary<string, object>());
                if (allowed)
                {
                    allowedTools.Add(toolInfo);
                }
            }
        }

        return new Dictionary<string, object> { ["tools"] = allowedTools };
    }

    private Dictionary<string, object> HandleToolsCall(Dictionary<string, object> msgParams)
    {
        var toolName = msgParams.TryGetValue("name", out var n) ? n?.ToString() ?? string.Empty : string.Empty;
        var arguments = msgParams.TryGetValue("arguments", out var a) && a is Dictionary<string, object> args
            ? args
            : new Dictionary<string, object>();

        if (string.IsNullOrWhiteSpace(toolName))
        {
            throw new ArgumentException("Missing 'name' in tools/call params");
        }

        // Map tool to ActionType — unknown tools denied by default.
        var actionType = _toolMapper.MapTool(toolName);
        if (actionType is null)
        {
            throw new UnauthorizedAccessException(
                $"Unknown tool '{toolName}' — cannot classify action type; denied by default.");
        }

        // Run through the gateway's 5-stage pipeline.
        var (allowed, reason) = _gateway.InterceptToolCall(_agentId, toolName, arguments);
        if (!allowed)
        {
            OnBlock?.Invoke(toolName, arguments, reason);
            throw new UnauthorizedAccessException(
                $"Tool call '{toolName}' blocked: {reason}");
        }

        return new Dictionary<string, object>
        {
            ["content"] = new List<Dictionary<string, object>>
            {
                new()
                {
                    ["type"] = "text",
                    ["text"] = JsonSerializer.Serialize(new
                    {
                        tool = toolName,
                        action_type = actionType.ToString(),
                        status = "allowed",
                        arguments
                    }, JsonOptions)
                }
            }
        };
    }

    private Dictionary<string, object> HandleResourcesList()
    {
        var allowedResources = new List<Dictionary<string, object>>();

        foreach (var (uri, resourceInfo) in _registeredResources)
        {
            var actionType = McpToolMapper.MapResource(uri);
            var (allowed, _) = _gateway.InterceptToolCall(_agentId, $"resource:{uri}", new Dictionary<string, object>());
            if (allowed)
            {
                allowedResources.Add(resourceInfo);
            }
        }

        return new Dictionary<string, object> { ["resources"] = allowedResources };
    }

    private Dictionary<string, object> HandleResourcesRead(Dictionary<string, object> msgParams)
    {
        var uri = msgParams.TryGetValue("uri", out var u) ? u?.ToString() ?? string.Empty : string.Empty;

        if (string.IsNullOrWhiteSpace(uri))
        {
            throw new ArgumentException("Missing 'uri' in resources/read params");
        }

        var actionType = McpToolMapper.MapResource(uri);
        var (allowed, reason) = _gateway.InterceptToolCall(
            _agentId,
            $"resource:{uri}",
            new Dictionary<string, object> { ["uri"] = uri, ["action_type"] = actionType.ToString() });

        if (!allowed)
        {
            OnBlock?.Invoke(uri, new Dictionary<string, object> { ["uri"] = uri }, reason);
            throw new UnauthorizedAccessException(
                $"Resource read '{uri}' blocked: {reason}");
        }

        return new Dictionary<string, object>
        {
            ["contents"] = new List<Dictionary<string, object>>
            {
                new()
                {
                    ["uri"] = uri,
                    ["mimeType"] = "application/json",
                    ["text"] = JsonSerializer.Serialize(new
                    {
                        uri,
                        action_type = actionType.ToString(),
                        status = "allowed"
                    }, JsonOptions)
                }
            }
        };
    }

    private static Dictionary<string, object> HandlePromptsList()
    {
        // Prompts listing does not require governance enforcement.
        return new Dictionary<string, object>
        {
            ["prompts"] = new List<Dictionary<string, object>>()
        };
    }

    private static Dictionary<string, object> HandlePromptsGet(Dictionary<string, object> msgParams)
    {
        var name = msgParams.TryGetValue("name", out var n) ? n?.ToString() ?? string.Empty : string.Empty;

        return new Dictionary<string, object>
        {
            ["description"] = $"Prompt '{name}' (governance-filtered)",
            ["messages"] = new List<Dictionary<string, object>>()
        };
    }

    // ── JSON-RPC helpers ─────────────────────────────────────────────────

    private static Dictionary<string, object?> JsonRpcSuccess(object? id, object result) => new()
    {
        ["jsonrpc"] = "2.0",
        ["id"] = id,
        ["result"] = result
    };

    private static Dictionary<string, object?> JsonRpcError(object? id, int code, string message) => new()
    {
        ["jsonrpc"] = "2.0",
        ["id"] = id,
        ["error"] = new Dictionary<string, object>
        {
            ["code"] = code,
            ["message"] = message
        }
    };

    private static Dictionary<string, object> ExtractParams(Dictionary<string, object?> message)
    {
        if (message.TryGetValue("params", out var paramsObj))
        {
            if (paramsObj is Dictionary<string, object> dict)
                return dict;

            if (paramsObj is JsonElement je && je.ValueKind == JsonValueKind.Object)
            {
                var result = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                foreach (var prop in je.EnumerateObject())
                {
                    result[prop.Name] = DeserializeJsonElement(prop.Value);
                }
                return result;
            }
        }

        return new Dictionary<string, object>();
    }

    private static object DeserializeJsonElement(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.String => element.GetString() ?? string.Empty,
        JsonValueKind.Number => element.TryGetInt64(out var l) ? l : element.GetDouble(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Null => string.Empty,
        JsonValueKind.Object => element.EnumerateObject()
            .ToDictionary(p => p.Name, p => DeserializeJsonElement(p.Value)),
        JsonValueKind.Array => element.EnumerateArray().Select(DeserializeJsonElement).ToList(),
        _ => element.ToString()
    };
}
