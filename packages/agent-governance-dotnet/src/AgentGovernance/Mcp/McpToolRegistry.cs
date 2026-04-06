// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Reflection;
using Microsoft.Extensions.Logging;

namespace AgentGovernance.Mcp;

/// <summary>
/// Discovers and registers MCP tools from assemblies using the <see cref="McpToolAttribute"/>.
/// Supports both static methods and instance methods (via DI service provider).
/// </summary>
public sealed class McpToolRegistry
{
    private readonly McpMessageHandler _handler;
    private readonly ILogger<McpToolRegistry>? _logger;
    private readonly object _registrationsLock = new();
    private readonly List<ToolRegistration> _registrations = new();

    /// <summary>
    /// Initializes a new <see cref="McpToolRegistry"/>.
    /// </summary>
    /// <param name="handler">The message handler to register discovered tools with.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public McpToolRegistry(McpMessageHandler handler, ILogger<McpToolRegistry>? logger = null)
    {
        _handler = handler;
        _logger = logger;
    }

    /// <summary>Gets all discovered tool registrations.</summary>
    public IReadOnlyList<ToolRegistration> Registrations
    {
        get
        {
            lock (_registrationsLock)
            {
                return _registrations.ToArray();
            }
        }
    }

    /// <summary>
    /// Scans the specified assembly for methods decorated with <see cref="McpToolAttribute"/>
    /// and registers each one with the underlying <see cref="McpMessageHandler"/>.
    /// </summary>
    /// <returns>The number of tools discovered and registered.</returns>
    public int DiscoverTools(Assembly assembly)
    {
        var count = 0;
        foreach (var type in assembly.GetTypes())
        {
            foreach (var method in type.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance))
            {
                var attr = method.GetCustomAttribute<McpToolAttribute>();
                if (attr is null) continue;

                var toolName = attr.Name ?? ToSnakeCase(method.Name);
                var schema = BuildSchemaFromMethod(method);
                var registration = new ToolRegistration(
                    toolName, attr.Description, method, type, attr.RequiresApproval, attr.ActionType, schema);

                // Pack description + schema into the toolInfo dict expected by McpMessageHandler.RegisterTool
                var toolInfo = new Dictionary<string, object>
                {
                    ["name"] = toolName,
                    ["description"] = attr.Description,
                    ["inputSchema"] = schema
                };
                _handler.RegisterTool(toolName, toolInfo);
                lock (_registrationsLock)
                {
                    _registrations.Add(registration);
                }
                count++;

                _logger?.LogDebug("Discovered MCP tool: {ToolName} from {TypeName}.{MethodName}",
                    toolName, type.Name, method.Name);
            }
        }

        _logger?.LogInformation("Discovered {Count} MCP tools from {Assembly}", count, assembly.GetName().Name);
        return count;
    }

    /// <summary>
    /// Scans the calling assembly for MCP tools.
    /// </summary>
    public int DiscoverTools() => DiscoverTools(Assembly.GetCallingAssembly());

    /// <summary>
    /// Gets a registration by tool name.
    /// </summary>
    public ToolRegistration? GetRegistration(string toolName)
    {
        lock (_registrationsLock)
        {
            return _registrations.Find(r => r.ToolName == toolName);
        }
    }

    /// <summary>
    /// Invokes a registered tool by name with the given parameters.
    /// For instance methods, requires a <paramref name="serviceProvider"/> to resolve the declaring type.
    /// </summary>
    public async Task<Dictionary<string, object>> InvokeToolAsync(
        string toolName,
        Dictionary<string, object> parameters,
        IServiceProvider? serviceProvider = null)
    {
        var reg = GetRegistration(toolName)
            ?? throw new InvalidOperationException($"Tool '{toolName}' is not registered");

        object? instance = null;
        if (!reg.Method.IsStatic)
        {
            instance = serviceProvider?.GetService(reg.DeclaringType)
                ?? throw new InvalidOperationException(
                    $"Tool '{toolName}' requires an instance of {reg.DeclaringType.Name} but none was provided via DI");
        }

        // Build method arguments from parameters
        var args = BuildArguments(reg.Method, parameters);

        try
        {
            var result = reg.Method.Invoke(instance, args);

            // Handle async methods
            if (result is Task<Dictionary<string, object>> asyncResult)
            {
                return await asyncResult;
            }
            if (result is Task task)
            {
                await task;
                // void async method — return empty result
                return new Dictionary<string, object> { ["status"] = "completed" };
            }
            if (result is Dictionary<string, object> syncResult)
            {
                return syncResult;
            }

            // Wrap non-dict return in a result dict
            return new Dictionary<string, object> { ["result"] = result ?? "null" };
        }
        catch (TargetInvocationException ex) when (ex.InnerException is not null)
        {
            throw ex.InnerException;
        }
    }

    /// <summary>
    /// Builds a JSON Schema from the method's parameters.
    /// </summary>
    /// <param name="method">The method to build a schema for.</param>
    /// <returns>A JSON Schema dictionary describing the method's parameters.</returns>
    public static Dictionary<string, object> BuildSchemaFromMethod(MethodInfo method)
    {
        var properties = new Dictionary<string, object>();
        var required = new List<string>();

        foreach (var param in method.GetParameters())
        {
            var propSchema = new Dictionary<string, object>
            {
                ["type"] = GetJsonType(param.ParameterType)
            };

            // Check for description attribute
            var descAttr = param.GetCustomAttribute<System.ComponentModel.DescriptionAttribute>();
            if (descAttr is not null)
                propSchema["description"] = descAttr.Description;

            properties[param.Name ?? param.Position.ToString()] = propSchema;

            if (!param.HasDefaultValue)
                required.Add(param.Name ?? param.Position.ToString());
        }

        var schema = new Dictionary<string, object>
        {
            ["type"] = "object",
            ["properties"] = properties
        };

        if (required.Count > 0)
            schema["required"] = required;

        return schema;
    }

    private static object[] BuildArguments(MethodInfo method, Dictionary<string, object> parameters)
    {
        var methodParams = method.GetParameters();
        var args = new object[methodParams.Length];

        for (int i = 0; i < methodParams.Length; i++)
        {
            var param = methodParams[i];
            var name = param.Name ?? param.Position.ToString();

            if (parameters.TryGetValue(name, out var value))
            {
                args[i] = ConvertParameter(value, param.ParameterType);
            }
            else if (param.HasDefaultValue)
            {
                args[i] = param.DefaultValue!;
            }
            else
            {
                throw new ArgumentException($"Required parameter '{name}' not provided");
            }
        }

        return args;
    }

    private static object ConvertParameter(object value, Type targetType)
    {
        if (value is null) return null!;
        if (targetType.IsAssignableFrom(value.GetType())) return value;

        // Handle System.Text.Json elements
        if (value is System.Text.Json.JsonElement jsonElement)
        {
            return jsonElement.ValueKind switch
            {
                System.Text.Json.JsonValueKind.String => jsonElement.GetString()!,
                System.Text.Json.JsonValueKind.Number when targetType == typeof(int) => jsonElement.GetInt32(),
                System.Text.Json.JsonValueKind.Number when targetType == typeof(long) => jsonElement.GetInt64(),
                System.Text.Json.JsonValueKind.Number when targetType == typeof(double) => jsonElement.GetDouble(),
                System.Text.Json.JsonValueKind.Number when targetType == typeof(decimal) => jsonElement.GetDecimal(),
                System.Text.Json.JsonValueKind.True or System.Text.Json.JsonValueKind.False => jsonElement.GetBoolean(),
                _ => value
            };
        }

        return Convert.ChangeType(value, targetType);
    }

    /// <summary>
    /// Converts a PascalCase method name to snake_case for MCP tool naming.
    /// </summary>
    /// <param name="name">The PascalCase name to convert.</param>
    /// <returns>The snake_case equivalent.</returns>
    public static string ToSnakeCase(string name)
    {
        if (string.IsNullOrEmpty(name)) return name;

        var result = new System.Text.StringBuilder();
        for (int i = 0; i < name.Length; i++)
        {
            var c = name[i];
            if (char.IsUpper(c))
            {
                if (i > 0) result.Append('_');
                result.Append(char.ToLowerInvariant(c));
            }
            else
            {
                result.Append(c);
            }
        }
        return result.ToString();
    }

    private static string GetJsonType(Type type)
    {
        if (type == typeof(string)) return "string";
        if (type == typeof(int) || type == typeof(long) || type == typeof(double) || type == typeof(decimal)) return "number";
        if (type == typeof(bool)) return "boolean";
        if (type.IsArray || (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(List<>))) return "array";
        return "object";
    }
}

/// <summary>
/// Represents a discovered MCP tool registration.
/// </summary>
public sealed record ToolRegistration(
    string ToolName,
    string Description,
    MethodInfo Method,
    Type DeclaringType,
    bool RequiresApproval,
    string? ActionType,
    Dictionary<string, object> Schema);
