// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Text.Json;
using AgentGovernance.Mcp;
using Microsoft.AspNetCore.Http;

namespace AgentGovernance.Extensions;

/// <summary>
/// ASP.NET Core middleware that intercepts MCP JSON-RPC messages
/// and routes them through the governance pipeline.
/// <para>
/// Only intercepts HTTP POST requests with JSON content that contain valid
/// JSON-RPC 2.0 messages (having <c>jsonrpc</c> and <c>method</c> fields).
/// All other requests pass through to the next middleware in the pipeline.
/// </para>
/// </summary>
/// <remarks>
/// This middleware implements <see cref="IMiddleware"/>, which requires
/// DI registration. Call <see cref="McpServiceCollectionExtensions.AddMcpGovernance"/>
/// before adding this middleware to the pipeline.
/// </remarks>
public sealed class McpGovernanceMiddleware : IMiddleware
{
    private readonly McpMessageHandler _handler;

    /// <summary>
    /// Initializes a new <see cref="McpGovernanceMiddleware"/>.
    /// </summary>
    /// <param name="handler">The MCP message handler resolved from DI.</param>
    public McpGovernanceMiddleware(McpMessageHandler handler)
    {
        _handler = handler;
    }

    /// <inheritdoc/>
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        // Only intercept POST requests with JSON content
        if (context.Request.Method != HttpMethods.Post ||
            context.Request.ContentType?.Contains("application/json") != true)
        {
            await next(context);
            return;
        }

        try
        {
            context.Request.EnableBuffering();

            // Read the JSON-RPC request body
            using var reader = new StreamReader(
                context.Request.Body,
                encoding: System.Text.Encoding.UTF8,
                detectEncodingFromByteOrderMarks: false,
                leaveOpen: true);
            var body = await reader.ReadToEndAsync();
            context.Request.Body.Position = 0;
            var message = JsonSerializer.Deserialize<Dictionary<string, object?>>(body,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true, MaxDepth = 32 });

            if (message is null)
            {
                await next(context);
                return;
            }

            // Check if this is an MCP message (has jsonrpc and method as string values)
            if (!message.TryGetValue("jsonrpc", out var jsonrpc) ||
                !message.TryGetValue("method", out var method) ||
                jsonrpc is not JsonElement jsonrpcEl || jsonrpcEl.ValueKind != JsonValueKind.String ||
                method is not JsonElement methodEl || methodEl.ValueKind != JsonValueKind.String)
            {
                await next(context);
                return;
            }

            // Route through governance
            var response = _handler.HandleMessage(message);

            // Write JSON-RPC response (always 200 per JSON-RPC spec — errors are in the body)
            context.Response.ContentType = "application/json";
            context.Response.StatusCode = 200;

            await context.Response.WriteAsync(
                JsonSerializer.Serialize(response, new JsonSerializerOptions { WriteIndented = false }),
                System.Text.Encoding.UTF8);
        }
        catch (JsonException)
        {
            // Not valid JSON — pass through to next middleware
            context.Request.Body.Position = 0;
            await next(context);
        }
    }
}
