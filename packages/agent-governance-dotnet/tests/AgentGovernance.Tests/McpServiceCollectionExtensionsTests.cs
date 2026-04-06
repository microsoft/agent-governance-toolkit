// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Reflection;
using System.Text;
using System.Text.Json;
using AgentGovernance.Extensions;
using AgentGovernance.Mcp;
using AgentGovernance.Mcp.Abstractions;
using AgentGovernance.Telemetry;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AgentGovernance.Tests;

public class McpServiceCollectionExtensionsTests
{
    // ── Core service registration ────────────────────────────────────────

    [Fact]
    public void AddMcpGovernance_RegistersAllCoreServices()
    {
        var services = new ServiceCollection();
        services.AddMcpGovernance();
        var provider = services.BuildServiceProvider();

        Assert.NotNull(provider.GetService<McpGateway>());
        Assert.NotNull(provider.GetService<McpSecurityScanner>());
        Assert.NotNull(provider.GetService<McpToolMapper>());
        Assert.NotNull(provider.GetService<McpMessageHandler>());
        Assert.NotNull(provider.GetService<GovernanceMetrics>());
        Assert.NotNull(provider.GetService<GovernanceKernel>());
        Assert.NotNull(provider.GetService<McpGovernanceOptions>());
        Assert.NotNull(provider.GetService<IMcpSessionStore>());
        Assert.NotNull(provider.GetService<IMcpNonceStore>());
        Assert.NotNull(provider.GetService<IMcpRateLimitStore>());
        Assert.NotNull(provider.GetService<IMcpAuditSink>());
        Assert.NotNull(provider.GetService<TimeProvider>());
    }

    [Fact]
    public void AddMcpGovernance_WithOptions_AppliesConfig()
    {
        var services = new ServiceCollection();
        services.AddMcpGovernance(new McpGovernanceOptions
        {
            DeniedTools = new() { "dangerous_tool" }
        });
        var provider = services.BuildServiceProvider();
        var gateway = provider.GetRequiredService<McpGateway>();

        var (allowed, _) = gateway.InterceptToolCall("did:mesh:a1", "dangerous_tool", new());
        Assert.False(allowed);
    }

    [Fact]
    public void AddMcpGovernance_OptionalServices_RegisteredWhenConfigured()
    {
        var services = new ServiceCollection();
        services.AddMcpGovernance(new McpGovernanceOptions
        {
            EnableResponseScanning = true,
            SessionTtl = TimeSpan.FromHours(1),
            MessageSigningKey = McpMessageSigner.GenerateKey()
        });
        var provider = services.BuildServiceProvider();

        Assert.NotNull(provider.GetService<McpResponseScanner>());
        Assert.NotNull(provider.GetService<McpSessionAuthenticator>());
        Assert.NotNull(provider.GetService<McpMessageSigner>());
    }

    [Fact]
    public void AddMcpGovernance_OptionalServices_NullWhenNotConfigured()
    {
        var services = new ServiceCollection();
        services.AddMcpGovernance(new McpGovernanceOptions
        {
            EnableResponseScanning = false,
            SessionTtl = null
        });
        var provider = services.BuildServiceProvider();

        Assert.Null(provider.GetService<McpResponseScanner>());
        Assert.Null(provider.GetService<McpSessionAuthenticator>());
        Assert.Null(provider.GetService<McpMessageSigner>());
    }

    [Fact]
    public void AddMcpGovernance_Singleton_ReturnsSameInstance()
    {
        var services = new ServiceCollection();
        services.AddMcpGovernance();
        var provider = services.BuildServiceProvider();

        var gateway1 = provider.GetRequiredService<McpGateway>();
        var gateway2 = provider.GetRequiredService<McpGateway>();
        Assert.Same(gateway1, gateway2);
    }

    [Fact]
    public void AddMcpGovernance_MetricsWired_ToGatewayAndScanner()
    {
        var services = new ServiceCollection();
        services.AddMcpGovernance();
        var provider = services.BuildServiceProvider();

        var gateway = provider.GetRequiredService<McpGateway>();
        var scanner = provider.GetRequiredService<McpSecurityScanner>();
        var metrics = provider.GetRequiredService<GovernanceMetrics>();

        Assert.Same(metrics, gateway.Metrics);
        Assert.Same(metrics, scanner.Metrics);
    }

    [Fact]
    public void AddMcpGovernance_WithAllowedTools_GatewayFilters()
    {
        var services = new ServiceCollection();
        services.AddMcpGovernance(new McpGovernanceOptions
        {
            AllowedTools = new() { "safe_tool" }
        });
        var provider = services.BuildServiceProvider();
        var gateway = provider.GetRequiredService<McpGateway>();

        var (blocked, _) = gateway.InterceptToolCall("did:mesh:a1", "other_tool", new());
        Assert.False(blocked);

        var (allowed, _) = gateway.InterceptToolCall("did:mesh:a1", "safe_tool", new());
        Assert.True(allowed);
    }

    [Fact]
    public void AddMcpGovernance_WithMaxToolCalls_RespectsBudget()
    {
        var services = new ServiceCollection();
        services.AddMcpGovernance(new McpGovernanceOptions
        {
            MaxToolCallsPerAgent = 2
        });
        var provider = services.BuildServiceProvider();
        var gateway = provider.GetRequiredService<McpGateway>();

        Assert.True(gateway.InterceptToolCall("did:mesh:a1", "tool", new()).Allowed);
        Assert.True(gateway.InterceptToolCall("did:mesh:a1", "tool", new()).Allowed);
        Assert.False(gateway.InterceptToolCall("did:mesh:a1", "tool", new()).Allowed);
    }

    [Fact]
    public void AddMcpGovernance_DefaultOptions_HasResponseScannerAndSessionAuth()
    {
        var services = new ServiceCollection();
        services.AddMcpGovernance();
        var provider = services.BuildServiceProvider();

        // Default options enable response scanning and session auth (TTL = 1h)
        Assert.NotNull(provider.GetService<McpResponseScanner>());
        Assert.NotNull(provider.GetService<McpSessionAuthenticator>());
    }

    [Fact]
    public void AddMcpGovernance_EnableCredentialRedactionFalse_PreservesAuditParameters()
    {
        var services = new ServiceCollection();
        services.AddMcpGovernance(new McpGovernanceOptions
        {
            EnableCredentialRedaction = false
        });
        var provider = services.BuildServiceProvider();
        var gateway = provider.GetRequiredService<McpGateway>();

        gateway.InterceptToolCall("did:mesh:a1", "read_file", new Dictionary<string, object>
        {
            ["apiKey"] = "sk-live_abc123def456ghi789"
        });

        Assert.Single(gateway.AuditLog);
        Assert.Equal("sk-live_abc123def456ghi789", gateway.AuditLog[0].Parameters["apiKey"]);
    }

    [Fact]
    public void AddMcpGovernance_ReturnsServiceCollection_ForChaining()
    {
        var services = new ServiceCollection();
        var result = services.AddMcpGovernance();

        Assert.Same(services, result);
    }

    [Fact]
    public void AddMcpGovernance_NullOptions_UsesDefaults()
    {
        var services = new ServiceCollection();
        services.AddMcpGovernance(null);
        var provider = services.BuildServiceProvider();

        var gateway = provider.GetRequiredService<McpGateway>();
        // Default: no deny-list, no allow-list — tool should pass
        var (allowed, _) = gateway.InterceptToolCall("did:mesh:a1", "any_tool", new());
        Assert.True(allowed);
    }

    [Fact]
    public void AddMcpGovernance_MiddlewareRegistered()
    {
        var services = new ServiceCollection();
        services.AddMcpGovernance();
        var provider = services.BuildServiceProvider();

        // McpGovernanceMiddleware should be resolvable (transient)
        var middleware = provider.GetService<McpGovernanceMiddleware>();
        Assert.NotNull(middleware);
    }

    [Fact]
    public void AddMcpGovernance_UsesConfiguredAgentId()
    {
        var services = new ServiceCollection();
        services.AddMcpGovernance(new McpGovernanceOptions
        {
            AgentId = "did:mesh:configured-agent"
        });
        var provider = services.BuildServiceProvider();
        var handler = provider.GetRequiredService<McpMessageHandler>();
        var agentIdField = typeof(McpMessageHandler).GetField("_agentId", BindingFlags.Instance | BindingFlags.NonPublic);

        Assert.NotNull(agentIdField);
        Assert.Equal("did:mesh:configured-agent", agentIdField!.GetValue(handler));
    }
}

public class McpGovernanceMiddlewareTests
{
    private static McpGovernanceMiddleware CreateMiddleware(McpGovernanceOptions? options = null)
    {
        // Use the static factory to create the handler, same approach as existing tests
        var opts = options ?? new McpGovernanceOptions();
        var stack = McpGovernanceExtensions.AddMcpGovernance(mcpOptions: opts);
        return new McpGovernanceMiddleware(stack.Handler);
    }

    private static DefaultHttpContext CreateHttpContext(
        string method,
        string? contentType,
        string? body)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.ContentType = contentType;

        if (body is not null)
        {
            var bytes = Encoding.UTF8.GetBytes(body);
            context.Request.Body = new MemoryStream(bytes);
            context.Request.ContentLength = bytes.Length;
        }

        context.Response.Body = new MemoryStream();

        return context;
    }

    private static async Task<string> ReadResponseBody(HttpContext context)
    {
        context.Response.Body.Seek(0, SeekOrigin.Begin);
        using var reader = new StreamReader(context.Response.Body, Encoding.UTF8);
        return await reader.ReadToEndAsync();
    }

    [Fact]
    public async Task Middleware_NonPostRequest_PassesThrough()
    {
        var middleware = CreateMiddleware();
        var context = CreateHttpContext("GET", "application/json", null);
        var nextCalled = false;

        await middleware.InvokeAsync(context, _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        Assert.True(nextCalled);
    }

    [Fact]
    public async Task Middleware_NonJsonContentType_PassesThrough()
    {
        var middleware = CreateMiddleware();
        var context = CreateHttpContext("POST", "text/plain", "hello");
        var nextCalled = false;

        await middleware.InvokeAsync(context, _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        Assert.True(nextCalled);
    }

    [Fact]
    public async Task Middleware_NullContentType_PassesThrough()
    {
        var middleware = CreateMiddleware();
        var context = CreateHttpContext("POST", null, "hello");
        var nextCalled = false;

        await middleware.InvokeAsync(context, _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        Assert.True(nextCalled);
    }

    [Fact]
    public async Task Middleware_NonMcpJson_PassesThrough()
    {
        var middleware = CreateMiddleware();
        var body = JsonSerializer.Serialize(new { name = "test", value = 42 });
        var context = CreateHttpContext("POST", "application/json", body);
        var nextCalled = false;

        await middleware.InvokeAsync(context, _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        Assert.True(nextCalled);
    }

    [Fact]
    public async Task Middleware_InvalidJson_PassesThrough()
    {
        var middleware = CreateMiddleware();
        var context = CreateHttpContext("POST", "application/json", "not json {{{");
        var nextCalled = false;

        await middleware.InvokeAsync(context, _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        Assert.True(nextCalled);
    }

    [Fact]
    public async Task Middleware_InvalidJson_PassesThroughWithBufferedBody()
    {
        var middleware = CreateMiddleware();
        var context = CreateHttpContext("POST", "application/json", "not json {{{");
        string? forwardedBody = null;

        await middleware.InvokeAsync(context, async ctx =>
        {
            using var reader = new StreamReader(ctx.Request.Body, Encoding.UTF8, leaveOpen: true);
            forwardedBody = await reader.ReadToEndAsync();
        });

        Assert.Equal("not json {{{", forwardedBody);
    }

    [Fact]
    public async Task Middleware_ValidMcpMessage_ReturnsJsonRpcResponse()
    {
        var middleware = CreateMiddleware();
        var mcpRequest = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["jsonrpc"] = "2.0",
            ["method"] = "prompts/list",
            ["params"] = new Dictionary<string, object>(),
            ["id"] = 1
        });
        var context = CreateHttpContext("POST", "application/json", mcpRequest);
        var nextCalled = false;

        await middleware.InvokeAsync(context, _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        // Should NOT have passed through to next middleware
        Assert.False(nextCalled);

        // Should have written a JSON-RPC response
        Assert.Equal(200, context.Response.StatusCode);
        Assert.Equal("application/json", context.Response.ContentType);

        var responseBody = await ReadResponseBody(context);
        Assert.NotEmpty(responseBody);

        var response = JsonSerializer.Deserialize<Dictionary<string, object?>>(responseBody);
        Assert.NotNull(response);
        Assert.Equal("2.0", response!["jsonrpc"]?.ToString());
        Assert.True(response.ContainsKey("result"));
    }

    [Fact]
    public async Task Middleware_DeniedToolCall_ReturnsError()
    {
        var middleware = CreateMiddleware(new McpGovernanceOptions
        {
            DeniedTools = new() { "dangerous_tool" }
        });
        var mcpRequest = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["jsonrpc"] = "2.0",
            ["method"] = "tools/call",
            ["params"] = new Dictionary<string, object>
            {
                ["name"] = "dangerous_tool",
                ["arguments"] = new Dictionary<string, object>()
            },
            ["id"] = 2
        });
        var context = CreateHttpContext("POST", "application/json", mcpRequest);
        var nextCalled = false;

        await middleware.InvokeAsync(context, _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        Assert.False(nextCalled);
        Assert.Equal(200, context.Response.StatusCode);

        var responseBody = await ReadResponseBody(context);
        var response = JsonSerializer.Deserialize<Dictionary<string, object?>>(responseBody);
        Assert.NotNull(response);
        Assert.True(response!.ContainsKey("error"));
    }

    [Fact]
    public async Task Middleware_NullBody_PassesThrough()
    {
        var middleware = CreateMiddleware();
        var context = CreateHttpContext("POST", "application/json", "null");
        var nextCalled = false;

        await middleware.InvokeAsync(context, _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        Assert.True(nextCalled);
    }

    [Fact]
    public async Task Middleware_EmptyBody_PassesThrough()
    {
        var middleware = CreateMiddleware();
        var context = CreateHttpContext("POST", "application/json", "");
        var nextCalled = false;

        await middleware.InvokeAsync(context, _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        // Empty body → JsonException → pass through
        Assert.True(nextCalled);
    }

    [Fact]
    public async Task Middleware_JsonContentTypeWithCharset_StillIntercepted()
    {
        var middleware = CreateMiddleware();
        var mcpRequest = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["jsonrpc"] = "2.0",
            ["method"] = "prompts/list",
            ["params"] = new Dictionary<string, object>(),
            ["id"] = 3
        });
        var context = CreateHttpContext("POST", "application/json; charset=utf-8", mcpRequest);
        var nextCalled = false;

        await middleware.InvokeAsync(context, _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        Assert.False(nextCalled);
        Assert.Equal(200, context.Response.StatusCode);
    }
}
