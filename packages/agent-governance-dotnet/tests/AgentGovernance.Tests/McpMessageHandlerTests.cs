// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Mcp;
using Xunit;

namespace AgentGovernance.Tests;

public class McpMessageHandlerTests
{
    private static (McpMessageHandler Handler, McpGateway Gateway) CreateHandler(
        IEnumerable<string>? deniedTools = null,
        IEnumerable<string>? allowedTools = null)
    {
        var kernel = new GovernanceKernel();
        var gateway = new McpGateway(kernel, deniedTools: deniedTools, allowedTools: allowedTools);
        var mapper = new McpToolMapper();
        var handler = new McpMessageHandler(gateway, mapper, "did:mesh:test-agent");
        return (handler, gateway);
    }

    private static Dictionary<string, object?> MakeMessage(string method, Dictionary<string, object>? msgParams = null, int id = 1)
    {
        return new Dictionary<string, object?>
        {
            ["jsonrpc"] = "2.0",
            ["method"] = method,
            ["params"] = msgParams ?? new Dictionary<string, object>(),
            ["id"] = id
        };
    }

    // ── tools/call ───────────────────────────────────────────────────────

    [Fact]
    public void HandleMessage_ToolsCall_AllowedTool_ReturnsSuccess()
    {
        var (handler, _) = CreateHandler();
        handler.RegisterTool("file_read", new Dictionary<string, object>
        {
            ["name"] = "file_read",
            ["description"] = "Read a file"
        });

        var response = handler.HandleMessage(MakeMessage("tools/call",
            new Dictionary<string, object>
            {
                ["name"] = "file_read",
                ["arguments"] = new Dictionary<string, object> { ["path"] = "/tmp/test.txt" }
            }));

        Assert.Equal("2.0", response["jsonrpc"]?.ToString());
        Assert.NotNull(response["result"]);
        Assert.False(response.ContainsKey("error") && response["error"] is not null);
    }

    [Fact]
    public void HandleMessage_ToolsCall_DeniedTool_ReturnsError()
    {
        var (handler, _) = CreateHandler(deniedTools: new[] { "evil_tool" });

        var response = handler.HandleMessage(MakeMessage("tools/call",
            new Dictionary<string, object>
            {
                ["name"] = "evil_tool",
                ["arguments"] = new Dictionary<string, object>()
            }));

        Assert.NotNull(response["error"]);
    }

    [Fact]
    public void HandleMessage_ToolsCall_DeniedTool_SanitizesErrorMessage()
    {
        var (handler, _) = CreateHandler(deniedTools: new[] { "evil_tool" });

        var response = handler.HandleMessage(MakeMessage("tools/call",
            new Dictionary<string, object>
            {
                ["name"] = "evil_tool",
                ["arguments"] = new Dictionary<string, object>()
            }));

        var error = Assert.IsType<Dictionary<string, object>>(response["error"]);
        Assert.Equal("Access denied by governance policy.", error["message"]);
    }

    [Fact]
    public void HandleMessage_ToolsCall_UnknownTool_ReturnsError()
    {
        var (handler, _) = CreateHandler();

        var response = handler.HandleMessage(MakeMessage("tools/call",
            new Dictionary<string, object>
            {
                ["name"] = "completely_unknown_xyz",
                ["arguments"] = new Dictionary<string, object>()
            }));

        Assert.NotNull(response["error"]);
    }

    [Fact]
    public void HandleMessage_ToolsCall_MissingName_ReturnsError()
    {
        var (handler, _) = CreateHandler();

        var response = handler.HandleMessage(MakeMessage("tools/call",
            new Dictionary<string, object> { ["arguments"] = new Dictionary<string, object>() }));

        Assert.NotNull(response["error"]);
    }

    // ── tools/list ───────────────────────────────────────────────────────

    [Fact]
    public void HandleMessage_ToolsList_ReturnsToolList()
    {
        var (handler, _) = CreateHandler();
        handler.RegisterTool("file_read", new Dictionary<string, object>
        {
            ["name"] = "file_read",
            ["description"] = "Read a file"
        });

        var response = handler.HandleMessage(MakeMessage("tools/list"));

        Assert.NotNull(response["result"]);
        var result = response["result"] as Dictionary<string, object>;
        Assert.NotNull(result);
        Assert.True(result!.ContainsKey("tools"));
    }

    // ── resources/read ───────────────────────────────────────────────────

    [Fact]
    public void HandleMessage_ResourcesRead_ValidUri_ReturnsSuccess()
    {
        var (handler, _) = CreateHandler();

        var response = handler.HandleMessage(MakeMessage("resources/read",
            new Dictionary<string, object> { ["uri"] = "https://api.example.com/data.txt" }));

        Assert.NotNull(response["result"]);
    }

    [Fact]
    public void HandleMessage_ResourcesRead_MissingUri_ReturnsError()
    {
        var (handler, _) = CreateHandler();

        var response = handler.HandleMessage(MakeMessage("resources/read",
            new Dictionary<string, object>()));

        Assert.NotNull(response["error"]);
    }

    // ── resources/list ───────────────────────────────────────────────────

    [Fact]
    public void HandleMessage_ResourcesList_ReturnsResourceList()
    {
        var (handler, _) = CreateHandler();

        var response = handler.HandleMessage(MakeMessage("resources/list"));

        Assert.NotNull(response["result"]);
        var result = response["result"] as Dictionary<string, object>;
        Assert.NotNull(result);
        Assert.True(result!.ContainsKey("resources"));
    }

    // ── prompts/list ─────────────────────────────────────────────────────

    [Fact]
    public void HandleMessage_PromptsList_ReturnsPromptsList()
    {
        var (handler, _) = CreateHandler();

        var response = handler.HandleMessage(MakeMessage("prompts/list"));

        Assert.NotNull(response["result"]);
    }

    // ── prompts/get ──────────────────────────────────────────────────────

    [Fact]
    public void HandleMessage_PromptsGet_ReturnsPrompt()
    {
        var (handler, _) = CreateHandler();

        var response = handler.HandleMessage(MakeMessage("prompts/get",
            new Dictionary<string, object> { ["name"] = "test-prompt" }));

        Assert.NotNull(response["result"]);
    }

    // ── Unknown method ───────────────────────────────────────────────────

    [Fact]
    public void HandleMessage_UnknownMethod_ReturnsMethodNotFound()
    {
        var (handler, _) = CreateHandler();

        var response = handler.HandleMessage(MakeMessage("unknown/method"));

        Assert.NotNull(response["error"]);
        var error = response["error"] as Dictionary<string, object>;
        Assert.NotNull(error);
        Assert.Equal(-32601, error!["code"]);
    }

    [Fact]
    public void HandleMessage_MissingMethod_ReturnsInvalidRequest()
    {
        var (handler, _) = CreateHandler();

        var response = handler.HandleMessage(new Dictionary<string, object?>
        {
            ["jsonrpc"] = "2.0",
            ["id"] = 1
        });

        Assert.NotNull(response["error"]);
        var error = response["error"] as Dictionary<string, object>;
        Assert.Equal(-32600, error!["code"]);
    }

    // ── JSON-RPC format ──────────────────────────────────────────────────

    [Fact]
    public void HandleMessage_PreservesId()
    {
        var (handler, _) = CreateHandler();

        var response = handler.HandleMessage(MakeMessage("prompts/list", id: 42));

        Assert.Equal(42, response["id"]);
    }

    [Fact]
    public void HandleMessage_AlwaysIncludesJsonRpcVersion()
    {
        var (handler, _) = CreateHandler();

        var response = handler.HandleMessage(MakeMessage("prompts/list"));

        Assert.Equal("2.0", response["jsonrpc"]?.ToString());
    }

    // ── OnBlock callback ─────────────────────────────────────────────────

    [Fact]
    public void HandleMessage_BlockedToolCall_InvokesOnBlock()
    {
        // Use "file_read" which the mapper can classify, but put it on the deny list.
        string? blockedTool = null;

        var handlerWithCallback = new McpMessageHandler(
            new McpGateway(new GovernanceKernel(), deniedTools: new[] { "file_read" }),
            new McpToolMapper(),
            "did:mesh:test")
        {
            OnBlock = (tool, _, _) => blockedTool = tool
        };

        handlerWithCallback.HandleMessage(MakeMessage("tools/call",
            new Dictionary<string, object>
            {
                ["name"] = "file_read",
                ["arguments"] = new Dictionary<string, object>()
            }));

        Assert.Equal("file_read", blockedTool);
    }

    // ── Registration ─────────────────────────────────────────────────────

    [Fact]
    public void RegisterTool_NullName_Throws()
    {
        var (handler, _) = CreateHandler();
        Assert.ThrowsAny<ArgumentException>(() =>
            handler.RegisterTool("", new Dictionary<string, object>()));
    }

    [Fact]
    public void RegisterResource_NullUri_Throws()
    {
        var (handler, _) = CreateHandler();
        Assert.ThrowsAny<ArgumentException>(() =>
            handler.RegisterResource("", new Dictionary<string, object>()));
    }
}
