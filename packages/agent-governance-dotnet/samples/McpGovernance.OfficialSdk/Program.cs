// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// ============================================================================
// Sample: MCP Governance + Official ModelContextProtocol SDK
//
// Shows how Agent Governance's security layer integrates with the official
// MCP C# SDK. The official SDK handles transport and protocol; our library
// adds OWASP-compliant security on top.
//
// Prerequisites:
//   dotnet add package ModelContextProtocol --version 1.2.0
//   dotnet add package Microsoft.AgentGovernance
// ============================================================================

using AgentGovernance;
using AgentGovernance.Extensions;
using AgentGovernance.Mcp;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = Host.CreateApplicationBuilder(args);

// ── 1. Register governance services ─────────────────────────────────────────
builder.Services.AddMcpGovernance(new McpGovernanceOptions
{
    DeniedTools = McpGovernanceDefaults.DeniedTools.ToList(),
    SensitiveTools = McpGovernanceDefaults.SensitiveTools.ToList(),
    MaxToolCallsPerAgent = 500,
    EnableResponseScanning = true,
    EnableCredentialRedaction = true,
});

// ── 2. Register official MCP server with governance filter ──────────────────
//
// Uncomment the block below after installing ModelContextProtocol:
//   dotnet add package ModelContextProtocol --version 1.2.0
//
// builder.Services.AddMcpServer()
//     .WithStdioServerTransport()    // or .WithHttpServerTransport()
//     .WithToolsFromAssembly()
//     .WithRequestFilters(filters =>
//     {
//         // Hook tool calls through the governance pipeline
//         filters.AddCallToolFilter(next => async (request, ct) =>
//         {
//             var gateway = builder.Services.BuildServiceProvider()
//                 .GetRequiredService<McpGateway>();
//
//             var toolName = request.Params?.Name ?? "unknown";
//             var agentId = request.Server?.ServerInfo?.Name ?? "unknown-agent";
//             var parameters = new Dictionary<string, object>();
//
//             if (request.Params?.Arguments is not null)
//             {
//                 foreach (var kvp in request.Params.Arguments)
//                     parameters[kvp.Key] = kvp.Value?.ToString() ?? "";
//             }
//
//             // 5-stage governance pipeline evaluates the call
//             var (allowed, reason) = gateway.InterceptToolCall(
//                 agentId, toolName, parameters);
//
//             if (!allowed)
//             {
//                 // Governance denied — throw MCP error back to client
//                 throw new McpException($"Governance denied: {reason}");
//             }
//
//             // Governance approved — execute the tool
//             var result = await next(request, ct);
//
//             // Optional: scan response for credential leaks
//             var redactor = builder.Services.BuildServiceProvider()
//                 .GetService<CredentialRedactor>();
//             // redactor?.Redact(...) on response content
//
//             return result;
//         });
//     })
//     .WithMessageFilters(filters =>
//     {
//         // Optional: log all incoming MCP messages
//         filters.AddIncomingFilter(next => async (context, ct) =>
//         {
//             Console.WriteLine($"[MCP] Incoming: {context.Message}");
//             await next(context, ct);
//         });
//
//         // Optional: scan all outgoing responses
//         filters.AddOutgoingFilter(next => async (context, ct) =>
//         {
//             // Credential redaction on outgoing messages
//             Console.WriteLine($"[MCP] Outgoing: {context.Message}");
//             await next(context, ct);
//         });
//     });

// ── Without the SDK, demonstrate the governance pipeline directly ────────────

var host = builder.Build();

// Simulate tool call governance
var gw = host.Services.GetRequiredService<McpGateway>();

Console.WriteLine("=== MCP Governance Demo ===\n");

// Allowed call
var (allowed1, reason1) = gw.InterceptToolCall(
    "did:mesh:agent-001", "read_file",
    new() { ["path"] = "/data/report.csv" });
Console.WriteLine($"read_file: {(allowed1 ? "✅ Allowed" : $"❌ Denied: {reason1}")}");

// Denied call (in default deny list)
var (allowed2, reason2) = gw.InterceptToolCall(
    "did:mesh:agent-001", "drop_database",
    new() { ["db"] = "production" });
Console.WriteLine($"drop_database: {(allowed2 ? "✅ Allowed" : $"❌ Denied: {reason2}")}");

// Sanitization catch (SQL injection in params)
var (allowed3, reason3) = gw.InterceptToolCall(
    "did:mesh:agent-001", "search",
    new() { ["query"] = "'; DROP TABLE users; --" });
Console.WriteLine($"search (SQLi): {(allowed3 ? "✅ Allowed" : $"❌ Denied: {reason3}")}");

// Credential redaction
var redacted = CredentialRedactor.Redact("API key: sk-live_abc123def456ghi789");
Console.WriteLine($"\nCredential redaction: {redacted}");

Console.WriteLine("\n=== Integration with official MCP SDK ===");
Console.WriteLine("Uncomment the AddMcpServer() block in Program.cs after installing:");
Console.WriteLine("  dotnet add package ModelContextProtocol --version 1.2.0");
Console.WriteLine("\nThe governance filter hooks into .WithRequestFilters() to evaluate");
Console.WriteLine("every tool call through the 5-stage security pipeline.");
