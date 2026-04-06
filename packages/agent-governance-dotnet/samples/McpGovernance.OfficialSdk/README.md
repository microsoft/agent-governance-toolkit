# MCP Governance + Official MCP SDK Sample

Shows how to integrate Agent Governance's security layer with the
[official ModelContextProtocol C# SDK](https://github.com/modelcontextprotocol/csharp-sdk).

**The official SDK handles transport and protocol. Our library adds security aligned to the OWASP MCP Security Cheat Sheet.**

## Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────┐
│  MCP Client  │────▶│  Official MCP SDK │────▶│   Your Tool  │
│  (Claude,    │     │  (transport +     │     │  (read_file, │
│   Copilot)   │◀────│   protocol)       │◀────│   query_db)  │
└──────────────┘     └────────┬─────────┘     └──────────────┘
                              │
                     ┌────────▼─────────┐
                     │ Agent Governance  │
                     │ ─────────────────│
                     │ § Deny-list      │
                     │ § Allow-list     │
                     │ § Sanitization   │
                     │ § Rate limiting  │
                     │ § Human approval │
                     │ § Response scan  │
                     │ § Credential     │
                     │   redaction      │
                     └──────────────────┘
```

## Run

```bash
cd packages/agent-governance-dotnet/samples/McpGovernance.OfficialSdk
dotnet run
```

## Enable Official SDK Integration

1. Install the MCP SDK:
   ```bash
   dotnet add package ModelContextProtocol --version 1.2.0
   ```

2. Uncomment the `AddMcpServer()` block in `Program.cs`

3. Uncomment the PackageReference in the `.csproj`

4. Run:
   ```bash
   dotnet run
   ```

## How It Works

The integration uses the official SDK's filter system:

- **`WithRequestFilters → AddCallToolFilter`** — Every `tools/call` request passes
  through `McpGateway.InterceptToolCall()` before the tool executes
- **`WithMessageFilters → AddOutgoingFilter`** — Outgoing responses pass through
  `CredentialRedactor.Redact()` to strip sensitive values

This gives you full OWASP MCP Security Cheat Sheet coverage (11/12 sections)
without modifying any tool implementations.
