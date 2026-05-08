# .NET Quickstart

A minimal, runnable console app that shows how to add the
[Microsoft.AgentGovernance](../../README.md) SDK to a .NET application.

In about 30 lines of `Program.cs` it covers:

- Creating a `GovernanceKernel` with a YAML policy file
- Subscribing to audit events
- Calling `EvaluateToolCall(...)` before every tool invocation and reading the
  decision (allow / deny / matched rule / reason)
- Demonstrating policy-driven **rate limiting** (3 `http_request` calls per
  minute)
- Demonstrating **prompt-injection detection** (one option turns it on)
- Creating a zero-trust **agent identity** and **delegating** narrowed
  capabilities to a child identity
- Printing an audit summary by event type

Everything is local: the project references the SDK via `ProjectReference`,
so it always builds against the in-tree source.

## Run it

> Requires the [.NET 8 SDK](https://dotnet.microsoft.com/download).

From this directory:

```bash
dotnet run
```

You should see output similar to:

```text
====================
  AGT Quickstart — .NET
====================

Loaded policy:  quickstart.yaml
Agent identity: did:agentmesh:research-assistant-001

-- Tool-call decisions --
  [ALLOW] web_search      rule=allow-safe-reads          reason=Matched rule 'allow-safe-reads' with action 'Allow'.
  [ALLOW] file_read       rule=allow-file-read           reason=Matched rule 'allow-file-read' with action 'Allow'.
  [BLOCK] file_write      rule=block-system-paths        reason=Matched rule 'block-system-paths' with action 'Deny'.
  [BLOCK] send_email      rule=require-approval-for-email reason=Matched rule 'require-approval-for-email' with action 'RequireApproval'.
  [BLOCK] execute_shell   rule=block-dangerous           reason=Matched rule 'block-dangerous' with action 'Deny'.

-- Rate-limit demo (policy: 3/minute on http_request) --
  [ALLOW] http_request    rule=rate-limit-http           reason=...
  [ALLOW] http_request    rule=rate-limit-http           reason=...
  [ALLOW] http_request    rule=rate-limit-http           reason=...
  [BLOCK] http_request    rule=rate-limit-http           reason=Rate limit exceeded ...
  [BLOCK] http_request    rule=rate-limit-http           reason=Rate limit exceeded ...

-- Prompt-injection demo --
  [BLOCK] web_search      rule=(default)                 reason=Prompt-injection pattern detected ...

-- Zero-trust identity --
  DID:          did:mesh:...
  Sponsor:      alice@contoso.com
  Capabilities: [web_search, file_read]
  Delegated to: did:mesh:... (capabilities: [file_read])

-- Audit summary --
  Events captured: 12
    PolicyCheck         8
    ToolCallBlocked     4
```

## Files

| File | Purpose |
|------|---------|
| `Program.cs` | The console app. Heavily commented; treat it as a tutorial. |
| `Quickstart.csproj` | Targets `net8.0`, references the local `AgentGovernance` SDK. |
| `policies/quickstart.yaml` | Sample policy with `allow`, `deny`, `require_approval`, and `rate_limit` rules. |

## Try it yourself

Edit `policies/quickstart.yaml` to:

- Flip `default_action` between `allow` and `deny` to see fail-open vs
  fail-closed behavior.
- Add a new rule, e.g.

  ```yaml
  - name: block-pii-tools
    condition: "tool_name == 'export_user_data'"
    action: deny
    priority: 100
  ```

- Switch the kernel's `ConflictStrategy` in `Program.cs` to
  `ConflictResolutionStrategy.DenyOverrides` to make any matching deny win,
  no matter the priority.

## Where to go next

- **Full feature tour** — [`agent-governance-dotnet/README.md`](../../README.md)
- **MCP integration** — `Microsoft.AgentGovernance.Extensions.ModelContextProtocol`
- **Agent Framework integration** — `Microsoft.AgentGovernance.Extensions.Microsoft.Agents`
- **Cross-language equivalents** — [`examples/quickstart/`](../../../examples/quickstart/) (Python)
