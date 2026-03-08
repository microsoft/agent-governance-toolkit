// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Audit;
using AgentGovernance.Integration;
using AgentGovernance.Policy;
using Xunit;

namespace AgentGovernance.Tests;

public class GovernanceMiddlewareTests
{
    private static GovernanceMiddleware CreateMiddleware(string yaml)
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(yaml);
        var emitter = new AuditEmitter();
        return new GovernanceMiddleware(engine, emitter);
    }

    [Fact]
    public void EvaluateToolCall_BlockedTool_ReturnsDenied()
    {
        var yaml = @"
apiVersion: governance.toolkit/v1
name: block-policy
default_action: allow
rules:
  - name: block-rm
    condition: ""tool_name == 'rm'""
    action: deny
    priority: 10
";
        var middleware = CreateMiddleware(yaml);

        var result = middleware.EvaluateToolCall("did:mesh:agent1", "rm");

        Assert.False(result.Allowed);
        Assert.Contains("deny", result.Reason, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(result.AuditEntry);
        Assert.Equal(GovernanceEventType.ToolCallBlocked, result.AuditEntry.Type);
    }

    [Fact]
    public void EvaluateToolCall_AllowedTool_ReturnsAllowed()
    {
        var yaml = @"
apiVersion: governance.toolkit/v1
name: allow-policy
default_action: allow
rules: []
";
        var middleware = CreateMiddleware(yaml);

        var result = middleware.EvaluateToolCall("did:mesh:agent1", "file_read");

        Assert.True(result.Allowed);
        Assert.NotNull(result.AuditEntry);
        Assert.Equal(GovernanceEventType.PolicyCheck, result.AuditEntry.Type);
    }

    [Fact]
    public void EvaluateToolCall_EmitsAuditEvents()
    {
        var yaml = @"
apiVersion: governance.toolkit/v1
name: audit-test
default_action: allow
rules:
  - name: block-delete
    condition: ""tool_name == 'delete'""
    action: deny
    priority: 10
";
        var engine = new PolicyEngine();
        engine.LoadYaml(yaml);
        var emitter = new AuditEmitter();
        var middleware = new GovernanceMiddleware(engine, emitter);

        var events = new List<GovernanceEvent>();
        emitter.OnAll(e => events.Add(e));

        middleware.EvaluateToolCall("did:mesh:test", "delete");

        // Should emit both a ToolCallBlocked and PolicyViolation event.
        Assert.Contains(events, e => e.Type == GovernanceEventType.ToolCallBlocked);
        Assert.Contains(events, e => e.Type == GovernanceEventType.PolicyViolation);
    }

    [Fact]
    public void EvaluateToolCall_IncludesToolNameInAuditData()
    {
        var yaml = @"
apiVersion: governance.toolkit/v1
name: data-test
default_action: allow
rules: []
";
        var middleware = CreateMiddleware(yaml);

        var result = middleware.EvaluateToolCall("did:mesh:test", "my_tool",
            new Dictionary<string, object> { ["path"] = "/tmp/file.txt" });

        Assert.Equal("my_tool", result.AuditEntry.Data["tool_name"]);
    }

    [Fact]
    public void EvaluateToolCall_ArgumentsMergedIntoContext()
    {
        var yaml = @"
apiVersion: governance.toolkit/v1
name: args-test
default_action: allow
rules:
  - name: block-secret-path
    condition: ""path == '/etc/secrets'""
    action: deny
    priority: 10
";
        var middleware = CreateMiddleware(yaml);

        var result = middleware.EvaluateToolCall("did:mesh:test", "read",
            new Dictionary<string, object> { ["path"] = "/etc/secrets" });

        Assert.False(result.Allowed);
    }

    [Fact]
    public void EvaluateToolCall_PolicyDecisionIsAttached()
    {
        var yaml = @"
apiVersion: governance.toolkit/v1
name: decision-test
default_action: deny
rules: []
";
        var middleware = CreateMiddleware(yaml);

        var result = middleware.EvaluateToolCall("did:mesh:test", "anything");

        Assert.NotNull(result.PolicyDecision);
        Assert.False(result.PolicyDecision!.Allowed);
    }
}
