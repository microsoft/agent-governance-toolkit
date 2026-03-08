// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Audit;
using AgentGovernance.Policy;
using Xunit;

namespace AgentGovernance.Tests;

public class GovernanceKernelTests
{
    private const string TestPolicy = @"
apiVersion: governance.toolkit/v1
name: kernel-test-policy
default_action: deny
rules:
  - name: allow-safe-tools
    condition: ""tool_name == 'read'""
    action: allow
    priority: 10
  - name: block-writes
    condition: ""tool_name == 'write'""
    action: deny
    priority: 5
";

    [Fact]
    public void Constructor_DefaultOptions_CreatesKernel()
    {
        var kernel = new GovernanceKernel();

        Assert.NotNull(kernel.PolicyEngine);
        Assert.NotNull(kernel.AuditEmitter);
        Assert.NotNull(kernel.Middleware);
        Assert.True(kernel.AuditEnabled);
    }

    [Fact]
    public void LoadPolicyFromYaml_LoadsSuccessfully()
    {
        var kernel = new GovernanceKernel();
        kernel.LoadPolicyFromYaml(TestPolicy);

        var policies = kernel.PolicyEngine.ListPolicies();
        Assert.Single(policies);
        Assert.Equal("kernel-test-policy", policies[0].Name);
    }

    [Fact]
    public void EvaluateToolCall_AllowedTool_ReturnsAllowed()
    {
        var kernel = new GovernanceKernel();
        kernel.LoadPolicyFromYaml(TestPolicy);

        var result = kernel.EvaluateToolCall("did:mesh:test", "read");
        Assert.True(result.Allowed);
    }

    [Fact]
    public void EvaluateToolCall_BlockedTool_ReturnsDenied()
    {
        var kernel = new GovernanceKernel();
        kernel.LoadPolicyFromYaml(TestPolicy);

        var result = kernel.EvaluateToolCall("did:mesh:test", "write");
        Assert.False(result.Allowed);
    }

    [Fact]
    public void OnEvent_ReceivesEmittedEvents()
    {
        var kernel = new GovernanceKernel();
        kernel.LoadPolicyFromYaml(TestPolicy);

        GovernanceEvent? received = null;
        kernel.OnEvent(GovernanceEventType.ToolCallBlocked, e => received = e);

        kernel.EvaluateToolCall("did:mesh:test", "write");

        Assert.NotNull(received);
        Assert.Equal(GovernanceEventType.ToolCallBlocked, received!.Type);
    }

    [Fact]
    public void OnAllEvents_ReceivesAllEventTypes()
    {
        var kernel = new GovernanceKernel();
        kernel.LoadPolicyFromYaml(TestPolicy);

        var events = new List<GovernanceEvent>();
        kernel.OnAllEvents(e => events.Add(e));

        kernel.EvaluateToolCall("did:mesh:test", "read");
        kernel.EvaluateToolCall("did:mesh:test", "write");

        Assert.True(events.Count >= 2);
    }

    [Fact]
    public void Options_ConflictStrategy_IsRespected()
    {
        var kernel = new GovernanceKernel(new GovernanceOptions
        {
            ConflictStrategy = ConflictResolutionStrategy.DenyOverrides
        });

        Assert.Equal(ConflictResolutionStrategy.DenyOverrides, kernel.PolicyEngine.ConflictStrategy);
    }

    [Fact]
    public void Options_EnableAuditFalse_SetsFlag()
    {
        var kernel = new GovernanceKernel(new GovernanceOptions
        {
            EnableAudit = false
        });

        Assert.False(kernel.AuditEnabled);
    }
}
