// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Audit;
using AgentGovernance.Extensions.Microsoft.Agents;
using Microsoft.Extensions.AI;
using Xunit;

namespace AgentGovernance.Tests;

public sealed class AgentFrameworkGovernanceAdapterFunctionTests
{
    [Fact]
    public async Task InvokeFunctionAsync_DeniedTool_TerminatesInvocation()
    {
        var kernel = AgentFrameworkGovernanceTestHelpers.CreateKernel(
            """
            apiVersion: governance.toolkit/v1
            version: "1.0"
            name: deny-deploy-policy
            default_action: allow
            rules:
              - name: block-deploy
                condition: "tool_name == 'deploy_prod'"
                action: deny
                priority: 10
            """);
        var adapter = new AgentFrameworkGovernanceAdapter(kernel);
        var agent = new AgentFrameworkGovernanceTestHelpers.TestAgent("deploy-agent");
        var context = new FunctionInvocationContext
        {
            Function = AIFunctionFactory.Create(
                (Action)(() => { }),
                "deploy_prod",
                "Deploys to production",
                serializerOptions: null),
            Arguments = new AIFunctionArguments
            {
                ["environment"] = "prod"
            }
        };
        var nextCalled = false;

        var result = await adapter.InvokeFunctionAsync(
            agent,
            context,
            (_, _) =>
            {
                nextCalled = true;
                return ValueTask.FromResult<object?>("should not execute");
            },
            CancellationToken.None);

        Assert.False(nextCalled);
        Assert.True(context.Terminate);
        var text = Assert.IsType<string>(result);
        Assert.Contains("Blocked by governance policy", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task InvokeFunctionAsync_UsesOnlyFrameworkTrustedSkillMetadata()
    {
        var kernel = AgentFrameworkGovernanceTestHelpers.CreateKernel(
            """
            apiVersion: governance.toolkit/v1
            version: "1.0"
            name: allow-all-policy
            default_action: allow
            rules: []
            """);
        var events = new List<GovernanceEvent>();
        kernel.OnAllEvents(events.Add);
        var adapter = new AgentFrameworkGovernanceAdapter(
            kernel,
            new AgentFrameworkGovernanceOptions
            {
                TrustedSkillMetadataResolver = (_, _) =>
                    TrustedSkillMetadataSource.Create("framework_search", "agent_framework")
            });
        var context = new FunctionInvocationContext
        {
            Function = AIFunctionFactory.Create((Action)(() => { }), "search", "Searches records"),
            Arguments = new AIFunctionArguments
            {
                ["skill_name"] = "spoofed_skill",
                ["skill_origin"] = "untrusted_request",
                ["query"] = "invoice"
            }
        };

        await adapter.InvokeFunctionAsync(
            new AgentFrameworkGovernanceTestHelpers.TestAgent("search-agent"),
            context,
            (_, _) => ValueTask.FromResult<object?>("ok"),
            CancellationToken.None);

        var auditEvent = Assert.Single(events, e => e.Type == GovernanceEventType.PolicyCheck);
        Assert.Equal("framework_search", auditEvent.Data["skill_name"]);
        Assert.Equal("agent_framework", auditEvent.Data["skill_origin"]);
        Assert.Equal("trusted", auditEvent.Data["provenance_source_trust"]);
        Assert.Equal(64, Assert.IsType<string>(auditEvent.Data["context_hash_before"]).Length);
        Assert.False(auditEvent.Data.ContainsKey("context_hash_after"));
        Assert.Equal(TimeSpan.Zero, auditEvent.Timestamp.Offset);
    }

    [Fact]
    public async Task InvokeFunctionAsync_DoesNotPromotePayloadSkillFieldsToTrustedMetadata()
    {
        var kernel = AgentFrameworkGovernanceTestHelpers.CreateKernel(
            """
            apiVersion: governance.toolkit/v1
            version: "1.0"
            name: allow-all-policy
            default_action: allow
            rules: []
            """);
        var events = new List<GovernanceEvent>();
        kernel.OnAllEvents(events.Add);
        var adapter = new AgentFrameworkGovernanceAdapter(kernel);
        var context = new FunctionInvocationContext
        {
            Function = AIFunctionFactory.Create((Action)(() => { }), "search", "Searches records"),
            Arguments = new AIFunctionArguments
            {
                ["skill_name"] = "spoofed_skill",
                ["skill_origin"] = "untrusted_request"
            }
        };

        await adapter.InvokeFunctionAsync(
            new AgentFrameworkGovernanceTestHelpers.TestAgent("search-agent"),
            context,
            (_, _) => ValueTask.FromResult<object?>("ok"),
            CancellationToken.None);

        var auditEvent = Assert.Single(events, e => e.Type == GovernanceEventType.PolicyCheck);
        Assert.False(auditEvent.Data.ContainsKey("skill_name"));
        Assert.False(auditEvent.Data.ContainsKey("skill_origin"));
        Assert.False(auditEvent.Data.ContainsKey("provenance_source_trust"));
        Assert.Equal(64, Assert.IsType<string>(auditEvent.Data["context_hash_before"]).Length);
    }
}
