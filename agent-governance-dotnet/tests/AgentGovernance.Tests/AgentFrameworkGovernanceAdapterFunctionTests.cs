// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
}
