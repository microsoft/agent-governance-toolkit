// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Audit;
using AgentGovernance.Extensions.Microsoft.Agents;
using Microsoft.Extensions.AI;
using Xunit;

namespace AgentGovernance.Tests;

public sealed class AgentFrameworkGovernanceAdapterRunTests
{
    [Fact]
    public async Task RunAsync_SinglePassEnumerable_ForwardsMessagesToInnerAgent()
    {
        var kernel = AgentFrameworkGovernanceTestHelpers.CreateKernel(
            """
            apiVersion: governance.toolkit/v1
            version: "1.0"
            name: allow-all-policy
            default_action: allow
            rules: []
            """);
        var adapter = new AgentFrameworkGovernanceAdapter(kernel);
        var agent = new AgentFrameworkGovernanceTestHelpers.TestAgent("scribe-agent");

        static IEnumerable<ChatMessage> StreamMessages()
        {
            yield return new ChatMessage(ChatRole.System, "be terse");
            yield return new ChatMessage(ChatRole.User, "draft an email");
        }

        var response = await adapter.RunAsync(
            StreamMessages(),
            session: null,
            options: null,
            agent,
            CancellationToken.None);

        Assert.True(agent.WasRun);
        Assert.Equal(2, agent.ReceivedMessages.Count);
        Assert.Equal("be terse", agent.ReceivedMessages[0].Text);
        Assert.Equal("draft an email", agent.ReceivedMessages[1].Text);
        Assert.Contains("allowed", response.Text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunAsync_DeniedRequest_ReturnsBlockedResponse_AndSkipsInnerAgent()
    {
        var kernel = AgentFrameworkGovernanceTestHelpers.CreateKernel(
            """
            apiVersion: governance.toolkit/v1
            version: "1.0"
            name: deny-transfer-policy
            default_action: allow
            rules:
              - name: block-transfer
                condition: "message == 'transfer funds'"
                action: deny
                priority: 10
            """);
        var adapter = new AgentFrameworkGovernanceAdapter(kernel);
        var agent = new AgentFrameworkGovernanceTestHelpers.TestAgent("loan-agent");
        var events = new List<GovernanceEvent>();
        kernel.OnAllEvents(events.Add);

        var response = await adapter.RunAsync(
            [new ChatMessage(ChatRole.User, "transfer funds")],
            session: null,
            options: null,
            agent,
            CancellationToken.None);

        Assert.False(agent.WasRun);
        Assert.Contains("Blocked by governance policy", response.Text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(events, governanceEvent => governanceEvent.Type == GovernanceEventType.PolicyViolation);
    }
}
