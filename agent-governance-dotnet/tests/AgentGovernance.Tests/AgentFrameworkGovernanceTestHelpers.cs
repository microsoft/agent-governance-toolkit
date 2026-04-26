// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

namespace AgentGovernance.Tests;

internal static class AgentFrameworkGovernanceTestHelpers
{
    public static GovernanceKernel CreateKernel(string yaml)
    {
        var kernel = new GovernanceKernel();
        kernel.LoadPolicyFromYaml(yaml);
        return kernel;
    }

    internal sealed class TestAgent : AIAgent
    {
        public TestAgent(string name)
        {
            Name = name;
        }

        public bool WasRun { get; private set; }

        public override string Name { get; }

        protected override string IdCore => $"did:test:{Name}";

        protected override Task<AgentResponse> RunCoreAsync(
            IEnumerable<ChatMessage> messages,
            AgentSession? session,
            AgentRunOptions? options,
            CancellationToken cancellationToken)
        {
            WasRun = true;
            return Task.FromResult(new AgentResponse(new ChatMessage(ChatRole.Assistant, "allowed")));
        }

        protected override async IAsyncEnumerable<AgentResponseUpdate> RunCoreStreamingAsync(
            IEnumerable<ChatMessage> messages,
            AgentSession? session,
            AgentRunOptions? options,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            WasRun = true;
            yield return new AgentResponseUpdate(ChatRole.Assistant, "allowed");
            await Task.CompletedTask;
        }

        protected override ValueTask<AgentSession> CreateSessionCoreAsync(CancellationToken cancellationToken)
            => throw new NotSupportedException();

        protected override ValueTask<JsonElement> SerializeSessionCoreAsync(
            AgentSession session,
            JsonSerializerOptions? options,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();

        protected override ValueTask<AgentSession> DeserializeSessionCoreAsync(
            JsonElement sessionState,
            JsonSerializerOptions? options,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();
    }
}
