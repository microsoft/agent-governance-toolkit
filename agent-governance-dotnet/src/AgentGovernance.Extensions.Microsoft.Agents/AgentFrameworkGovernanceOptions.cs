// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Integration;
using AgentGovernance.Policy;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

namespace AgentGovernance.Extensions.Microsoft.Agents;

/// <summary>
/// Configuration for bridging <see cref="GovernanceKernel" /> into Microsoft Agent Framework middleware.
/// </summary>
public sealed class AgentFrameworkGovernanceOptions
{
    /// <summary>
    /// Whether the adapter should attach function-call middleware in addition to run middleware.
    /// This requires an agent backed by a FunctionInvokingChatClient-compatible pipeline.
    /// </summary>
    public bool EnableFunctionMiddleware { get; set; } = true;

    /// <summary>
    /// The fallback agent DID used when no agent-specific identifier can be inferred.
    /// </summary>
    public string DefaultAgentId { get; set; } = "did:agentmesh:unknown-agent";

    /// <summary>
    /// Resolves an agent DID from the MAF agent and session for policy/audit correlation.
    /// </summary>
    public Func<AIAgent, AgentSession?, string?>? AgentIdResolver { get; set; }

    /// <summary>
    /// Extracts the message text used for run-level governance evaluation.
    /// Defaults to the last non-empty user-visible message text.
    /// </summary>
    public Func<IEnumerable<ChatMessage>, string?>? InputTextResolver { get; set; }

    /// <summary>
    /// Converts validated function arguments into the dictionary exposed to AGT policy conditions.
    /// </summary>
    public Func<FunctionInvocationContext, Dictionary<string, object>>? ToolArgumentsResolver { get; set; }

    /// <summary>
    /// Builds the user-visible response when a run is denied before the inner agent executes.
    /// </summary>
    public Func<PolicyDecision, AgentResponse>? BlockedRunResponseFactory { get; set; }

    /// <summary>
    /// Builds the tool result returned when a function call is denied by governance.
    /// </summary>
    public Func<ToolCallResult, object?>? BlockedToolResultFactory { get; set; }
}
