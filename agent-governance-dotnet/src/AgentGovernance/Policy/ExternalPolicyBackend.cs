// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace AgentGovernance.Policy;

/// <summary>
/// Result from evaluating an external policy backend.
/// </summary>
public sealed class ExternalPolicyDecision
{
    /// <summary>
    /// Backend identifier.
    /// </summary>
    public required string Backend { get; init; }

    /// <summary>
    /// Whether the backend allowed the request.
    /// </summary>
    public bool Allowed { get; init; }

    /// <summary>
    /// Human-readable reason for the decision.
    /// </summary>
    public required string Reason { get; init; }

    /// <summary>
    /// Evaluation time in milliseconds.
    /// </summary>
    public double EvaluationMs { get; init; }

    /// <summary>
    /// Optional backend error. Presence of an error should be treated as fail-closed.
    /// </summary>
    public string? Error { get; init; }

    /// <summary>
    /// Optional structured details.
    /// </summary>
    public Dictionary<string, object>? Metadata { get; init; }
}

/// <summary>
/// Abstraction for non-native policy backends such as OPA/Rego or Cedar.
/// </summary>
public interface IExternalPolicyBackend
{
    /// <summary>
    /// Backend name.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Evaluate the request context.
    /// </summary>
    ExternalPolicyDecision Evaluate(IReadOnlyDictionary<string, object> context);
}
