// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Threading;
using System.Threading.Tasks;

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
    /// Evaluate the request context synchronously.
    /// </summary>
    ExternalPolicyDecision Evaluate(IReadOnlyDictionary<string, object> context);

    /// <summary>
    /// Evaluate the request context asynchronously.
    /// </summary>
    /// <remarks>
    /// Default implementation wraps <see cref="Evaluate"/> in a completed
    /// <see cref="Task"/>. Backends whose evaluation involves real I/O
    /// (HTTP, subprocess wait, etc.) should override this with a genuine
    /// async path so callers in async contexts (ASP.NET handlers,
    /// background workers, agent loops) can avoid blocking a thread on
    /// the wait. Overrides must not call back into <see cref="Evaluate"/>
    /// to produce their result — that re-introduces the very
    /// sync-over-async pattern this method exists to escape.
    /// </remarks>
    /// <param name="context">Evaluation input.</param>
    /// <param name="cancellationToken">Token to cancel the evaluation.</param>
    Task<ExternalPolicyDecision> EvaluateAsync(
        IReadOnlyDictionary<string, object> context,
        CancellationToken cancellationToken = default)
        => Task.FromResult(Evaluate(context));
}
