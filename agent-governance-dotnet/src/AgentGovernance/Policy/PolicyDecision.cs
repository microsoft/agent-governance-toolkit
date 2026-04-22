// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace AgentGovernance.Policy;

/// <summary>
/// Represents the result of evaluating a request against one or more governance policies.
/// </summary>
public sealed class PolicyDecision
{
    /// <summary>
    /// Whether the request is allowed to proceed.
    /// </summary>
    public bool Allowed { get; init; }

    /// <summary>
    /// The resulting action string (e.g., "allow", "deny", "warn", "require_approval").
    /// </summary>
    public required string Action { get; init; }

    /// <summary>
    /// Name of the rule that produced this decision, or <c>null</c> if the decision
    /// was derived from the policy default action.
    /// </summary>
    public string? MatchedRule { get; init; }

    /// <summary>
    /// Name of the policy that produced this decision.
    /// </summary>
    public string? PolicyName { get; init; }

    /// <summary>
    /// Human-readable reason explaining why this decision was made.
    /// </summary>
    public required string Reason { get; init; }

    /// <summary>
    /// List of approvers required when the action is <c>require_approval</c>.
    /// Empty when not applicable.
    /// </summary>
    public List<string> Approvers { get; init; } = new();

    /// <summary>
    /// Indicates whether the request was rate-limited.
    /// </summary>
    public bool RateLimited { get; init; }

    /// <summary>
    /// Timestamp when the current rate limit window resets, if applicable.
    /// </summary>
    public DateTime? RateLimitReset { get; init; }

    /// <summary>
    /// Time when evaluation started.
    /// </summary>
    public DateTime EvaluatedAt { get; init; } = DateTime.UtcNow;

    /// <summary>
    /// Time in milliseconds taken to evaluate the policy decision.
    /// </summary>
    public double EvaluationMs { get; init; }

    /// <summary>
    /// Additional decision context supplied by advanced resolvers.
    /// </summary>
    public Dictionary<string, object>? Metadata { get; init; }

    /// <summary>
    /// Creates a default "allowed" decision (used when no rules match and default is allow).
    /// </summary>
    public static PolicyDecision AllowDefault(double evaluationMs = 0)
        => AllowDefault(DateTime.UtcNow, evaluationMs);

    /// <summary>
    /// Creates a default "allowed" decision with an explicit evaluation timestamp.
    /// </summary>
    public static PolicyDecision AllowDefault(DateTime evaluatedAt, double evaluationMs = 0) => new()
    {
        Allowed = true,
        Action = "allow",
        Reason = "No matching rules; default action is allow.",
        EvaluatedAt = evaluatedAt,
        EvaluationMs = evaluationMs
    };

    /// <summary>
    /// Creates a default "denied" decision (used when no rules match and default is deny).
    /// </summary>
    public static PolicyDecision DenyDefault(double evaluationMs = 0)
        => DenyDefault(DateTime.UtcNow, evaluationMs);

    /// <summary>
    /// Creates a default "denied" decision with an explicit evaluation timestamp.
    /// </summary>
    public static PolicyDecision DenyDefault(DateTime evaluatedAt, double evaluationMs = 0) => new()
    {
        Allowed = false,
        Action = "deny",
        Reason = "No matching rules; default action is deny.",
        EvaluatedAt = evaluatedAt,
        EvaluationMs = evaluationMs
    };

    /// <summary>
    /// Creates a decision from a matched <see cref="PolicyRule"/>.
    /// </summary>
    public static PolicyDecision FromRule(
        PolicyRule rule,
        string policyName = "",
        DateTime? evaluatedAt = null,
        double evaluationMs = 0,
        DateTime? rateLimitReset = null,
        Dictionary<string, object>? metadata = null)
    {
        var action = rule.Action;
        return new PolicyDecision
        {
            Allowed = action is PolicyAction.Allow or PolicyAction.Warn or PolicyAction.Log,
            Action = action.ToString().ToLowerInvariant(),
            MatchedRule = rule.Name,
            PolicyName = string.IsNullOrWhiteSpace(policyName) ? null : policyName,
            Reason = action == PolicyAction.RateLimit
                ? $"Matched rate-limit rule '{rule.Name}'."
                : $"Matched rule '{rule.Name}' with action '{action}'.",
            Approvers = action == PolicyAction.RequireApproval ? new List<string>(rule.Approvers) : new(),
            RateLimited = action == PolicyAction.RateLimit,
            RateLimitReset = rateLimitReset,
            EvaluatedAt = evaluatedAt ?? DateTime.UtcNow,
            EvaluationMs = evaluationMs,
            Metadata = metadata
        };
    }
}
