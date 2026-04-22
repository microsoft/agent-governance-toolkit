// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

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
    /// Time in milliseconds taken to evaluate the policy decision.
    /// </summary>
    public double EvaluationMs { get; init; }

    /// <summary>
    /// Creates a default "allowed" decision (used when no rules match and default is allow).
    /// </summary>
    /// <param name="evaluationMs">Evaluation duration in milliseconds.</param>
    /// <returns>A new <see cref="PolicyDecision"/> indicating the request is allowed.</returns>
    public static PolicyDecision AllowDefault(double evaluationMs = 0) => new()
    {
        Allowed = true,
        Action = "allow",
        Reason = "No matching rules; default action is allow.",
        EvaluationMs = evaluationMs
    };

    /// <summary>
    /// Creates a default "denied" decision (used when no rules match and default is deny).
    /// </summary>
    /// <param name="evaluationMs">Evaluation duration in milliseconds.</param>
    /// <returns>A new <see cref="PolicyDecision"/> indicating the request is denied.</returns>
    public static PolicyDecision DenyDefault(double evaluationMs = 0) => new()
    {
        Allowed = false,
        Action = "deny",
        Reason = "No matching rules; default action is deny.",
        EvaluationMs = evaluationMs
    };

    /// <summary>
    /// Creates a decision from a matched <see cref="PolicyRule"/>.
    /// </summary>
    /// <param name="rule">The rule that matched.</param>
    /// <param name="evaluationMs">Evaluation duration in milliseconds.</param>
    /// <returns>A new <see cref="PolicyDecision"/> derived from the rule.</returns>
    public static PolicyDecision FromRule(PolicyRule rule, double evaluationMs = 0)
    {
        var action = rule.Action;
        return new PolicyDecision
        {
            Allowed = action is PolicyAction.Allow or PolicyAction.Warn or PolicyAction.Log,
            Action = action.ToString().ToLowerInvariant(),
            MatchedRule = rule.Name,
            Reason = $"Matched rule '{rule.Name}' with action '{action}'.",
            Approvers = action == PolicyAction.RequireApproval ? new List<string>(rule.Approvers) : new(),
            RateLimited = action == PolicyAction.RateLimit,
            EvaluationMs = evaluationMs
        };
    }
}
