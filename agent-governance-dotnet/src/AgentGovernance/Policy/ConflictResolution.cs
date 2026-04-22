// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

namespace AgentGovernance.Policy;

/// <summary>
/// Strategies for resolving conflicts when multiple policy rules match a single request.
/// </summary>
public enum ConflictResolutionStrategy
{
    /// <summary>
    /// Any deny wins over any allow. Among denies, the highest priority wins.
    /// This is the safest strategy for security-critical environments.
    /// </summary>
    DenyOverrides,

    /// <summary>
    /// Any allow wins over any deny. Among allows, the highest priority wins.
    /// Use when permissiveness is preferred.
    /// </summary>
    AllowOverrides,

    /// <summary>
    /// The rule with the highest priority wins, regardless of its action.
    /// This is the default strategy.
    /// </summary>
    PriorityFirstMatch,

    /// <summary>
    /// The most specific scope wins (Agent > Tenant > Global).
    /// Ties within the same scope are broken by priority.
    /// </summary>
    MostSpecificWins
}

/// <summary>
/// Scope of a governance policy, ordered from broadest to most specific.
/// </summary>
public enum PolicyScope
{
    /// <summary>Applies to all agents in the system.</summary>
    Global = 0,

    /// <summary>Applies to agents within a specific tenant.</summary>
    Tenant = 1,

    /// <summary>Applies to a specific agent.</summary>
    Agent = 2
}

/// <summary>
/// Resolves conflicts between multiple matching policy rules using a configured strategy.
/// </summary>
public static class PolicyConflictResolver
{
    /// <summary>
    /// Resolves a list of candidate rule/decision pairs into a single winning decision.
    /// </summary>
    /// <param name="candidates">
    /// Matching rules paired with their corresponding decisions and the scope of the policy they belong to.
    /// </param>
    /// <param name="strategy">The conflict resolution strategy to use.</param>
    /// <returns>The winning <see cref="PolicyDecision"/>, or <c>null</c> if no candidates were provided.</returns>
    public static PolicyDecision? Resolve(
        IReadOnlyList<CandidateDecision> candidates,
        ConflictResolutionStrategy strategy)
    {
        if (candidates.Count == 0)
        {
            return null;
        }

        if (candidates.Count == 1)
        {
            return candidates[0].Decision;
        }

        return strategy switch
        {
            ConflictResolutionStrategy.DenyOverrides => ResolveDenyOverrides(candidates),
            ConflictResolutionStrategy.AllowOverrides => ResolveAllowOverrides(candidates),
            ConflictResolutionStrategy.PriorityFirstMatch => ResolvePriorityFirstMatch(candidates),
            ConflictResolutionStrategy.MostSpecificWins => ResolveMostSpecificWins(candidates),
            _ => ResolvePriorityFirstMatch(candidates)
        };
    }

    /// <summary>
    /// Any deny wins. Among denies, highest priority wins.
    /// If there are no denies, pick the highest priority allow.
    /// </summary>
    private static PolicyDecision ResolveDenyOverrides(IReadOnlyList<CandidateDecision> candidates)
    {
        var denies = candidates.Where(c => !c.Decision.Allowed).ToList();
        if (denies.Count > 0)
        {
            return denies.OrderByDescending(c => c.Rule.Priority).First().Decision;
        }

        return candidates.OrderByDescending(c => c.Rule.Priority).First().Decision;
    }

    /// <summary>
    /// Any allow wins. Among allows, highest priority wins.
    /// If there are no allows, pick the highest priority deny.
    /// </summary>
    private static PolicyDecision ResolveAllowOverrides(IReadOnlyList<CandidateDecision> candidates)
    {
        var allows = candidates.Where(c => c.Decision.Allowed).ToList();
        if (allows.Count > 0)
        {
            return allows.OrderByDescending(c => c.Rule.Priority).First().Decision;
        }

        return candidates.OrderByDescending(c => c.Rule.Priority).First().Decision;
    }

    /// <summary>
    /// Highest priority wins regardless of action type.
    /// </summary>
    private static PolicyDecision ResolvePriorityFirstMatch(IReadOnlyList<CandidateDecision> candidates)
    {
        return candidates.OrderByDescending(c => c.Rule.Priority).First().Decision;
    }

    /// <summary>
    /// Most specific scope wins (Agent > Tenant > Global).
    /// Ties within the same scope are broken by priority.
    /// </summary>
    private static PolicyDecision ResolveMostSpecificWins(IReadOnlyList<CandidateDecision> candidates)
    {
        return candidates
            .OrderByDescending(c => (int)c.Scope)
            .ThenByDescending(c => c.Rule.Priority)
            .First()
            .Decision;
    }

    /// <summary>
    /// Parses a <see cref="PolicyScope"/> from a string value.
    /// </summary>
    /// <param name="value">The scope string (e.g., "global", "tenant", "agent").</param>
    /// <returns>The parsed <see cref="PolicyScope"/>.</returns>
    public static PolicyScope ParseScope(string? value)
    {
        return value?.ToLowerInvariant() switch
        {
            "tenant" => PolicyScope.Tenant,
            "agent" => PolicyScope.Agent,
            _ => PolicyScope.Global
        };
    }
}

/// <summary>
/// A candidate decision produced by evaluating a single rule, annotated with
/// the rule, its decision, and the scope of the policy it belongs to.
/// </summary>
/// <param name="Rule">The matched rule.</param>
/// <param name="Decision">The decision produced by the rule.</param>
/// <param name="Scope">The scope of the policy that contains this rule.</param>
public sealed record CandidateDecision(PolicyRule Rule, PolicyDecision Decision, PolicyScope Scope);
