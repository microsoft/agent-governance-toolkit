// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Trust;

namespace AgentGovernance.Discovery;

/// <summary>
/// Registry abstraction for discovery reconciliation.
/// </summary>
public interface IDiscoveryRegistryProvider
{
    /// <summary>
    /// Return whether the agent is known to governance.
    /// </summary>
    bool IsRegistered(DiscoveredAgent agent);
}

/// <summary>
/// Reconciles discovered agents against a governance registry.
/// </summary>
public sealed class Reconciler
{
    private readonly AgentInventory _inventory;
    private readonly IDiscoveryRegistryProvider _registry;

    /// <summary>
    /// Create a new reconciler.
    /// </summary>
    public Reconciler(AgentInventory inventory, IDiscoveryRegistryProvider registry)
    {
        _inventory = inventory ?? throw new ArgumentNullException(nameof(inventory));
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
    }

    /// <summary>
    /// Reconcile discovered agents and return shadow agents.
    /// </summary>
    public IReadOnlyList<ShadowAgent> Reconcile(RiskScorer? scorer = null)
    {
        scorer ??= new RiskScorer();
        var shadows = new List<ShadowAgent>();

        foreach (var agent in _inventory.Agents)
        {
            if (_registry.IsRegistered(agent))
            {
                agent.Status = AgentStatus.Registered;
                continue;
            }

            agent.Status = AgentStatus.Shadow;
            var risk = scorer.Score(agent);
            shadows.Add(new ShadowAgent
            {
                Agent = agent,
                Risk = risk,
                RecommendedActions = BuildRecommendedActions(agent, risk)
            });
        }

        return shadows;
    }

    private static IReadOnlyList<string> BuildRecommendedActions(DiscoveredAgent agent, RiskAssessment risk)
    {
        var actions = new List<string>
        {
            "Register the agent with governance before production use."
        };

        if (string.IsNullOrWhiteSpace(agent.Owner))
        {
            actions.Add("Identify a human or team owner.");
        }

        if (string.IsNullOrWhiteSpace(agent.Did))
        {
            actions.Add("Issue a governed identity or DID for the agent.");
        }

        if (risk.Level >= RiskLevel.High)
        {
            actions.Add("Quarantine or restrict execution until governance controls are in place.");
        }

        return actions;
    }
}

/// <summary>
/// Static registry provider based on a known DID set.
/// </summary>
public sealed class StaticRegistryProvider(IEnumerable<string> knownDids) : IDiscoveryRegistryProvider
{
    private readonly HashSet<string> _knownDids = new(knownDids.Select(AgentIdentity.NormalizeDid), StringComparer.Ordinal);

    /// <inheritdoc />
    public bool IsRegistered(DiscoveredAgent agent)
    {
        return !string.IsNullOrWhiteSpace(agent.Did) && _knownDids.Contains(AgentIdentity.NormalizeDid(agent.Did));
    }
}

/// <summary>
/// Discovery registry provider backed by the current identity registry.
/// </summary>
public sealed class IdentityRegistryProvider(IdentityRegistry registry) : IDiscoveryRegistryProvider
{
    private readonly IdentityRegistry _registry = registry ?? throw new ArgumentNullException(nameof(registry));

    /// <inheritdoc />
    public bool IsRegistered(DiscoveredAgent agent)
    {
        return !string.IsNullOrWhiteSpace(agent.Did) && _registry.IsTrusted(agent.Did);
    }
}
