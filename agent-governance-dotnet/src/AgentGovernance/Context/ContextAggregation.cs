// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.ObjectModel;

namespace AgentGovernance.Context;

/// <summary>
/// Organization-authored rule over a combination of accumulated labels.
/// </summary>
public sealed class AggregationRule
{
    /// <summary>Creates an immutable aggregation rule.</summary>
    public AggregationRule(
        string name,
        IEnumerable<string> allLabels,
        DataClassification setsSensitivity,
        IEnumerable<string>? addsRestrictions = null)
    {
        Name = ContextTokens.Identifier(name, nameof(name));
        AllLabels = ContextTokens.Snapshot(allLabels, nameof(allLabels));
        SetsSensitivity = DataClassificationGuard.Defined(
            setsSensitivity,
            nameof(setsSensitivity));
        AddsRestrictions = ContextTokens.SnapshotOptional(
            addsRestrictions,
            nameof(addsRestrictions));
    }

    /// <summary>Stable rule name.</summary>
    public string Name { get; }

    /// <summary>Labels that must all be present for this rule to match.</summary>
    public IReadOnlySet<string> AllLabels { get; }

    /// <summary>Minimum sensitivity applied by this rule.</summary>
    public DataClassification SetsSensitivity { get; }

    /// <summary>Restrictions added by this rule.</summary>
    public IReadOnlySet<string> AddsRestrictions { get; }
}

/// <summary>
/// Ordered immutable collection of aggregation rules.
/// </summary>
public sealed class AggregationRuleSet
{
    /// <summary>Creates a rule set in declared evaluation order.</summary>
    public AggregationRuleSet(IEnumerable<AggregationRule>? rules = null)
    {
        var snapshot = rules?.ToArray() ?? [];
        if (snapshot.Any(static rule => rule is null))
        {
            throw new ArgumentException("Rules cannot contain null values.", nameof(rules));
        }

        Rules = new ReadOnlyCollection<AggregationRule>(snapshot);
    }

    /// <summary>Rules in deterministic evaluation order.</summary>
    public IReadOnlyList<AggregationRule> Rules { get; }

    /// <summary>
    /// Applies known rules and escalates unknown combinations at the threshold.
    /// </summary>
    public AggregationResult Evaluate(
        ContextEnvelope envelope,
        int categoryThreshold)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        if (categoryThreshold < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(categoryThreshold),
                categoryThreshold,
                "Category threshold must be positive.");
        }

        var sensitivity = envelope.AggregateSensitivity;
        var restrictions = new HashSet<string>(
            envelope.Restrictions,
            StringComparer.Ordinal);
        var applied = new List<string>();

        foreach (var rule in Rules)
        {
            if (!rule.AllLabels.IsSubsetOf(envelope.Labels))
            {
                continue;
            }

            sensitivity = DataClassificationGuard.Maximum(
                sensitivity,
                rule.SetsSensitivity);
            restrictions.UnionWith(rule.AddsRestrictions);
            applied.Add(rule.Name);
        }

        return new AggregationResult(
            sensitivity,
            restrictions,
            escalate: applied.Count == 0 && envelope.Labels.Count >= categoryThreshold,
            applied);
    }
}

/// <summary>
/// Result of evaluating an envelope against aggregation rules.
/// </summary>
public sealed class AggregationResult
{
    internal AggregationResult(
        DataClassification aggregateSensitivity,
        IEnumerable<string> restrictions,
        bool escalate,
        IEnumerable<string> rulesApplied)
    {
        AggregateSensitivity = DataClassificationGuard.Defined(
            aggregateSensitivity,
            nameof(aggregateSensitivity));
        Restrictions = ContextTokens.Snapshot(restrictions, nameof(restrictions));
        Escalate = escalate;
        RulesApplied = new ReadOnlyCollection<string>(rulesApplied.ToArray());
    }

    /// <summary>Resulting maximum sensitivity.</summary>
    public DataClassification AggregateSensitivity { get; }

    /// <summary>Resulting grow-only restrictions.</summary>
    public IReadOnlySet<string> Restrictions { get; }

    /// <summary>Whether the unknown-combination backstop requires review.</summary>
    public bool Escalate { get; }

    /// <summary>Names of matching rules in evaluation order.</summary>
    public IReadOnlyList<string> RulesApplied { get; }
}
