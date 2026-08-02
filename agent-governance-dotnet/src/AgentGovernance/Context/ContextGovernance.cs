// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace AgentGovernance.Context;

/// <summary>
/// Pure operations over accumulated governance context.
/// </summary>
public static class ContextGovernance
{
    private static readonly IReadOnlyDictionary<string, string> RestrictedActions =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["export"] = "no_external_export",
            ["delegate"] = "no_external_delegation",
            ["memory_write"] = "no_memory_write"
        };

    /// <summary>
    /// Folds an action's actual result into an envelope and reapplies aggregation.
    /// </summary>
    public static ContextEnvelope Accumulate(
        ContextEnvelope envelope,
        IEnumerable<string> resultLabels,
        DataClassification resultSensitivity,
        AggregationRuleSet ruleSet,
        int categoryThreshold)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(ruleSet);

        var folded = envelope.Fold(resultLabels, resultSensitivity);
        var aggregation = ruleSet.Evaluate(folded, categoryThreshold);
        var raised = folded.WithAggregateSensitivity(
            aggregation.AggregateSensitivity);

        return raised.ApplyRestrictions(aggregation.Restrictions);
    }

    /// <summary>
    /// Gates an action against an already-accumulated envelope.
    /// </summary>
    public static ContextDecision DecideNext(
        ContextEnvelope envelope,
        string action,
        AggregationRuleSet ruleSet,
        int categoryThreshold,
        DataClassification restrictedFloor = DataClassification.Restricted)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(ruleSet);
        ContextTokens.Identifier(action, nameof(action));
        DataClassificationGuard.Defined(restrictedFloor, nameof(restrictedFloor));

        var aggregation = ruleSet.Evaluate(envelope, categoryThreshold);
        if (aggregation.Escalate)
        {
            return new ContextDecision(
                ContextOutcome.Escalate,
                new ObligationSet(resultLabels: envelope.Labels),
                aggregation.AggregateSensitivity,
                "aggregation threshold crossed with no governing rule");
        }

        RestrictedActions.TryGetValue(action, out var gatingRestriction);
        var restrictionPresent = gatingRestriction is not null
            && envelope.Restrictions.Contains(gatingRestriction);
        var floorTriggered = gatingRestriction is not null
            && aggregation.AggregateSensitivity >= restrictedFloor;

        if (restrictionPresent || floorTriggered)
        {
            var obligations = envelope.Restrictions
                .Order(StringComparer.Ordinal)
                .Select(static restriction => new Obligation(restriction));
            var reason = restrictionPresent
                ? $"action '{action}' restricted by '{gatingRestriction}'"
                : $"action '{action}' gated by sensitivity floor";

            return new ContextDecision(
                ContextOutcome.Constrain,
                new ObligationSet(obligations, envelope.Labels),
                aggregation.AggregateSensitivity,
                reason);
        }

        return new ContextDecision(
            ContextOutcome.Allow,
            new ObligationSet(resultLabels: envelope.Labels),
            aggregation.AggregateSensitivity);
    }

    /// <summary>
    /// Returns the grow-only union of parent and child-declared restrictions.
    /// </summary>
    public static IReadOnlySet<string> MergeRestrictions(
        ContextEnvelope parent,
        IEnumerable<string> childDeclared)
    {
        ArgumentNullException.ThrowIfNull(parent);
        return ContextTokens.Union(
            parent.Restrictions,
            childDeclared,
            nameof(childDeclared));
    }
}
