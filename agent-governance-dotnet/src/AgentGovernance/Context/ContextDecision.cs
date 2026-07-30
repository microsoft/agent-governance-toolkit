// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.ObjectModel;
using AgentGovernance.Policy;

namespace AgentGovernance.Context;

/// <summary>
/// Governance-level outcome of a context-aware decision.
/// </summary>
public enum ContextOutcome
{
    /// <summary>Allow the action.</summary>
    Allow,

    /// <summary>Allow only with enforceable obligations.</summary>
    Constrain,

    /// <summary>Deny the action.</summary>
    Deny,

    /// <summary>Stop and require review.</summary>
    Escalate
}

/// <summary>
/// One restriction obligation carried by a constrained decision.
/// </summary>
public sealed class Obligation
{
    /// <summary>Creates an immutable obligation.</summary>
    public Obligation(string key, bool satisfied = false)
    {
        Key = ContextTokens.Identifier(key, nameof(key));
        Satisfied = satisfied;
    }

    /// <summary>Restriction key to enforce.</summary>
    public string Key { get; }

    /// <summary>Whether the obligation has already been satisfied.</summary>
    public bool Satisfied { get; }
}

/// <summary>
/// Immutable obligations and result labels carried by a decision.
/// </summary>
public sealed class ObligationSet
{
    /// <summary>Creates an immutable obligation set.</summary>
    public ObligationSet(
        IEnumerable<Obligation>? obligations = null,
        IEnumerable<string>? resultLabels = null)
    {
        var snapshot = obligations?.ToArray() ?? [];
        if (snapshot.Any(static obligation => obligation is null))
        {
            throw new ArgumentException(
                "Obligations cannot contain null values.",
                nameof(obligations));
        }

        Obligations = new ReadOnlyCollection<Obligation>(snapshot);
        ResultLabels = ContextTokens.SnapshotOptional(
            resultLabels,
            nameof(resultLabels));
    }

    /// <summary>Declared obligations in deterministic order.</summary>
    public IReadOnlyList<Obligation> Obligations { get; }

    /// <summary>Labels produced by the governed action.</summary>
    public IReadOnlySet<string> ResultLabels { get; }

    /// <summary>Whether every declared obligation is satisfied.</summary>
    public bool AllSatisfied => Obligations.All(static obligation => obligation.Satisfied);
}

/// <summary>
/// Context-aware decision and the obligations it carries.
/// </summary>
public sealed class ContextDecision
{
    /// <summary>Creates an immutable context decision.</summary>
    public ContextDecision(
        ContextOutcome outcome,
        ObligationSet obligations,
        DataClassification aggregateSensitivity,
        string reason = "")
    {
        if (!Enum.IsDefined(outcome))
        {
            throw new ArgumentOutOfRangeException(
                nameof(outcome),
                outcome,
                "Outcome must be a defined ContextOutcome value.");
        }

        ArgumentNullException.ThrowIfNull(obligations);
        ArgumentNullException.ThrowIfNull(reason);

        Outcome = outcome;
        Obligations = obligations;
        AggregateSensitivity = DataClassificationGuard.Defined(
            aggregateSensitivity,
            nameof(aggregateSensitivity));
        Reason = reason;
    }

    /// <summary>Governance-level outcome.</summary>
    public ContextOutcome Outcome { get; }

    /// <summary>Obligations carried by this decision.</summary>
    public ObligationSet Obligations { get; }

    /// <summary>Accumulated sensitivity at decision time.</summary>
    public DataClassification AggregateSensitivity { get; }

    /// <summary>Human-readable decision reason.</summary>
    public string Reason { get; }

    /// <summary>
    /// Maps this decision to the existing policy action surface.
    /// </summary>
    public PolicyAction ToPolicyAction(bool hasObligationChannel) =>
        Outcome switch
        {
            ContextOutcome.Allow => PolicyAction.Allow,
            ContextOutcome.Deny => PolicyAction.Deny,
            ContextOutcome.Escalate => PolicyAction.RequireApproval,
            ContextOutcome.Constrain when hasObligationChannel => PolicyAction.Allow,
            ContextOutcome.Constrain
                when Obligations.Obligations.Count > 0 && Obligations.AllSatisfied =>
                PolicyAction.Allow,
            _ => PolicyAction.Deny
        };
}
