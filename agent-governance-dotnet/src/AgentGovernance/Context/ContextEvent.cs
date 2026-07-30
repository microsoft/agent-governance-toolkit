// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.ObjectModel;

namespace AgentGovernance.Context;

/// <summary>
/// Stable event-type vocabulary for accumulated context transitions.
/// </summary>
public static class ContextEventTypes
{
    /// <summary>A context envelope was created.</summary>
    public const string EnvelopeCreated = "CONTEXT_ENVELOPE_CREATED";

    /// <summary>A context envelope was updated.</summary>
    public const string EnvelopeUpdated = "CONTEXT_ENVELOPE_UPDATED";

    /// <summary>Aggregation elevated context sensitivity or restrictions.</summary>
    public const string AggregationElevated = "CONTEXT_AGGREGATION_ELEVATED";

    /// <summary>Context crossed a delegation boundary.</summary>
    public const string Delegated = "CONTEXT_DELEGATED";

    /// <summary>Context content was redacted.</summary>
    public const string Redacted = "CONTEXT_REDACTED";

    /// <summary>A derived artifact received labels.</summary>
    public const string DerivedArtifactLabeled = "DERIVED_ARTIFACT_LABELED";
}

/// <summary>
/// Immutable audit event describing one envelope transition.
/// </summary>
public sealed class ContextEvent
{
    private ContextEvent(
        string eventType,
        string agentId,
        string contextEnvelopeId,
        DataClassification previousSensitivity,
        DataClassification newSensitivity,
        IEnumerable<string> labelsAdded,
        IEnumerable<string> rulesApplied,
        IEnumerable<string> restrictionsAdded,
        DataClassification classification)
    {
        EventType = eventType;
        AgentId = agentId;
        ContextEnvelopeId = contextEnvelopeId;
        PreviousSensitivity = previousSensitivity;
        NewSensitivity = newSensitivity;
        LabelsAdded = ContextTokens.Snapshot(labelsAdded, nameof(labelsAdded));
        RulesApplied = SnapshotRules(rulesApplied);
        RestrictionsAdded = ContextTokens.Snapshot(
            restrictionsAdded,
            nameof(restrictionsAdded));
        Classification = classification;
    }

    /// <summary>Stable event type.</summary>
    public string EventType { get; }

    /// <summary>Agent responsible for the transition.</summary>
    public string AgentId { get; }

    /// <summary>Identifier of the resulting envelope.</summary>
    public string ContextEnvelopeId { get; }

    /// <summary>Sensitivity before the transition.</summary>
    public DataClassification PreviousSensitivity { get; }

    /// <summary>Sensitivity after the transition.</summary>
    public DataClassification NewSensitivity { get; }

    /// <summary>Labels added by the transition.</summary>
    public IReadOnlySet<string> LabelsAdded { get; }

    /// <summary>Applied rules in caller-supplied order.</summary>
    public IReadOnlyList<string> RulesApplied { get; }

    /// <summary>Restrictions added by the transition.</summary>
    public IReadOnlySet<string> RestrictionsAdded { get; }

    /// <summary>Classification floor protecting this event.</summary>
    public DataClassification Classification { get; }

    /// <summary>
    /// Creates a deterministic event from an envelope transition.
    /// </summary>
    public static ContextEvent Create(
        string eventType,
        string agentId,
        ContextEnvelope before,
        ContextEnvelope after,
        IEnumerable<string>? rulesApplied = null)
    {
        ContextTokens.Identifier(eventType, nameof(eventType));
        ContextTokens.Identifier(agentId, nameof(agentId));
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);

        return new ContextEvent(
            eventType,
            agentId,
            after.EnvelopeId,
            before.AggregateSensitivity,
            after.AggregateSensitivity,
            after.Labels.Except(before.Labels, StringComparer.Ordinal),
            rulesApplied ?? [],
            after.Restrictions.Except(
                before.Restrictions,
                StringComparer.Ordinal),
            DataClassificationGuard.Maximum(
                before.AggregateSensitivity,
                after.AggregateSensitivity));
    }

    private static IReadOnlyList<string> SnapshotRules(
        IEnumerable<string> rulesApplied)
    {
        ArgumentNullException.ThrowIfNull(rulesApplied);
        var snapshot = rulesApplied
            .Select(static rule => ContextTokens.Identifier(rule, nameof(rulesApplied)))
            .ToArray();
        return new ReadOnlyCollection<string>(snapshot);
    }
}
