// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Frozen;

namespace AgentGovernance.Context;

/// <summary>
/// Immutable, versioned accumulated governance state for one workflow.
/// </summary>
public sealed class ContextEnvelope
{
    /// <summary>
    /// Creates an immutable context envelope from caller-supplied state.
    /// </summary>
    public ContextEnvelope(
        string envelopeId,
        string workflowId,
        IEnumerable<string>? labels = null,
        DataClassification aggregateSensitivity = DataClassification.Public,
        IEnumerable<string>? restrictions = null,
        int version = 0,
        string? parentEnvelopeId = null,
        DateTimeOffset? createdAt = null)
    {
        EnvelopeId = ContextTokens.Identifier(envelopeId, nameof(envelopeId));
        WorkflowId = ContextTokens.Identifier(workflowId, nameof(workflowId));
        Labels = ContextTokens.SnapshotOptional(labels, nameof(labels));
        AggregateSensitivity = DataClassificationGuard.Defined(
            aggregateSensitivity,
            nameof(aggregateSensitivity));
        Restrictions = ContextTokens.SnapshotOptional(restrictions, nameof(restrictions));

        if (version < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(version),
                version,
                "Envelope version cannot be negative.");
        }

        Version = version;
        ParentEnvelopeId = parentEnvelopeId is null
            ? null
            : ContextTokens.Identifier(parentEnvelopeId, nameof(parentEnvelopeId));
        CreatedAt = createdAt;
    }

    /// <summary>Stable identifier for this envelope lineage.</summary>
    public string EnvelopeId { get; }

    /// <summary>Workflow correlation identifier.</summary>
    public string WorkflowId { get; }

    /// <summary>Accumulated organization-authored labels.</summary>
    public IReadOnlySet<string> Labels { get; }

    /// <summary>Running maximum sensitivity.</summary>
    public DataClassification AggregateSensitivity { get; }

    /// <summary>Grow-only restriction tokens.</summary>
    public IReadOnlySet<string> Restrictions { get; }

    /// <summary>Monotonic envelope version.</summary>
    public int Version { get; }

    /// <summary>Parent envelope identifier for delegated context.</summary>
    public string? ParentEnvelopeId { get; }

    /// <summary>Optional timestamp supplied by the caller.</summary>
    public DateTimeOffset? CreatedAt { get; }

    /// <summary>
    /// Returns the next version after joining labels and sensitivity.
    /// </summary>
    public ContextEnvelope Fold(
        IEnumerable<string> newLabels,
        DataClassification newSensitivity)
    {
        var nextLabels = ContextTokens.Union(
            Labels,
            newLabels,
            nameof(newLabels));

        return Copy(
            labels: nextLabels,
            aggregateSensitivity: DataClassificationGuard.Maximum(
                AggregateSensitivity,
                DataClassificationGuard.Defined(newSensitivity, nameof(newSensitivity))),
            version: checked(Version + 1));
    }

    /// <summary>
    /// Returns the next version after adding grow-only restrictions.
    /// </summary>
    public ContextEnvelope ApplyRestrictions(IEnumerable<string> restrictions)
    {
        var nextRestrictions = ContextTokens.Union(
            Restrictions,
            restrictions,
            nameof(restrictions));

        return Copy(
            restrictions: nextRestrictions,
            version: checked(Version + 1));
    }

    /// <summary>
    /// Projects this envelope onto its opaque cross-boundary reference.
    /// </summary>
    public EnvelopeReference ToReference() =>
        new(EnvelopeId, AggregateSensitivity);

    internal ContextEnvelope WithAggregateSensitivity(DataClassification sensitivity) =>
        Copy(aggregateSensitivity: sensitivity);

    private ContextEnvelope Copy(
        IEnumerable<string>? labels = null,
        DataClassification? aggregateSensitivity = null,
        IEnumerable<string>? restrictions = null,
        int? version = null) =>
        new(
            EnvelopeId,
            WorkflowId,
            labels ?? Labels,
            aggregateSensitivity ?? AggregateSensitivity,
            restrictions ?? Restrictions,
            version ?? Version,
            ParentEnvelopeId,
            CreatedAt);
}

internal static class ContextTokens
{
    private static readonly IReadOnlySet<string> Empty =
        Array.Empty<string>().ToFrozenSet(StringComparer.Ordinal);

    internal static string Identifier(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (!string.Equals(value, value.Trim(), StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Value cannot contain leading or trailing whitespace.",
                parameterName);
        }

        return value;
    }

    internal static IReadOnlySet<string> SnapshotOptional(
        IEnumerable<string>? tokens,
        string parameterName) =>
        tokens is null ? Empty : Snapshot(tokens, parameterName);

    internal static IReadOnlySet<string> Snapshot(
        IEnumerable<string> tokens,
        string parameterName)
    {
        ArgumentNullException.ThrowIfNull(tokens, parameterName);

        var snapshot = new HashSet<string>(StringComparer.Ordinal);
        foreach (var token in tokens)
        {
            snapshot.Add(Identifier(token, parameterName));
        }

        return snapshot.ToFrozenSet(StringComparer.Ordinal);
    }

    internal static IReadOnlySet<string> Union(
        IEnumerable<string> existing,
        IEnumerable<string> added,
        string parameterName)
    {
        ArgumentNullException.ThrowIfNull(added, parameterName);
        return Snapshot(existing.Concat(added), parameterName);
    }
}

/// <summary>
/// Opaque cross-boundary reference to accumulated governance context.
/// </summary>
public sealed class EnvelopeReference
{
    /// <summary>Creates an opaque envelope reference.</summary>
    public EnvelopeReference(
        string envelopeId,
        DataClassification sensitivity)
    {
        EnvelopeId = ContextTokens.Identifier(envelopeId, nameof(envelopeId));
        Sensitivity = DataClassificationGuard.Defined(
            sensitivity,
            nameof(sensitivity));
    }

    /// <summary>Opaque envelope lineage identifier.</summary>
    public string EnvelopeId { get; }

    /// <summary>Coarse sensitivity tier used to select a policy path.</summary>
    public DataClassification Sensitivity { get; }
}
