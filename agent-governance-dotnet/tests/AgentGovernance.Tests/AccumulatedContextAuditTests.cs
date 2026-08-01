// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Context;
using Xunit;

namespace AgentGovernance.Tests;

public sealed class AccumulatedContextAuditTests
{
    [Fact]
    public void EnvelopeReference_ExposesOnlyOpaqueIdAndSensitivity()
    {
        var envelope = Envelope(
            "env-after",
            labels: ["pii", "financial"],
            sensitivity: DataClassification.Restricted,
            restrictions: ["no_external_export"],
            version: 7);

        var reference = envelope.ToReference();

        Assert.Equal("env-after", reference.EnvelopeId);
        Assert.Equal(DataClassification.Restricted, reference.Sensitivity);
        Assert.Equal(
            ["EnvelopeId", "Sensitivity"],
            typeof(EnvelopeReference)
                .GetProperties()
                .Select(static property => property.Name)
                .Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Create_BuildsExactDeterministicTransitionDelta()
    {
        var before = Envelope(
            "env-before",
            labels: ["pii"],
            sensitivity: DataClassification.Confidential,
            restrictions: ["retain_audit"],
            version: 2);
        var after = Envelope(
            "env-after",
            labels: ["pii", "financial"],
            sensitivity: DataClassification.Restricted,
            restrictions: ["retain_audit", "no_external_export"],
            version: 4);
        var rules = new List<string>
        {
            "pii_financial_restricted",
            "financial_export_control"
        };

        var auditEvent = ContextEvent.Create(
            ContextEventTypes.AggregationElevated,
            "did:mesh:agent-1",
            before,
            after,
            rules);
        rules.Clear();

        Assert.Equal(
            ContextEventTypes.AggregationElevated,
            auditEvent.EventType);
        Assert.Equal("did:mesh:agent-1", auditEvent.AgentId);
        Assert.Equal("env-after", auditEvent.ContextEnvelopeId);
        Assert.Equal(
            DataClassification.Confidential,
            auditEvent.PreviousSensitivity);
        Assert.Equal(
            DataClassification.Restricted,
            auditEvent.NewSensitivity);
        Assert.True(auditEvent.LabelsAdded.SetEquals(["financial"]));
        Assert.Equal(
            ["pii_financial_restricted", "financial_export_control"],
            auditEvent.RulesApplied);
        Assert.True(
            auditEvent.RestrictionsAdded.SetEquals(["no_external_export"]));
        Assert.Equal(DataClassification.Restricted, auditEvent.Classification);
        Assert.DoesNotContain(
            typeof(ContextEvent).GetProperties(),
            static property => property.Name.Contains(
                "Time",
                StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Create_UsesMaximumSensitivityAsEventClassification()
    {
        var auditEvent = ContextEvent.Create(
            ContextEventTypes.Redacted,
            "did:mesh:agent-1",
            Envelope(
                "env-before",
                sensitivity: DataClassification.TopSecret),
            Envelope(
                "env-after",
                sensitivity: DataClassification.Internal));

        Assert.Equal(DataClassification.TopSecret, auditEvent.Classification);
        Assert.Equal(DataClassification.Internal, auditEvent.NewSensitivity);
    }

    [Fact]
    public void ContextEventTypes_MatchStablePythonVocabulary()
    {
        Assert.Equal("CONTEXT_ENVELOPE_CREATED", ContextEventTypes.EnvelopeCreated);
        Assert.Equal("CONTEXT_ENVELOPE_UPDATED", ContextEventTypes.EnvelopeUpdated);
        Assert.Equal("CONTEXT_AGGREGATION_ELEVATED", ContextEventTypes.AggregationElevated);
        Assert.Equal("CONTEXT_DELEGATED", ContextEventTypes.Delegated);
        Assert.Equal("CONTEXT_REDACTED", ContextEventTypes.Redacted);
        Assert.Equal("DERIVED_ARTIFACT_LABELED", ContextEventTypes.DerivedArtifactLabeled);
    }

    [Fact]
    public void Create_RejectsMalformedAuditIdentityAndRules()
    {
        var envelope = Envelope("env-1");

        Assert.Throws<ArgumentException>(
            () => ContextEvent.Create("", "did:mesh:agent-1", envelope, envelope));
        Assert.Throws<ArgumentException>(
            () => ContextEvent.Create(
                ContextEventTypes.EnvelopeUpdated,
                " ",
                envelope,
                envelope));
        Assert.Throws<ArgumentException>(
            () => ContextEvent.Create(
                ContextEventTypes.EnvelopeUpdated,
                "did:mesh:agent-1",
                envelope,
                envelope,
                [""]));
    }

    private static ContextEnvelope Envelope(
        string envelopeId,
        IEnumerable<string>? labels = null,
        DataClassification sensitivity = DataClassification.Public,
        IEnumerable<string>? restrictions = null,
        int version = 0) =>
        new(
            envelopeId,
            "workflow-audit",
            labels,
            sensitivity,
            restrictions,
            version,
            createdAt: new DateTimeOffset(2026, 7, 27, 5, 0, 0, TimeSpan.Zero));
}
