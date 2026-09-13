// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Context;
using Xunit;

namespace AgentGovernance.Tests;

public sealed class AccumulatedContextClassificationTests
{
    [Fact]
    public void DataClassification_UsesStableOrderedVocabulary()
    {
        Assert.Collection(
            Enum.GetValues<DataClassification>(),
            value => Assert.Equal((DataClassification.Public, 0), (value, (int)value)),
            value => Assert.Equal((DataClassification.Internal, 1), (value, (int)value)),
            value => Assert.Equal((DataClassification.Confidential, 2), (value, (int)value)),
            value => Assert.Equal((DataClassification.Restricted, 3), (value, (int)value)),
            value => Assert.Equal((DataClassification.TopSecret, 4), (value, (int)value)));
    }

    [Fact]
    public void ContextEnvelope_RejectsUndefinedClassification()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new ContextEnvelope(
                "env-1",
                "workflow-1",
                aggregateSensitivity: (DataClassification)99));
    }
}

public sealed class AccumulatedContextEnvelopeTests
{
    private static readonly DateTimeOffset CreatedAt =
        new(2026, 7, 27, 5, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Constructor_SnapshotsInputsAndPreservesCallerTimestamp()
    {
        var labels = new HashSet<string>(StringComparer.Ordinal) { "pii" };
        var restrictions = new HashSet<string>(StringComparer.Ordinal) { "no_memory_write" };

        var envelope = new ContextEnvelope(
            "env-1",
            "workflow-1",
            labels,
            DataClassification.Internal,
            restrictions,
            version: 7,
            parentEnvelopeId: "parent-1",
            createdAt: CreatedAt);

        labels.Add("financial");
        restrictions.Add("no_external_export");

        Assert.Equal("env-1", envelope.EnvelopeId);
        Assert.Equal("workflow-1", envelope.WorkflowId);
        Assert.True(envelope.Labels.SetEquals(["pii"]));
        Assert.Equal(DataClassification.Internal, envelope.AggregateSensitivity);
        Assert.True(envelope.Restrictions.SetEquals(["no_memory_write"]));
        Assert.Equal(7, envelope.Version);
        Assert.Equal("parent-1", envelope.ParentEnvelopeId);
        Assert.Equal(CreatedAt, envelope.CreatedAt);
    }

    [Fact]
    public void Fold_UnionsLabelsRaisesSensitivityAndIncrementsVersionWithoutMutation()
    {
        var original = Envelope(
            labels: ["pii"],
            sensitivity: DataClassification.Internal,
            restrictions: ["no_memory_write"],
            version: 2);

        var folded = original.Fold(
            ["financial"],
            DataClassification.Confidential);

        Assert.NotSame(original, folded);
        Assert.True(folded.Labels.SetEquals(["pii", "financial"]));
        Assert.Equal(DataClassification.Confidential, folded.AggregateSensitivity);
        Assert.True(folded.Restrictions.SetEquals(["no_memory_write"]));
        Assert.Equal(3, folded.Version);
        Assert.True(original.Labels.SetEquals(["pii"]));
        Assert.Equal(DataClassification.Internal, original.AggregateSensitivity);
        Assert.Equal(2, original.Version);
    }

    [Fact]
    public void Fold_IsIdempotentCommutativeAndNeverLowersSensitivity()
    {
        var original = Envelope(
            labels: ["pii"],
            sensitivity: DataClassification.Restricted);

        var leftThenRight = original
            .Fold(["financial"], DataClassification.Public)
            .Fold(["behavioral", "pii"], DataClassification.Confidential);
        var rightThenLeft = original
            .Fold(["behavioral", "pii"], DataClassification.Confidential)
            .Fold(["financial"], DataClassification.Public);

        Assert.True(leftThenRight.Labels.SetEquals(rightThenLeft.Labels));
        Assert.Equal(DataClassification.Restricted, leftThenRight.AggregateSensitivity);
        Assert.Equal(leftThenRight.AggregateSensitivity, rightThenLeft.AggregateSensitivity);
    }

    [Fact]
    public void ApplyRestrictions_IsGrowOnlyAndIncrementsVersion()
    {
        var original = Envelope(
            restrictions: ["no_external_export"],
            version: 4);

        var unchangedSet = original.ApplyRestrictions([]);
        var grown = unchangedSet.ApplyRestrictions(["no_memory_write"]);

        Assert.True(unchangedSet.Restrictions.SetEquals(["no_external_export"]));
        Assert.Equal(5, unchangedSet.Version);
        Assert.True(grown.Restrictions.SetEquals(["no_external_export", "no_memory_write"]));
        Assert.Equal(6, grown.Version);
        Assert.True(original.Restrictions.SetEquals(["no_external_export"]));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(" pii")]
    [InlineData("pii ")]
    public void Constructor_RejectsMalformedLabels(string label)
    {
        Assert.Throws<ArgumentException>(
            () => Envelope(labels: [label]));
    }

    [Fact]
    public void Constructor_RejectsMalformedIdentityAndVersion()
    {
        Assert.Throws<ArgumentException>(() => new ContextEnvelope("", "workflow-1"));
        Assert.Throws<ArgumentException>(() => new ContextEnvelope("env-1", " "));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new ContextEnvelope("env-1", "workflow-1", version: -1));
    }

    [Fact]
    public void Fold_RejectsMalformedLabelsAndUndefinedClassification()
    {
        var envelope = Envelope();

        Assert.Throws<ArgumentException>(
            () => envelope.Fold([""], DataClassification.Public));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => envelope.Fold(["pii"], (DataClassification)(-1)));
    }

    private static ContextEnvelope Envelope(
        IEnumerable<string>? labels = null,
        DataClassification sensitivity = DataClassification.Public,
        IEnumerable<string>? restrictions = null,
        int version = 0) =>
        new(
            "env-1",
            "workflow-1",
            labels,
            sensitivity,
            restrictions,
            version,
            createdAt: CreatedAt);
}

public sealed class AccumulatedContextAggregationTests
{
    [Fact]
    public void Evaluate_AppliesEveryKnownRuleInDeclaredOrder()
    {
        var rules = new[]
        {
            new AggregationRule(
                "pii_financial_restricted",
                ["pii", "financial"],
                DataClassification.Restricted,
                ["no_external_export"]),
            new AggregationRule(
                "financial_behavioral_top_secret",
                ["financial", "behavioral"],
                DataClassification.TopSecret,
                ["no_memory_write"])
        };
        var ruleSet = new AggregationRuleSet(rules);
        var envelope = Envelope(
            labels: ["pii", "financial", "behavioral"],
            sensitivity: DataClassification.Confidential,
            restrictions: ["retain_audit"]);

        var result = ruleSet.Evaluate(envelope, categoryThreshold: 99);

        Assert.Equal(DataClassification.TopSecret, result.AggregateSensitivity);
        Assert.True(
            result.Restrictions.SetEquals(
                ["retain_audit", "no_external_export", "no_memory_write"]));
        Assert.Equal(
            ["pii_financial_restricted", "financial_behavioral_top_secret"],
            result.RulesApplied);
        Assert.False(result.Escalate);
    }

    [Fact]
    public void Evaluate_PreservesCurrentSensitivityWhenNoRuleMatches()
    {
        var result = Rules().Evaluate(
            Envelope(
                labels: ["pii", "behavioral"],
                sensitivity: DataClassification.Confidential),
            categoryThreshold: 99);

        Assert.Equal(DataClassification.Confidential, result.AggregateSensitivity);
        Assert.Empty(result.RulesApplied);
        Assert.False(result.Escalate);
    }

    [Fact]
    public void Evaluate_EscalatesUnknownCombinationAtThresholdOnlyWhenNoRuleMatches()
    {
        var unknown = Rules().Evaluate(
            Envelope(labels: ["a", "b", "c"]),
            categoryThreshold: 3);
        var known = Rules().Evaluate(
            Envelope(labels: ["pii", "financial", "behavioral"]),
            categoryThreshold: 3);

        Assert.True(unknown.Escalate);
        Assert.False(known.Escalate);
    }

    [Fact]
    public void Accumulate_FoldsActualResultAndAppliesAggregationAsTwoVersions()
    {
        var original = Envelope(
            labels: ["pii"],
            sensitivity: DataClassification.Internal,
            version: 4);

        var accumulated = ContextGovernance.Accumulate(
            original,
            ["financial"],
            DataClassification.Confidential,
            Rules(),
            categoryThreshold: 99);

        Assert.True(accumulated.Labels.SetEquals(["pii", "financial"]));
        Assert.Equal(DataClassification.Restricted, accumulated.AggregateSensitivity);
        Assert.True(accumulated.Restrictions.SetEquals(["no_external_export"]));
        Assert.Equal(6, accumulated.Version);
        Assert.True(original.Labels.SetEquals(["pii"]));
        Assert.Equal(DataClassification.Internal, original.AggregateSensitivity);
        Assert.Empty(original.Restrictions);
        Assert.Equal(4, original.Version);
    }

    [Fact]
    public void AggregationModels_SnapshotMutableInputs()
    {
        var labels = new HashSet<string>(StringComparer.Ordinal) { "pii" };
        var restrictions = new HashSet<string>(StringComparer.Ordinal) { "retain_audit" };
        var mutableRules = new List<AggregationRule>
        {
            new(
                "pii_internal",
                labels,
                DataClassification.Internal,
                restrictions)
        };

        var ruleSet = new AggregationRuleSet(mutableRules);
        labels.Add("financial");
        restrictions.Add("no_external_export");
        mutableRules.Clear();

        var result = ruleSet.Evaluate(
            Envelope(labels: ["pii"]),
            categoryThreshold: 99);

        Assert.Equal(["pii_internal"], result.RulesApplied);
        Assert.True(result.Restrictions.SetEquals(["retain_audit"]));
    }

    [Fact]
    public void Aggregation_RejectsMalformedRulesAndThresholds()
    {
        Assert.Throws<ArgumentException>(
            () => new AggregationRule(
                "",
                ["pii"],
                DataClassification.Restricted));
        Assert.Throws<ArgumentException>(
            () => new AggregationRule(
                "bad-label",
                [" "],
                DataClassification.Restricted));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new AggregationRule(
                "bad-classification",
                ["pii"],
                (DataClassification)99));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => Rules().Evaluate(Envelope(), categoryThreshold: 0));
    }

    private static AggregationRuleSet Rules() =>
        new(
        [
            new AggregationRule(
                "pii_financial_restricted",
                ["pii", "financial"],
                DataClassification.Restricted,
                ["no_external_export"])
        ]);

    private static ContextEnvelope Envelope(
        IEnumerable<string>? labels = null,
        DataClassification sensitivity = DataClassification.Internal,
        IEnumerable<string>? restrictions = null,
        int version = 0) =>
        new(
            "env-aggregation",
            "workflow-aggregation",
            labels,
            sensitivity,
            restrictions,
            version,
            createdAt: new DateTimeOffset(2026, 7, 27, 5, 0, 0, TimeSpan.Zero));
}
