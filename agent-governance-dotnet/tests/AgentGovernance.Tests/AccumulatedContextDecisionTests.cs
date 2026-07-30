// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Context;
using AgentGovernance.Policy;
using Xunit;

namespace AgentGovernance.Tests;

public sealed class AccumulatedContextDecisionTests
{
    [Fact]
    public void DecideNext_EscalatesUnknownCombinationAndMapsToReview()
    {
        var envelope = Envelope(labels: ["a", "b", "c"]);

        var decision = ContextGovernance.DecideNext(
            envelope,
            "read",
            Rules(),
            categoryThreshold: 3);

        Assert.Equal(ContextOutcome.Escalate, decision.Outcome);
        Assert.True(decision.Obligations.ResultLabels.SetEquals(["a", "b", "c"]));
        Assert.Empty(decision.Obligations.Obligations);
        Assert.Equal(
            "aggregation threshold crossed with no governing rule",
            decision.Reason);
        Assert.Equal(PolicyAction.RequireApproval, decision.ToPolicyAction(false));
    }

    [Theory]
    [InlineData("export", "no_external_export")]
    [InlineData("delegate", "no_external_delegation")]
    [InlineData("memory_write", "no_memory_write")]
    public void DecideNext_ExplicitRestrictionConstrainsBelowFloor(
        string action,
        string restriction)
    {
        var envelope = Envelope(
            labels: ["pii"],
            sensitivity: DataClassification.Confidential,
            restrictions: [restriction, "retain_audit"]);

        var decision = ContextGovernance.DecideNext(
            envelope,
            action,
            Rules(),
            categoryThreshold: 99);

        Assert.Equal(ContextOutcome.Constrain, decision.Outcome);
        Assert.Equal(
            new[] { "retain_audit", restriction }.Order(StringComparer.Ordinal),
            decision.Obligations.Obligations.Select(static obligation => obligation.Key));
        Assert.All(
            decision.Obligations.Obligations,
            static obligation => Assert.False(obligation.Satisfied));
        Assert.Equal(PolicyAction.Deny, decision.ToPolicyAction(false));
        Assert.Equal(PolicyAction.Allow, decision.ToPolicyAction(true));
    }

    [Fact]
    public void DecideNext_SensitivityFloorConstrainsFlowActionWithoutRestriction()
    {
        var decision = ContextGovernance.DecideNext(
            Envelope(
                labels: ["pii"],
                sensitivity: DataClassification.Restricted),
            "export",
            Rules(),
            categoryThreshold: 99);

        Assert.Equal(ContextOutcome.Constrain, decision.Outcome);
        Assert.Empty(decision.Obligations.Obligations);
        Assert.Equal(
            "action 'export' gated by sensitivity floor",
            decision.Reason);
        Assert.Equal(PolicyAction.Deny, decision.ToPolicyAction(false));
        Assert.Equal(PolicyAction.Allow, decision.ToPolicyAction(true));
    }

    [Fact]
    public void DecideNext_AllowsSupportedUnrestrictedAction()
    {
        var decision = ContextGovernance.DecideNext(
            Envelope(labels: ["pii"]),
            "read",
            Rules(),
            categoryThreshold: 99);

        Assert.Equal(ContextOutcome.Allow, decision.Outcome);
        Assert.True(decision.Obligations.ResultLabels.SetEquals(["pii"]));
        Assert.Equal(PolicyAction.Allow, decision.ToPolicyAction(false));
    }

    [Fact]
    public void ToPolicyAction_EnforcesObligationsAndFailsClosed()
    {
        var satisfied = Decision(
            ContextOutcome.Constrain,
            new ObligationSet([new Obligation("retain_audit", satisfied: true)]));
        var unsatisfied = Decision(
            ContextOutcome.Constrain,
            new ObligationSet([new Obligation("retain_audit")]));
        var empty = Decision(ContextOutcome.Constrain, new ObligationSet());
        var denied = Decision(ContextOutcome.Deny, new ObligationSet());

        Assert.Equal(PolicyAction.Allow, satisfied.ToPolicyAction(false));
        Assert.Equal(PolicyAction.Deny, unsatisfied.ToPolicyAction(false));
        Assert.Equal(PolicyAction.Deny, empty.ToPolicyAction(false));
        Assert.Equal(PolicyAction.Deny, denied.ToPolicyAction(true));
    }

    [Fact]
    public void DecisionModels_RejectMalformedOrUnsupportedState()
    {
        Assert.Throws<ArgumentException>(() => new Obligation(""));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => Decision((ContextOutcome)99, new ObligationSet()));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => Decision(
                ContextOutcome.Allow,
                new ObligationSet(),
                (DataClassification)99));
        Assert.Throws<ArgumentException>(
            () => ContextGovernance.DecideNext(
                Envelope(),
                " ",
                Rules(),
                categoryThreshold: 99));
    }

    private static ContextDecision Decision(
        ContextOutcome outcome,
        ObligationSet obligations,
        DataClassification sensitivity = DataClassification.Restricted) =>
        new(outcome, obligations, sensitivity);

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
        IEnumerable<string>? restrictions = null) =>
        new(
            "env-decision",
            "workflow-decision",
            labels,
            sensitivity,
            restrictions,
            createdAt: new DateTimeOffset(2026, 7, 27, 5, 0, 0, TimeSpan.Zero));
}

public sealed class AccumulatedContextDelegationTests
{
    [Fact]
    public void MergeRestrictions_InheritsParentAndAddsChildRestrictions()
    {
        var parent = new ContextEnvelope(
            "parent-1",
            "workflow-1",
            restrictions: ["no_external_export"]);

        var child = ContextGovernance.MergeRestrictions(
            parent,
            ["no_memory_write"]);
        var grandchild = ContextGovernance.MergeRestrictions(
            new ContextEnvelope(
                "child-1",
                "workflow-1",
                restrictions: child,
                parentEnvelopeId: parent.EnvelopeId),
            ["retain_audit"]);

        Assert.True(child.SetEquals(["no_external_export", "no_memory_write"]));
        Assert.True(
            grandchild.SetEquals(
                ["no_external_export", "no_memory_write", "retain_audit"]));
        Assert.True(parent.Restrictions.SetEquals(["no_external_export"]));
    }

    [Fact]
    public void MergeRestrictions_CannotDropParentRestrictions()
    {
        var parent = new ContextEnvelope(
            "parent-1",
            "workflow-1",
            restrictions: ["no_external_export", "no_memory_write"]);

        var effective = ContextGovernance.MergeRestrictions(parent, []);

        Assert.True(
            effective.SetEquals(
                ["no_external_export", "no_memory_write"]));
    }

    [Fact]
    public void MergeRestrictions_RejectsMalformedChildToken()
    {
        var parent = new ContextEnvelope("parent-1", "workflow-1");

        Assert.Throws<ArgumentException>(
            () => ContextGovernance.MergeRestrictions(parent, [""]));
    }
}
