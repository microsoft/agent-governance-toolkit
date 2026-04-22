// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Policy;
using Xunit;

namespace AgentGovernance.Tests;

public class ConflictResolutionTests
{
    private static PolicyRule MakeRule(string name, PolicyAction action, int priority) =>
        new() { Name = name, Condition = "true_field", Action = action, Priority = priority };

    [Fact]
    public void DenyOverrides_DenyWinsOverAllow()
    {
        var candidates = new List<CandidateDecision>
        {
            new(MakeRule("allow-rule", PolicyAction.Allow, 5),
                PolicyDecision.FromRule(MakeRule("allow-rule", PolicyAction.Allow, 5)),
                PolicyScope.Global),
            new(MakeRule("deny-rule", PolicyAction.Deny, 3),
                PolicyDecision.FromRule(MakeRule("deny-rule", PolicyAction.Deny, 3)),
                PolicyScope.Global)
        };

        var result = PolicyConflictResolver.Resolve(candidates, ConflictResolutionStrategy.DenyOverrides);

        Assert.NotNull(result);
        Assert.False(result!.Allowed);
        Assert.Equal("deny-rule", result.MatchedRule);
    }

    [Fact]
    public void AllowOverrides_AllowWinsOverDeny()
    {
        var candidates = new List<CandidateDecision>
        {
            new(MakeRule("deny-rule", PolicyAction.Deny, 10),
                PolicyDecision.FromRule(MakeRule("deny-rule", PolicyAction.Deny, 10)),
                PolicyScope.Global),
            new(MakeRule("allow-rule", PolicyAction.Allow, 3),
                PolicyDecision.FromRule(MakeRule("allow-rule", PolicyAction.Allow, 3)),
                PolicyScope.Global)
        };

        var result = PolicyConflictResolver.Resolve(candidates, ConflictResolutionStrategy.AllowOverrides);

        Assert.NotNull(result);
        Assert.True(result!.Allowed);
        Assert.Equal("allow-rule", result.MatchedRule);
    }

    [Fact]
    public void PriorityFirstMatch_HighestPriorityWins()
    {
        var candidates = new List<CandidateDecision>
        {
            new(MakeRule("low-priority", PolicyAction.Allow, 1),
                PolicyDecision.FromRule(MakeRule("low-priority", PolicyAction.Allow, 1)),
                PolicyScope.Global),
            new(MakeRule("high-priority", PolicyAction.Deny, 100),
                PolicyDecision.FromRule(MakeRule("high-priority", PolicyAction.Deny, 100)),
                PolicyScope.Global)
        };

        var result = PolicyConflictResolver.Resolve(candidates, ConflictResolutionStrategy.PriorityFirstMatch);

        Assert.NotNull(result);
        Assert.False(result!.Allowed);
        Assert.Equal("high-priority", result.MatchedRule);
    }

    [Fact]
    public void MostSpecificWins_AgentScopeBeatsGlobal()
    {
        var candidates = new List<CandidateDecision>
        {
            new(MakeRule("global-deny", PolicyAction.Deny, 100),
                PolicyDecision.FromRule(MakeRule("global-deny", PolicyAction.Deny, 100)),
                PolicyScope.Global),
            new(MakeRule("agent-allow", PolicyAction.Allow, 1),
                PolicyDecision.FromRule(MakeRule("agent-allow", PolicyAction.Allow, 1)),
                PolicyScope.Agent)
        };

        var result = PolicyConflictResolver.Resolve(candidates, ConflictResolutionStrategy.MostSpecificWins);

        Assert.NotNull(result);
        Assert.True(result!.Allowed);
        Assert.Equal("agent-allow", result.MatchedRule);
    }

    [Fact]
    public void MostSpecificWins_TenantBeatGlobal_AgentBeatsTenant()
    {
        var candidates = new List<CandidateDecision>
        {
            new(MakeRule("global-rule", PolicyAction.Deny, 10),
                PolicyDecision.FromRule(MakeRule("global-rule", PolicyAction.Deny, 10)),
                PolicyScope.Global),
            new(MakeRule("tenant-rule", PolicyAction.Allow, 5),
                PolicyDecision.FromRule(MakeRule("tenant-rule", PolicyAction.Allow, 5)),
                PolicyScope.Tenant),
            new(MakeRule("agent-rule", PolicyAction.Deny, 1),
                PolicyDecision.FromRule(MakeRule("agent-rule", PolicyAction.Deny, 1)),
                PolicyScope.Agent)
        };

        var result = PolicyConflictResolver.Resolve(candidates, ConflictResolutionStrategy.MostSpecificWins);

        Assert.NotNull(result);
        Assert.Equal("agent-rule", result.MatchedRule);
    }

    [Fact]
    public void Resolve_EmptyList_ReturnsNull()
    {
        var result = PolicyConflictResolver.Resolve(
            new List<CandidateDecision>(),
            ConflictResolutionStrategy.DenyOverrides);

        Assert.Null(result);
    }

    [Fact]
    public void Resolve_SingleCandidate_ReturnsThatDecision()
    {
        var candidates = new List<CandidateDecision>
        {
            new(MakeRule("only-rule", PolicyAction.Allow, 5),
                PolicyDecision.FromRule(MakeRule("only-rule", PolicyAction.Allow, 5)),
                PolicyScope.Global)
        };

        var result = PolicyConflictResolver.Resolve(candidates, ConflictResolutionStrategy.DenyOverrides);

        Assert.NotNull(result);
        Assert.Equal("only-rule", result!.MatchedRule);
    }

    [Fact]
    public void ParseScope_ValidValues_ParseCorrectly()
    {
        Assert.Equal(PolicyScope.Global, PolicyConflictResolver.ParseScope("global"));
        Assert.Equal(PolicyScope.Tenant, PolicyConflictResolver.ParseScope("tenant"));
        Assert.Equal(PolicyScope.Agent, PolicyConflictResolver.ParseScope("agent"));
        Assert.Equal(PolicyScope.Global, PolicyConflictResolver.ParseScope(null));
        Assert.Equal(PolicyScope.Global, PolicyConflictResolver.ParseScope("unknown"));
    }
}
