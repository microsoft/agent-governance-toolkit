// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Hypervisor;
using Xunit;

namespace AgentGovernance.Tests;

public class ExecutionRingsTests
{
    private readonly RingEnforcer _enforcer = new();

    [Theory]
    [InlineData(0.96, ExecutionRing.Ring0)]
    [InlineData(0.95, ExecutionRing.Ring0)]
    [InlineData(0.85, ExecutionRing.Ring1)]
    [InlineData(0.80, ExecutionRing.Ring1)]
    [InlineData(0.70, ExecutionRing.Ring2)]
    [InlineData(0.60, ExecutionRing.Ring2)]
    [InlineData(0.50, ExecutionRing.Ring3)]
    [InlineData(0.0, ExecutionRing.Ring3)]
    public void ComputeRing_AssignsCorrectRing(double trust, ExecutionRing expected)
    {
        Assert.Equal(expected, _enforcer.ComputeRing(trust));
    }

    [Fact]
    public void Check_SufficientPrivilege_Allowed()
    {
        var result = _enforcer.Check(trustScore: 0.85, requiredRing: ExecutionRing.Ring2);
        Assert.True(result.Allowed);
        Assert.Equal(ExecutionRing.Ring1, result.AgentRing);
    }

    [Fact]
    public void Check_InsufficientPrivilege_Denied()
    {
        var result = _enforcer.Check(trustScore: 0.50, requiredRing: ExecutionRing.Ring1);
        Assert.False(result.Allowed);
        Assert.Equal(ExecutionRing.Ring3, result.AgentRing);
    }

    [Fact]
    public void Check_Ring0_NeverAutoGranted()
    {
        var result = _enforcer.Check(trustScore: 0.90, requiredRing: ExecutionRing.Ring0);
        Assert.False(result.Allowed);
        Assert.Contains("Ring 0", result.Reason);
    }

    [Fact]
    public void Check_Ring0_GrantedWhenTrustSufficient()
    {
        var result = _enforcer.Check(trustScore: 0.96, requiredRing: ExecutionRing.Ring0);
        Assert.True(result.Allowed);
    }

    [Fact]
    public void ShouldDemote_TrustDrops_ReturnsTrue()
    {
        Assert.True(_enforcer.ShouldDemote(ExecutionRing.Ring1, newTrustScore: 0.50));
    }

    [Fact]
    public void ShouldDemote_TrustStable_ReturnsFalse()
    {
        Assert.False(_enforcer.ShouldDemote(ExecutionRing.Ring2, newTrustScore: 0.70));
    }

    [Fact]
    public void GetLimits_ReturnsRingSpecificLimits()
    {
        var ring3 = _enforcer.GetLimits(ExecutionRing.Ring3);
        Assert.Equal(10, ring3.MaxCallsPerMinute);
        Assert.False(ring3.AllowWrites);
        Assert.False(ring3.AllowNetwork);

        var ring1 = _enforcer.GetLimits(ExecutionRing.Ring1);
        Assert.Equal(1000, ring1.MaxCallsPerMinute);
        Assert.True(ring1.AllowWrites);
    }

    [Fact]
    public void CustomThresholds_Override()
    {
        var custom = new RingEnforcer(new Dictionary<ExecutionRing, double>
        {
            [ExecutionRing.Ring0] = 0.99,
            [ExecutionRing.Ring1] = 0.90,
            [ExecutionRing.Ring2] = 0.70,
            [ExecutionRing.Ring3] = 0.0
        });

        Assert.Equal(ExecutionRing.Ring3, custom.ComputeRing(0.60));
        Assert.Equal(ExecutionRing.Ring2, custom.ComputeRing(0.75));
    }
}
