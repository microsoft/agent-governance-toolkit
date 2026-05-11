// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Hypervisor;
using Xunit;

namespace AgentGovernance.Tests;

public class KillSwitchTests
{
    [Fact]
    public void NewKillSwitch_IsNotArmed()
    {
        var ks = new KillSwitch();

        Assert.False(ks.IsArmed);
    }

    [Fact]
    public void Arm_SetsIsArmedTrue()
    {
        var ks = new KillSwitch();
        ks.Arm();

        Assert.True(ks.IsArmed);
    }

    [Fact]
    public void Disarm_SetsIsArmedFalse()
    {
        var ks = new KillSwitch();
        ks.Arm();
        ks.Disarm();

        Assert.False(ks.IsArmed);
    }

    [Fact]
    public void Kill_WhenDisarmed_Throws()
    {
        var ks = new KillSwitch();

        Assert.Throws<InvalidOperationException>(
            () => ks.Kill("agent-1", KillReason.ManualOverride, "test"));
    }

    [Fact]
    public void Kill_WhenArmed_ReturnsEvent()
    {
        var ks = new KillSwitch();
        ks.Arm();

        var evt = ks.Kill("agent-1", KillReason.PolicyViolation, "exceeded scope");

        Assert.Equal("agent-1", evt.AgentId);
        Assert.Equal(KillReason.PolicyViolation, evt.Reason);
        Assert.Equal("exceeded scope", evt.Detail);
        Assert.True(evt.Timestamp <= DateTimeOffset.UtcNow);
    }

    [Fact]
    public void Kill_FiresOnKillEvent()
    {
        var ks = new KillSwitch();
        ks.Arm();

        KillEvent? received = null;
        ks.OnKill += (_, e) => received = e;

        ks.Kill("agent-1", KillReason.AnomalyDetected, "drift");

        Assert.NotNull(received);
        Assert.Equal("agent-1", received!.AgentId);
        Assert.Equal(KillReason.AnomalyDetected, received.Reason);
    }

    [Fact]
    public void History_TracksAllKills()
    {
        var ks = new KillSwitch();
        ks.Arm();

        ks.Kill("agent-1", KillReason.PolicyViolation, "v1");
        ks.Kill("agent-2", KillReason.TrustThreshold, "v2");
        ks.Kill("agent-3", KillReason.ResourceExhaustion, "v3");

        Assert.Equal(3, ks.History.Count);
        Assert.Equal("agent-1", ks.History[0].AgentId);
        Assert.Equal("agent-2", ks.History[1].AgentId);
        Assert.Equal("agent-3", ks.History[2].AgentId);
    }

    [Fact]
    public void History_IsEmpty_WhenNoKills()
    {
        var ks = new KillSwitch();

        Assert.Empty(ks.History);
    }

    [Fact]
    public void ArmDisarmArm_AllowsKillAfterRearm()
    {
        var ks = new KillSwitch();
        ks.Arm();
        ks.Disarm();
        ks.Arm();

        var evt = ks.Kill("agent-1", KillReason.ManualOverride, "re-armed");

        Assert.Equal("agent-1", evt.AgentId);
    }

    [Fact]
    public void Kill_AllReasons_Accepted()
    {
        var ks = new KillSwitch();
        ks.Arm();

        foreach (var reason in Enum.GetValues<KillReason>())
        {
            var evt = ks.Kill($"agent-{reason}", reason, reason.ToString());
            Assert.Equal(reason, evt.Reason);
        }

        Assert.Equal(Enum.GetValues<KillReason>().Length, ks.History.Count);
    }

    [Fact]
    public async Task ConcurrentKills_AllRecorded()
    {
        var ks = new KillSwitch();
        ks.Arm();

        const int threads = 16;
        const int killsPerThread = 50;

        var tasks = Enumerable.Range(0, threads).Select(t => Task.Run(() =>
        {
            for (var i = 0; i < killsPerThread; i++)
            {
                ks.Kill($"agent-{t}-{i}", KillReason.PolicyViolation, "concurrent");
            }
        })).ToArray();

        await Task.WhenAll(tasks);

        Assert.Equal(threads * killsPerThread, ks.History.Count);
    }
}
