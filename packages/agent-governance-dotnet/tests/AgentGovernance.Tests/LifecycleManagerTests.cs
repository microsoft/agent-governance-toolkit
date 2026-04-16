// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Lifecycle;
using Xunit;

namespace AgentGovernance.Tests;

public class LifecycleManagerTests
{
    private const string AgentId = "did:agentmesh:lifecycle-test";

    [Fact]
    public void NewManager_StartsInProvisioning()
    {
        var mgr = new LifecycleManager(AgentId);

        Assert.Equal(LifecycleState.Provisioning, mgr.State);
        Assert.Empty(mgr.Events);
    }

    [Fact]
    public void Activate_FromProvisioning_Succeeds()
    {
        var mgr = new LifecycleManager(AgentId);

        var evt = mgr.Activate();

        Assert.Equal(LifecycleState.Active, mgr.State);
        Assert.Equal(LifecycleState.Provisioning, evt.FromState);
        Assert.Equal(LifecycleState.Active, evt.ToState);
        Assert.Equal("Ready", evt.Reason);
        Assert.Equal(AgentId, evt.AgentId);
    }

    [Fact]
    public void Suspend_FromActive_Succeeds()
    {
        var mgr = new LifecycleManager(AgentId);
        mgr.Activate();

        var evt = mgr.Suspend("policy hold");

        Assert.Equal(LifecycleState.Suspended, mgr.State);
        Assert.Equal("policy hold", evt.Reason);
    }

    [Fact]
    public void Quarantine_FromActive_Succeeds()
    {
        var mgr = new LifecycleManager(AgentId);
        mgr.Activate();

        var evt = mgr.Quarantine("trust breach");

        Assert.Equal(LifecycleState.Quarantined, mgr.State);
        Assert.Equal("trust breach", evt.Reason);
    }

    [Fact]
    public void Decommission_FromActive_Succeeds()
    {
        var mgr = new LifecycleManager(AgentId);
        mgr.Activate();

        var evt = mgr.Decommission("end of life");

        Assert.Equal(LifecycleState.Decommissioning, mgr.State);
        Assert.Equal("end of life", evt.Reason);
    }

    [Fact]
    public void FullLifecycle_ProvisionToDecommissioned()
    {
        var mgr = new LifecycleManager(AgentId);

        mgr.Activate();
        mgr.Suspend("maintenance");
        mgr.Transition(LifecycleState.Active, "maintenance complete", "ops");
        mgr.Decommission("retiring");
        mgr.Transition(LifecycleState.Decommissioned, "done", "ops");

        Assert.Equal(LifecycleState.Decommissioned, mgr.State);
        Assert.Equal(5, mgr.Events.Count);
    }

    [Fact]
    public void InvalidTransition_Throws()
    {
        var mgr = new LifecycleManager(AgentId);

        // Provisioning → Quarantined is not allowed
        Assert.Throws<InvalidOperationException>(
            () => mgr.Quarantine("should fail"));
    }

    [Fact]
    public void Decommissioned_CannotTransition()
    {
        var mgr = new LifecycleManager(AgentId);
        mgr.Activate();
        mgr.Decommission("retiring");
        mgr.Transition(LifecycleState.Decommissioned, "done", "ops");

        Assert.Throws<InvalidOperationException>(
            () => mgr.Activate("should fail"));
    }

    [Fact]
    public void CanTransition_ReturnsCorrectly()
    {
        var mgr = new LifecycleManager(AgentId);

        Assert.True(mgr.CanTransition(LifecycleState.Active));
        Assert.True(mgr.CanTransition(LifecycleState.Decommissioning));
        Assert.False(mgr.CanTransition(LifecycleState.Suspended));
        Assert.False(mgr.CanTransition(LifecycleState.Quarantined));
    }

    [Fact]
    public void Transition_RecordsInitiatedBy()
    {
        var mgr = new LifecycleManager(AgentId);

        var evt = mgr.Transition(LifecycleState.Active, "init", "admin-user");

        Assert.Equal("admin-user", evt.InitiatedBy);
    }

    [Fact]
    public void ConvenienceMethods_UseSystemAsInitiator()
    {
        var mgr = new LifecycleManager(AgentId);
        var evt = mgr.Activate();

        Assert.Equal("system", evt.InitiatedBy);
    }

    [Fact]
    public void Events_AreImmutableSnapshot()
    {
        var mgr = new LifecycleManager(AgentId);
        mgr.Activate();

        var snapshot = mgr.Events;
        mgr.Suspend("pause");

        // Snapshot should not reflect the new event
        Assert.Single(snapshot);
        Assert.Equal(2, mgr.Events.Count);
    }

    [Fact]
    public void Rotating_FromActive_Succeeds()
    {
        var mgr = new LifecycleManager(AgentId);
        mgr.Activate();

        var evt = mgr.Transition(LifecycleState.Rotating, "key rotation", "security");

        Assert.Equal(LifecycleState.Rotating, mgr.State);
        Assert.Equal("key rotation", evt.Reason);
    }

    [Fact]
    public void Degraded_FromActive_Succeeds()
    {
        var mgr = new LifecycleManager(AgentId);
        mgr.Activate();

        var evt = mgr.Transition(LifecycleState.Degraded, "partial failure", "monitor");

        Assert.Equal(LifecycleState.Degraded, mgr.State);
    }

    [Fact]
    public void Quarantine_FromDegraded_Succeeds()
    {
        var mgr = new LifecycleManager(AgentId);
        mgr.Activate();
        mgr.Transition(LifecycleState.Degraded, "failing", "monitor");

        mgr.Quarantine("escalation");

        Assert.Equal(LifecycleState.Quarantined, mgr.State);
    }

    [Fact]
    public void Active_FromQuarantined_Succeeds()
    {
        var mgr = new LifecycleManager(AgentId);
        mgr.Activate();
        mgr.Quarantine("incident");

        mgr.Transition(LifecycleState.Active, "cleared", "ops");

        Assert.Equal(LifecycleState.Active, mgr.State);
    }
}
