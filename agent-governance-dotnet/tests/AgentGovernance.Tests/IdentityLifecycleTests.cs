// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Trust;
using Xunit;

namespace AgentGovernance.Tests;

public class IdentityLifecycleTests
{
    [Fact]
    public void NewIdentity_IsActive()
    {
        var identity = AgentIdentity.Create("test");

        Assert.Equal(IdentityStatus.Active, identity.Status);
        Assert.True(identity.IsActive());
    }

    [Fact]
    public void Suspend_ChangesStatusToSuspended()
    {
        var identity = AgentIdentity.Create("test");
        identity.Suspend();

        Assert.Equal(IdentityStatus.Suspended, identity.Status);
        Assert.False(identity.IsActive());
    }

    [Fact]
    public void Reactivate_RestoresSuspendedToActive()
    {
        var identity = AgentIdentity.Create("test");
        identity.Suspend();
        identity.Reactivate();

        Assert.Equal(IdentityStatus.Active, identity.Status);
        Assert.True(identity.IsActive());
    }

    [Fact]
    public void Revoke_ChangesStatusToRevoked()
    {
        var identity = AgentIdentity.Create("test");
        identity.Revoke();

        Assert.Equal(IdentityStatus.Revoked, identity.Status);
        Assert.False(identity.IsActive());
    }

    [Fact]
    public void Revoke_FromSuspended_Works()
    {
        var identity = AgentIdentity.Create("test");
        identity.Suspend();
        identity.Revoke();

        Assert.Equal(IdentityStatus.Revoked, identity.Status);
    }

    [Fact]
    public void Reactivate_Revoked_ThrowsInvalidOperationException()
    {
        var identity = AgentIdentity.Create("test");
        identity.Revoke();

        Assert.Throws<InvalidOperationException>(() => identity.Reactivate());
    }

    [Fact]
    public void Suspend_Revoked_ThrowsInvalidOperationException()
    {
        var identity = AgentIdentity.Create("test");
        identity.Revoke();

        Assert.Throws<InvalidOperationException>(() => identity.Suspend());
    }

    [Fact]
    public void Suspend_AlreadySuspended_Idempotent()
    {
        var identity = AgentIdentity.Create("test");
        identity.Suspend();
        identity.Suspend();

        Assert.Equal(IdentityStatus.Suspended, identity.Status);
    }

    [Fact]
    public void Reactivate_AlreadyActive_Idempotent()
    {
        var identity = AgentIdentity.Create("test");
        identity.Reactivate();

        Assert.Equal(IdentityStatus.Active, identity.Status);
    }

    [Fact]
    public void Revoke_AlreadyRevoked_Idempotent()
    {
        var identity = AgentIdentity.Create("test");
        identity.Revoke();
        identity.Revoke();

        Assert.Equal(IdentityStatus.Revoked, identity.Status);
    }
}
