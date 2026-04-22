// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Trust;
using Xunit;

namespace AgentGovernance.Tests;

public class IdentityRegistryTests
{
    [Fact]
    public void Register_And_Get_RoundTrips()
    {
        var registry = new IdentityRegistry();
        var identity = AgentIdentity.Create("agent-alpha", sponsor: "owner@example.com");

        registry.Register(identity);
        var retrieved = registry.Get(identity.Did);

        Assert.Same(identity, retrieved);
    }

    [Fact]
    public void Register_DuplicateDid_ThrowsInvalidOperationException()
    {
        var registry = new IdentityRegistry();
        var identity = AgentIdentity.Create("agent-alpha");

        registry.Register(identity);

        Assert.Throws<InvalidOperationException>(() => registry.Register(identity));
    }

    [Fact]
    public void Get_UnknownDid_ThrowsKeyNotFoundException()
    {
        var registry = new IdentityRegistry();

        Assert.Throws<KeyNotFoundException>(() => registry.Get("did:mesh:unknown"));
    }

    [Fact]
    public void TryGet_AcceptsLegacyDidFormat()
    {
        var registry = new IdentityRegistry();
        var identity = AgentIdentity.Create("agent-alpha");
        registry.Register(identity);

        Assert.True(registry.TryGet(
            identity.Did.Replace("did:mesh:", "did:agentmesh:", StringComparison.Ordinal),
            out var retrieved));
        Assert.Same(identity, retrieved);
    }

    [Fact]
    public void Revoke_SetsIdentityToRevoked()
    {
        var registry = new IdentityRegistry();
        var identity = AgentIdentity.Create("agent-alpha");
        registry.Register(identity);

        registry.Revoke(identity.Did, "Compromised key");

        Assert.Equal(IdentityStatus.Revoked, identity.Status);
        Assert.False(identity.IsActive());
        Assert.Equal("Compromised key", identity.RevocationReason);
    }

    [Fact]
    public void Revoke_CascadesToDelegatedChildren()
    {
        var registry = new IdentityRegistry();
        var parent = AgentIdentity.Create(
            "parent",
            sponsor: "owner@example.com",
            capabilities: new[] { "read", "write" });
        var child = parent.Delegate("child", new[] { "read" });

        registry.Register(parent);
        registry.Register(child);

        registry.Revoke(parent.Did, "security incident");

        Assert.Equal(IdentityStatus.Revoked, parent.Status);
        Assert.Equal(IdentityStatus.Revoked, child.Status);
        Assert.Equal("Parent revoked: security incident", child.RevocationReason);
    }

    [Fact]
    public void Revoke_UnknownDid_ThrowsKeyNotFoundException()
    {
        var registry = new IdentityRegistry();

        Assert.Throws<KeyNotFoundException>(() =>
            registry.Revoke("did:mesh:unknown", "reason"));
    }

    [Fact]
    public void ListActive_ReturnsOnlyActiveIdentities()
    {
        var registry = new IdentityRegistry();
        var active1 = AgentIdentity.Create("active1");
        var active2 = AgentIdentity.Create("active2");
        var revoked = AgentIdentity.Create("revoked");

        registry.Register(active1);
        registry.Register(active2);
        registry.Register(revoked);

        registry.Revoke(revoked.Did, "test");

        var actives = registry.ListActive();
        Assert.Equal(2, actives.Count);
        Assert.Contains(active1, actives);
        Assert.Contains(active2, actives);
        Assert.DoesNotContain(revoked, actives);
    }

    [Fact]
    public void Count_ReturnsTotal()
    {
        var registry = new IdentityRegistry();
        Assert.Equal(0, registry.Count);

        registry.Register(AgentIdentity.Create("a"));
        registry.Register(AgentIdentity.Create("b"));

        Assert.Equal(2, registry.Count);
    }

    [Fact]
    public void Register_Null_ThrowsArgumentNullException()
    {
        var registry = new IdentityRegistry();
        Assert.Throws<ArgumentNullException>(() => registry.Register(null!));
    }

    [Fact]
    public void ListActive_ExcludesSuspended()
    {
        var registry = new IdentityRegistry();
        var identity = AgentIdentity.Create("test");
        registry.Register(identity);

        identity.Suspend();

        var actives = registry.ListActive();
        Assert.Empty(actives);
    }

    [Fact]
    public void GetBySponsor_ReturnsAllSponsorIdentities()
    {
        var registry = new IdentityRegistry();
        var a = AgentIdentity.Create("a", sponsor: "owner@example.com");
        var b = AgentIdentity.Create("b", sponsor: "owner@example.com");
        var c = AgentIdentity.Create("c", sponsor: "other@example.com");

        registry.Register(a);
        registry.Register(b);
        registry.Register(c);

        var owned = registry.GetBySponsor("owner@example.com");

        Assert.Equal(2, owned.Count);
        Assert.Contains(a, owned);
        Assert.Contains(b, owned);
        Assert.DoesNotContain(c, owned);
    }

    [Fact]
    public void IsTrusted_RequiresActiveIdentity()
    {
        var registry = new IdentityRegistry();
        var identity = AgentIdentity.Create("trusted");
        registry.Register(identity);

        Assert.True(registry.IsTrusted(identity.Did));

        identity.Suspend();
        Assert.False(registry.IsTrusted(identity.Did));
    }

    [Fact]
    public void Register_RequiresAttestation_WhenConfigured()
    {
        var registry = new IdentityRegistry(requireAttestation: true);
        var unverified = AgentIdentity.Create("plain");
        var verified = AgentIdentity.Create("verified", attestationVerified: true);

        Assert.Throws<InvalidOperationException>(() => registry.Register(unverified));

        registry.Register(verified);
        Assert.True(registry.IsTrusted(verified.Did));
    }
}
