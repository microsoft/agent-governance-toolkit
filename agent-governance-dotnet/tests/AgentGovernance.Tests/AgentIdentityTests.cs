// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Trust;
using Xunit;

namespace AgentGovernance.Tests;

public class AgentIdentityTests
{
    [Fact]
    public void Create_GeneratesValidIdentity()
    {
        var identity = AgentIdentity.Create("test-agent", sponsor: "owner@example.com");

        Assert.StartsWith("did:mesh:", identity.Did);
        Assert.Equal("test-agent", identity.Name);
        Assert.Equal("owner@example.com", identity.SponsorEmail);
        Assert.NotEmpty(identity.VerificationKeyId);
        Assert.NotNull(identity.PublicKey);
        Assert.NotNull(identity.PrivateKey);
        Assert.Equal(32, identity.PublicKey.Length);
        Assert.Equal(32, identity.PrivateKey!.Length);
    }

    [Fact]
    public void Create_UsesFallbackSponsor_WhenNotProvided()
    {
        var identity = AgentIdentity.Create("agent alpha");

        Assert.Equal("agent-alpha@agentmesh.dev", identity.SponsorEmail);
    }

    [Fact]
    public void Create_DifferentNames_ProduceDifferentDids()
    {
        var id1 = AgentIdentity.Create("agent-alpha");
        var id2 = AgentIdentity.Create("agent-beta");

        Assert.NotEqual(id1.Did, id2.Did);
    }

    [Fact]
    public void NormalizeDid_AcceptsLegacyPrefix()
    {
        Assert.Equal(
            "did:mesh:test-agent",
            AgentIdentity.NormalizeDid("did:agentmesh:test-agent"));
    }

    [Fact]
    public void Sign_ProducesConsistentSignature()
    {
        var identity = AgentIdentity.Create("signer");
        var data = "Hello, governance!"u8.ToArray();

        var sig1 = identity.Sign(data);
        var sig2 = identity.Sign(data);

        Assert.Equal(sig1, sig2);
        Assert.Equal(32, sig1.Length);
    }

    [Fact]
    public void Sign_StringOverload_Works()
    {
        var identity = AgentIdentity.Create("signer");
        var sig = identity.Sign("test message");

        Assert.NotNull(sig);
        Assert.Equal(32, sig.Length);
    }

    [Fact]
    public void Verify_ValidSignature_ReturnsTrue()
    {
        var identity = AgentIdentity.Create("verifier");
        var data = "some data to sign"u8.ToArray();

        var signature = identity.Sign(data);
        Assert.True(identity.Verify(data, signature));
    }

    [Fact]
    public void Verify_TamperedData_ReturnsFalse()
    {
        var identity = AgentIdentity.Create("verifier");
        var data = "original data"u8.ToArray();
        var signature = identity.Sign(data);

        var tampered = "tampered data"u8.ToArray();
        Assert.False(identity.Verify(tampered, signature));
    }

    [Fact]
    public void Verify_TamperedSignature_ReturnsFalse()
    {
        var identity = AgentIdentity.Create("verifier");
        var data = "some data"u8.ToArray();
        var signature = identity.Sign(data);

        var tampered = (byte[])signature.Clone();
        tampered[0] ^= 0xFF;
        Assert.False(identity.Verify(data, tampered));
    }

    [Fact]
    public void Verify_VerificationOnlyIdentity_ThrowsInvalidOperationException()
    {
        var identity = AgentIdentity.Create("full");
        var verifyOnly = new AgentIdentity(identity.Did, identity.PublicKey);

        var data = "test"u8.ToArray();
        var sig = identity.Sign(data);

        Assert.Throws<InvalidOperationException>(() => verifyOnly.Verify(data, sig));
    }

    [Fact]
    public void Sign_WithoutPrivateKey_ThrowsInvalidOperationException()
    {
        var identity = new AgentIdentity("did:mesh:test", new byte[32]);

        Assert.Throws<InvalidOperationException>(() =>
            identity.Sign("test"u8.ToArray()));
    }

    [Fact]
    public void VerifySignature_Static_WithPrivateKey_Works()
    {
        var identity = AgentIdentity.Create("static-test");
        var data = "static verification"u8.ToArray();
        var signature = identity.Sign(data);

        Assert.True(AgentIdentity.VerifySignature(
            identity.PublicKey, data, signature, identity.PrivateKey));
    }

    [Fact]
    public void VerifySignature_Static_WithoutPrivateKey_ThrowsInvalidOperationException()
    {
        var identity = AgentIdentity.Create("static-test");
        var data = "test"u8.ToArray();
        var signature = identity.Sign(data);

        Assert.Throws<InvalidOperationException>(() =>
            AgentIdentity.VerifySignature(identity.PublicKey, data, signature));
    }

    [Fact]
    public void HasCapability_SupportsExactAndPrefixWildcard()
    {
        var identity = AgentIdentity.Create(
            "capability-agent",
            capabilities: new[] { "read:*", "write" });

        Assert.True(identity.HasCapability("read:users"));
        Assert.True(identity.HasCapability("write"));
        Assert.False(identity.HasCapability("admin"));
    }

    [Fact]
    public void Delegate_CreatesChildWithNarrowedCapabilities()
    {
        var parent = AgentIdentity.Create(
            "parent",
            sponsor: "owner@example.com",
            capabilities: new[] { "read", "write", "execute" });

        var child = parent.Delegate("child", new[] { "read" });

        Assert.Equal(parent.Did, child.ParentDid);
        Assert.Equal(1, child.DelegationDepth);
        Assert.Equal(new[] { "read" }, child.Capabilities);
        Assert.Equal(parent.SponsorEmail, child.SponsorEmail);
    }

    [Fact]
    public void Delegate_RejectsCapabilityNotInParent()
    {
        var parent = AgentIdentity.Create(
            "parent",
            sponsor: "owner@example.com",
            capabilities: new[] { "read" });

        Assert.Throws<InvalidOperationException>(() =>
            parent.Delegate("child", new[] { "read", "write" }));
    }

    [Fact]
    public void GetEffectiveCapabilities_IntersectsDelegationChain()
    {
        var registry = new IdentityRegistry();
        var root = AgentIdentity.Create(
            "root",
            sponsor: "owner@example.com",
            capabilities: new[] { "read", "write", "execute" });
        var child = root.Delegate("child", new[] { "read", "write" });
        var leaf = child.Delegate("leaf", new[] { "read" });

        registry.Register(root);
        registry.Register(child);
        registry.Register(leaf);

        Assert.Equal(new[] { "read" }, leaf.GetEffectiveCapabilities(registry));
    }

    [Fact]
    public void VerifyDelegationChain_ValidChain_ReturnsTrue()
    {
        var registry = new IdentityRegistry();
        var root = AgentIdentity.Create(
            "root",
            sponsor: "owner@example.com",
            capabilities: new[] { "read", "write" });
        var child = root.Delegate("child", new[] { "read" });

        registry.Register(root);
        registry.Register(child);

        Assert.True(AgentIdentity.VerifyDelegationChain(child, registry));
    }

    [Fact]
    public void ToString_ReturnsDid()
    {
        var identity = AgentIdentity.Create("display-test");
        Assert.Equal(identity.Did, identity.ToString());
    }
}
