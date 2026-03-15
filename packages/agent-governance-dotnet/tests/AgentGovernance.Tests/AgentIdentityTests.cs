// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Trust;
using Xunit;

namespace AgentGovernance.Tests;

public class AgentIdentityTests
{
    [Fact]
    public void Create_GeneratesValidIdentity()
    {
        var identity = AgentIdentity.Create("test-agent");

        Assert.StartsWith("did:mesh:", identity.Did);
        Assert.NotNull(identity.PublicKey);
        Assert.NotNull(identity.PrivateKey);
        Assert.Equal(32, identity.PublicKey.Length);
        Assert.Equal(32, identity.PrivateKey!.Length);
    }

    [Fact]
    public void Create_DifferentNames_ProduceDifferentDids()
    {
        var id1 = AgentIdentity.Create("agent-alpha");
        var id2 = AgentIdentity.Create("agent-beta");

        // DIDs should be different (they contain random components).
        Assert.NotEqual(id1.Did, id2.Did);
    }

    [Fact]
    public void Sign_ProducesConsistentSignature()
    {
        var identity = AgentIdentity.Create("signer");
        var data = "Hello, governance!"u8.ToArray();

        var sig1 = identity.Sign(data);
        var sig2 = identity.Sign(data);

        Assert.Equal(sig1, sig2);
        Assert.Equal(32, sig1.Length); // HMAC-SHA256 produces 32-byte output.
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

        // Flip a byte in the signature.
        var tampered = (byte[])signature.Clone();
        tampered[0] ^= 0xFF;
        Assert.False(identity.Verify(data, tampered));
    }

    [Fact]
    public void Verify_VerificationOnlyIdentity_ThrowsInvalidOperationException()
    {
        // An identity with no private key cannot verify in HMAC mode — throws to make the limitation explicit.
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
    public void ToString_ReturnsDid()
    {
        var identity = AgentIdentity.Create("display-test");
        Assert.Equal(identity.Did, identity.ToString());
    }
}
