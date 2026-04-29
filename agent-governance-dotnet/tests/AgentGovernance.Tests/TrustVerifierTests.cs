// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Trust;
using System.Security.Cryptography;
using Xunit;

namespace AgentGovernance.Tests;

public class TrustVerifierTests
{
    [Fact]
    public void VerifyPeer_ValidAsymmetricProof_ReturnsTrue()
    {
        var signingIdentity = AgentIdentity.CreateAsymmetric("peer-agent");
        var presentedIdentity = CreateVerificationOnlyIdentity(signingIdentity);
        var challenge = RandomNumberGenerator.GetBytes(32);
        var signature = signingIdentity.Sign(challenge);

        Assert.True(TrustVerifier.VerifyPeer(signingIdentity.Did, presentedIdentity, challenge, signature));
    }

    [Fact]
    public void VerifyPeer_MismatchedDid_ReturnsFalse()
    {
        var identity = AgentIdentity.CreateAsymmetric("peer-agent");
        var challenge = RandomNumberGenerator.GetBytes(32);
        var signature = identity.Sign(challenge);

        Assert.False(TrustVerifier.VerifyPeer("did:mesh:wrong-id", identity, challenge, signature));
    }

    [Fact]
    public void VerifyPeer_InvalidSignature_ReturnsFalse()
    {
        var identity = AgentIdentity.CreateAsymmetric("peer-agent");
        var challenge = RandomNumberGenerator.GetBytes(32);
        var signature = identity.Sign(challenge);
        signature[0] ^= 0xFF;

        Assert.False(TrustVerifier.VerifyPeer(identity.Did, identity, challenge, signature));
    }

    [Fact]
    public void VerifyPeer_CompatibilityIdentity_ReturnsFalse()
    {
        var identity = AgentIdentity.Create("peer-agent");
        var challenge = RandomNumberGenerator.GetBytes(32);
        var signature = identity.Sign(challenge);

        Assert.False(TrustVerifier.VerifyPeer(identity.Did, identity, challenge, signature));
    }

    [Fact]
    public void VerifyPeer_EmptyChallenge_ReturnsFalse()
    {
        var identity = AgentIdentity.CreateAsymmetric("peer-agent");
        var signature = identity.Sign(new byte[] { 1 });

        Assert.False(TrustVerifier.VerifyPeer(identity.Did, identity, Array.Empty<byte>(), signature));
    }

    [Fact]
    public void VerifyPeer_EmptySignature_ReturnsFalse()
    {
        var identity = AgentIdentity.CreateAsymmetric("peer-agent");
        var challenge = RandomNumberGenerator.GetBytes(32);

        Assert.False(TrustVerifier.VerifyPeer(identity.Did, identity, challenge, Array.Empty<byte>()));
    }

    [Fact]
    public void VerifyPeer_NullPeerId_ThrowsArgumentException()
    {
        var identity = AgentIdentity.CreateAsymmetric("peer-agent");
        var challenge = RandomNumberGenerator.GetBytes(32);
        var signature = identity.Sign(challenge);

        Assert.ThrowsAny<ArgumentException>(() => TrustVerifier.VerifyPeer(null!, identity, challenge, signature));
    }

    [Fact]
    public void VerifyPeer_NullIdentity_ThrowsArgumentNullException()
    {
        var challenge = RandomNumberGenerator.GetBytes(32);
        var signature = new byte[] { 1 };

        Assert.Throws<ArgumentNullException>(() =>
            TrustVerifier.VerifyPeer("did:mesh:test", null!, challenge, signature));
    }

    [Fact]
    public void VerifyPeer_NullChallenge_ThrowsArgumentNullException()
    {
        var identity = AgentIdentity.CreateAsymmetric("peer-agent");
        var signature = new byte[] { 1 };

        Assert.Throws<ArgumentNullException>(() =>
            TrustVerifier.VerifyPeer(identity.Did, identity, null!, signature));
    }

    [Fact]
    public void VerifyPeer_NullSignature_ThrowsArgumentNullException()
    {
        var identity = AgentIdentity.CreateAsymmetric("peer-agent");
        var challenge = RandomNumberGenerator.GetBytes(32);

        Assert.Throws<ArgumentNullException>(() =>
            TrustVerifier.VerifyPeer(identity.Did, identity, challenge, null!));
    }

    [Fact]
    public void VerifyPeer_LegacyOverload_ReturnsFalse()
    {
        var identity = AgentIdentity.CreateAsymmetric("peer-agent");

#pragma warning disable CS0618
        Assert.False(TrustVerifier.VerifyPeer(identity.Did, identity));
#pragma warning restore CS0618
    }

    private static AgentIdentity CreateVerificationOnlyIdentity(AgentIdentity identity)
    {
        return new AgentIdentity(
            did: identity.Did,
            publicKey: identity.PublicKey,
            name: identity.Name,
            signingAlgorithm: identity.SigningAlgorithm);
    }
}
