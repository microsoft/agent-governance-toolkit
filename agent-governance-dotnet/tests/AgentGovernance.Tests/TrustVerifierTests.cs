// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Trust;
using Xunit;

namespace AgentGovernance.Tests;

public class TrustVerifierTests
{
    [Fact]
    public void VerifyPeer_ValidIdentity_ReturnsTrue()
    {
        var identity = AgentIdentity.Create("peer-agent");
        Assert.True(TrustVerifier.VerifyPeer(identity.Did, identity));
    }

    [Fact]
    public void VerifyPeer_MismatchedDid_ReturnsFalse()
    {
        var identity = AgentIdentity.Create("peer-agent");
        Assert.False(TrustVerifier.VerifyPeer("did:mesh:wrong-id", identity));
    }

    [Fact]
    public void VerifyPeer_NoPrivateKey_ReturnsFalse()
    {
        var identity = AgentIdentity.Create("peer-agent");
        var publicOnly = new AgentIdentity(identity.Did, identity.PublicKey);

        Assert.False(TrustVerifier.VerifyPeer(identity.Did, publicOnly));
    }

    [Fact]
    public void VerifyPeer_NullPeerId_ThrowsArgumentException()
    {
        var identity = AgentIdentity.Create("peer-agent");
        Assert.ThrowsAny<ArgumentException>(() => TrustVerifier.VerifyPeer(null!, identity));
    }

    [Fact]
    public void VerifyPeer_NullIdentity_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            TrustVerifier.VerifyPeer("did:mesh:test", null!));
    }

    [Fact]
    public void VerifyPeer_MultipleVerifications_AllSucceed()
    {
        var identity = AgentIdentity.Create("consistent-peer");

        for (int i = 0; i < 5; i++)
        {
            Assert.True(TrustVerifier.VerifyPeer(identity.Did, identity));
        }
    }

    [Fact]
    public void VerifyPeer_DifferentAgents_EachVerifyIndependently()
    {
        var agent1 = AgentIdentity.Create("agent-1");
        var agent2 = AgentIdentity.Create("agent-2");

        Assert.True(TrustVerifier.VerifyPeer(agent1.Did, agent1));
        Assert.True(TrustVerifier.VerifyPeer(agent2.Did, agent2));

        // Cross-verification should fail (DID mismatch).
        Assert.False(TrustVerifier.VerifyPeer(agent1.Did, agent2));
    }
}
