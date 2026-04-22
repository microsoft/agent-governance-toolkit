// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Text;

namespace AgentGovernance.Trust;

/// <summary>
/// Provides peer verification capabilities using challenge-response protocols.
/// Verifies that a peer possesses the signing key corresponding to its claimed identity.
/// </summary>
public static class TrustVerifier
{
    /// <summary>
    /// The size in bytes of the random challenge nonce.
    /// </summary>
    private const int ChallengeSizeBytes = 32;

    /// <summary>
    /// Verifies a peer's identity using a challenge-response protocol.
    /// Generates a random challenge, has the peer sign it, and verifies the signature
    /// against the peer's claimed identity.
    /// </summary>
    /// <param name="peerId">The expected DID of the peer being verified.</param>
    /// <param name="peerIdentity">
    /// The <see cref="AgentIdentity"/> of the peer. Must have signing key material
    /// available for the .NET 8 compatibility implementation.
    /// </param>
    /// <returns><c>true</c> if the peer's identity is verified; otherwise <c>false</c>.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="peerId"/> is null or whitespace.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="peerIdentity"/> is <c>null</c>.
    /// </exception>
    /// <remarks>
    /// On .NET 8 this verifier uses the SDK's compatibility signing implementation.
    /// When the SDK grows native asymmetric signing support, the verifier can switch
    /// without changing the public API.
    /// </remarks>
    public static bool VerifyPeer(string peerId, AgentIdentity peerIdentity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(peerId);
        ArgumentNullException.ThrowIfNull(peerIdentity);

        // Step 1: Verify the claimed DID matches.
        if (peerIdentity.Did != AgentIdentity.NormalizeDid(peerId))
        {
            return false;
        }

        // Step 2: Peer must have a private key to prove identity.
        if (peerIdentity.PrivateKey is null)
        {
            return false;
        }

        // Step 3: Generate a random challenge.
        var challenge = RandomNumberGenerator.GetBytes(ChallengeSizeBytes);

        // Step 4: Peer signs the challenge.
        byte[] signature;
        try
        {
            signature = peerIdentity.Sign(challenge);
        }
        catch (InvalidOperationException)
        {
            return false;
        }

        // Step 5: Verify the signature.
        try
        {
            return peerIdentity.Verify(challenge, signature);
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }
}
