// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Text;

namespace AgentGovernance.Trust;

/// <summary>
/// Provides peer verification capabilities using challenge-response protocols.
/// Verifies that a peer possesses the private key corresponding to its claimed identity.
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
    /// The <see cref="AgentIdentity"/> of the peer. Must have a private key
    /// for signing the challenge (HMAC-SHA256 fallback mode).
    /// </param>
    /// <returns><c>true</c> if the peer's identity is verified; otherwise <c>false</c>.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="peerId"/> is null or whitespace.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="peerIdentity"/> is <c>null</c>.
    /// </exception>
    /// <remarks>
    /// ⚠️ <b>SECURITY WARNING (CWE-327):</b> This method uses HMAC-SHA256 as a compatibility
    /// fallback. In HMAC mode, the verifier must have access to the peer's private key.
    /// Migrate to Ed25519 on .NET 9+ for proper asymmetric challenge-response verification.
    /// </remarks>
    public static bool VerifyPeer(string peerId, AgentIdentity peerIdentity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(peerId);
        ArgumentNullException.ThrowIfNull(peerIdentity);

        // Step 1: Verify the claimed DID matches.
        if (peerIdentity.Did != peerId)
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
#pragma warning disable CS0618 // Intentional use of deprecated Sign() for HMAC fallback path
            signature = peerIdentity.Sign(challenge);
#pragma warning restore CS0618
        }
        catch (InvalidOperationException)
        {
            return false;
        }

        // Step 5: Verify the signature.
        try
        {
#pragma warning disable CS0618 // Intentional use of deprecated Verify() for HMAC fallback path
            return peerIdentity.Verify(challenge, signature);
#pragma warning restore CS0618
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }
}
