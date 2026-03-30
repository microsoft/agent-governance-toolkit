// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Security.Cryptography;
using System.Text;

namespace AgentGovernance.Trust;

/// <summary>
/// Represents the lifecycle status of an agent identity.
/// </summary>
public enum IdentityStatus
{
    /// <summary>The identity is active and can participate in governance operations.</summary>
    Active,

    /// <summary>The identity is temporarily suspended and cannot sign or verify.</summary>
    Suspended,

    /// <summary>The identity has been permanently revoked.</summary>
    Revoked
}

/// <summary>
/// Represents an agent identity with cryptographic signing and verification capabilities.
/// <para>
/// Uses HMAC-SHA256 as a portable signing mechanism for .NET 8.0 compatibility.
/// When targeting .NET 9.0+, this should be migrated to the native
/// <c>System.Security.Cryptography.Ed25519</c> API for proper Ed25519 support.
/// The DID format follows the AgentMesh convention: <c>did:mesh:{unique-id}</c>.
/// </para>
/// </summary>
/// <remarks>
/// <b>Migration note (.NET 9+):</b> Replace HMAC-SHA256 with Ed25519:
/// <code>
/// // .NET 9+ Ed25519 example:
/// using var key = Ed25519.Create();
/// byte[] signature = key.SignData(data);
/// bool valid = key.VerifyData(data, signature);
/// </code>
/// </remarks>
public sealed class AgentIdentity
{
    /// <summary>
    /// The key size in bytes used for HMAC-SHA256 signing keys.
    /// Matches the Ed25519 key size (32 bytes) for forward-compatible serialisation.
    /// </summary>
    private const int KeySizeBytes = 32;

    /// <summary>
    /// The decentralised identifier for this agent (e.g., "did:mesh:a1b2c3d4").
    /// </summary>
    public string Did { get; }

    /// <summary>
    /// The public key bytes. In the HMAC-SHA256 fallback, this is a 32-byte
    /// truncated SHA-256 hash of the private key. With Ed25519, this would be
    /// the actual Ed25519 public key.
    /// </summary>
    public byte[] PublicKey { get; }

    /// <summary>
    /// The private key bytes used for signing. <c>null</c> for verification-only identities.
    /// </summary>
    public byte[]? PrivateKey { get; }

    /// <summary>
    /// The current lifecycle status of this identity.
    /// </summary>
    public IdentityStatus Status { get; private set; } = IdentityStatus.Active;

    /// <summary>
    /// Suspends this identity, preventing it from participating in governance operations.
    /// A suspended identity can be reactivated.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the identity is already revoked.
    /// </exception>
    public void Suspend()
    {
        if (Status == IdentityStatus.Revoked)
        {
            throw new InvalidOperationException(
                "Cannot suspend a revoked identity.");
        }

        Status = IdentityStatus.Suspended;
    }

    /// <summary>
    /// Permanently revokes this identity. A revoked identity cannot be reactivated.
    /// </summary>
    public void Revoke()
    {
        Status = IdentityStatus.Revoked;
    }

    /// <summary>
    /// Reactivates a suspended identity, restoring it to active status.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the identity is revoked and cannot be reactivated.
    /// </exception>
    public void Reactivate()
    {
        if (Status == IdentityStatus.Revoked)
        {
            throw new InvalidOperationException(
                "Cannot reactivate a revoked identity.");
        }

        Status = IdentityStatus.Active;
    }

    /// <summary>
    /// Returns whether this identity is currently active.
    /// </summary>
    /// <returns><c>true</c> if the identity status is <see cref="IdentityStatus.Active"/>; otherwise <c>false</c>.</returns>
    public bool IsActive() => Status == IdentityStatus.Active;

    /// <summary>
    /// Initializes a new <see cref="AgentIdentity"/> with the specified DID and key material.
    /// </summary>
    /// <param name="did">The decentralised identifier.</param>
    /// <param name="publicKey">The public key bytes.</param>
    /// <param name="privateKey">The private key bytes, or <c>null</c> for verification-only identities.</param>
    public AgentIdentity(string did, byte[] publicKey, byte[]? privateKey = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(did);
        ArgumentNullException.ThrowIfNull(publicKey);

        Did = did;
        PublicKey = publicKey;
        PrivateKey = privateKey;
    }

    /// <summary>
    /// Creates a new agent identity with a freshly generated key pair.
    /// The DID is derived from the agent name using the <c>did:mesh:</c> method.
    /// </summary>
    /// <param name="name">A human-readable name for the agent (used to derive the DID).</param>
    /// <returns>A new <see cref="AgentIdentity"/> with both public and private keys.</returns>
    public static AgentIdentity Create(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        // Generate a deterministic-format DID from the name + random component.
        var uniqueId = GenerateUniqueId(name);
        var did = $"did:mesh:{uniqueId}";

        // Generate a random 32-byte private key.
        var privateKey = RandomNumberGenerator.GetBytes(KeySizeBytes);

        // Derive public key: SHA-256 hash of the private key (HMAC-SHA256 fallback).
        var publicKey = DerivePublicKey(privateKey);

        return new AgentIdentity(did, publicKey, privateKey);
    }

    /// <summary>
    /// Signs the provided data using this identity's private key.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <returns>A 32-byte HMAC-SHA256 signature.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when this identity does not have a private key (verification-only).
    /// </exception>
    /// <remarks>
    /// ⚠️ <b>SECURITY WARNING (CWE-327):</b> This method uses HMAC-SHA256 as a compatibility
    /// fallback. HMAC-SHA256 is a symmetric scheme — both signing and verification require the
    /// private key, which is unsuitable for cross-agent trust scenarios. Prefer Ed25519 (available
    /// natively in .NET 9+) for production deployments. This fallback exists only for backward
    /// compatibility with .NET 8.0 environments and should be considered deprecated.
    /// </remarks>
    [Obsolete("HMAC-SHA256 signing is a compatibility fallback. Migrate to Ed25519 on .NET 9+ for proper asymmetric signing.")]
    public byte[] Sign(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        if (PrivateKey is null)
        {
            throw new InvalidOperationException(
                "Cannot sign data: this identity does not have a private key.");
        }

        System.Diagnostics.Trace.TraceWarning(
            "[AgentIdentity] Using HMAC-SHA256 fallback for signing. " +
            "This is deprecated — migrate to Ed25519 on .NET 9+ for proper asymmetric cryptography.");

        using var hmac = new HMACSHA256(PrivateKey);
        return hmac.ComputeHash(data);
    }

    /// <summary>
    /// Signs a string message using this identity's private key.
    /// </summary>
    /// <param name="message">The message to sign.</param>
    /// <returns>A 32-byte HMAC-SHA256 signature.</returns>
    /// <inheritdoc cref="Sign(byte[])" path="/remarks"/>
    [Obsolete("HMAC-SHA256 signing is a compatibility fallback. Migrate to Ed25519 on .NET 9+ for proper asymmetric signing.")]
    public byte[] Sign(string message)
    {
        ArgumentNullException.ThrowIfNull(message);
        return Sign(Encoding.UTF8.GetBytes(message));
    }

    /// <summary>
    /// Verifies a signature against data using this identity's key material.
    /// </summary>
    /// <param name="data">The data that was signed.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <returns><c>true</c> if the signature is valid; otherwise <c>false</c>.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when this identity does not have a private key. HMAC-SHA256
    /// verification requires the signing key. For public-key verification,
    /// migrate to Ed25519 on .NET 9+.
    /// </exception>
    /// <remarks>
    /// ⚠️ <b>SECURITY WARNING (CWE-327):</b> HMAC-SHA256 verification requires the private key,
    /// making it unsuitable for public-key-only verification. Migrate to Ed25519 on .NET 9+.
    /// </remarks>
    [Obsolete("HMAC-SHA256 verification is a compatibility fallback. Migrate to Ed25519 on .NET 9+ for public-key verification.")]
    public bool Verify(byte[] data, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);

        if (PrivateKey is null)
        {
            throw new InvalidOperationException(
                "Cannot verify signature: HMAC-SHA256 requires the private key. " +
                "For cross-agent verification with only a public key, migrate to Ed25519 (.NET 9+).");
        }

#pragma warning disable CS0618 // Intentional use of deprecated Sign() for HMAC fallback path
        var expected = Sign(data);
#pragma warning restore CS0618
        return CryptographicOperations.FixedTimeEquals(expected, signature);
    }

    /// <summary>
    /// Verifies a signature using a standalone key pair.
    /// This static overload is provided for cross-agent verification scenarios.
    /// </summary>
    /// <param name="publicKey">The public key of the signer (unused in HMAC mode; reserved for Ed25519).</param>
    /// <param name="data">The signed data.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <param name="privateKey">
    /// The private key for HMAC recomputation. Required for HMAC-SHA256;
    /// will not be needed with Ed25519 on .NET 9+.
    /// </param>
    /// <returns><c>true</c> if the signature is valid; otherwise <c>false</c>.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <paramref name="privateKey"/> is <c>null</c> because HMAC-SHA256
    /// cannot verify without the signing key.
    /// </exception>
    /// <remarks>
    /// ⚠️ <b>SECURITY WARNING (CWE-327):</b> This static overload uses HMAC-SHA256, which
    /// requires the private key for verification — defeating the purpose of public-key
    /// cryptography. Migrate to Ed25519 on .NET 9+ where only the public key is needed.
    /// </remarks>
    [Obsolete("HMAC-SHA256 verification is a compatibility fallback. Migrate to Ed25519 on .NET 9+ for public-key verification.")]
    public static bool VerifySignature(byte[] publicKey, byte[] data, byte[] signature, byte[]? privateKey = null)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);

        if (privateKey is null)
        {
            throw new InvalidOperationException(
                "Cannot verify signature: HMAC-SHA256 requires the private key. " +
                "For public-key-only verification, migrate to Ed25519 (.NET 9+).");
        }

        using var hmac = new HMACSHA256(privateKey);
        var expected = hmac.ComputeHash(data);
        return CryptographicOperations.FixedTimeEquals(expected, signature);
    }

    /// <summary>
    /// Generates a unique identifier component for a DID based on the agent name.
    /// Combines the name hash with random bytes for uniqueness.
    /// </summary>
    private static string GenerateUniqueId(string name)
    {
        // Hash the name for a deterministic prefix, append random bytes for uniqueness.
        var nameBytes = Encoding.UTF8.GetBytes(name);
        var hash = SHA256.HashData(nameBytes);
        var randomBytes = RandomNumberGenerator.GetBytes(4);

        // Take first 4 bytes of name hash + 4 random bytes = 8 hex chars each.
        return Convert.ToHexString(hash[..4]).ToLowerInvariant()
             + Convert.ToHexString(randomBytes).ToLowerInvariant();
    }

    /// <summary>
    /// Derives a public key from the private key using SHA-256.
    /// This is a placeholder for Ed25519 key derivation.
    /// </summary>
    private static byte[] DerivePublicKey(byte[] privateKey)
    {
        return SHA256.HashData(privateKey)[..KeySizeBytes];
    }

    /// <inheritdoc />
    public override string ToString() => Did;
}
