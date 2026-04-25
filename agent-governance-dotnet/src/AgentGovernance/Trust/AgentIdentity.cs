// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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

    /// <summary>The identity is temporarily suspended and cannot participate in governance operations.</summary>
    Suspended,

    /// <summary>The identity has been permanently revoked.</summary>
    Revoked
}

/// <summary>
/// Signing implementation used by an <see cref="AgentIdentity"/>.
/// </summary>
public enum IdentitySigningAlgorithm
{
    /// <summary>
    /// Legacy compatibility mode backed by HMAC-derived signatures.
    /// </summary>
    Compatibility,

    /// <summary>
    /// Native asymmetric signing using ECDSA P-256.
    /// </summary>
    EcdsaP256
}

/// <summary>
/// Represents an agent identity with compatibility signing, delegation metadata, and registry-friendly
/// sponsor and capability information.
/// </summary>
public sealed class AgentIdentity
{
    private const int KeySizeBytes = 32;
    private const string DefaultSponsorDomain = "agentmesh.dev";

    /// <summary>
    /// The canonical DID prefix used for new identities.
    /// </summary>
    public const string CanonicalDidPrefix = "did:mesh:";

    /// <summary>
    /// Legacy DID prefix accepted for backwards compatibility.
    /// </summary>
    public const string LegacyDidPrefix = "did:agentmesh:";

    /// <summary>
    /// MCP DID prefix for MCP-native agent identities.
    /// </summary>
    public const string McpDidPrefix = "did:mcp:";

    /// <summary>
    /// Maximum delegation depth allowed for child identities.
    /// </summary>
    public const int MaxDelegationDepth = 10;

    /// <summary>
    /// Service endpoint used in exported DID documents.
    /// </summary>
    public const string DefaultServiceEndpoint = "https://mesh.agentmesh.dev/v1";

    /// <summary>
    /// The decentralised identifier for this agent (e.g., "did:mesh:abc123...").
    /// </summary>
    public string Did { get; }

    /// <summary>
    /// Human-readable agent name.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// Optional agent description.
    /// </summary>
    public string? Description { get; }

    /// <summary>
    /// The public key bytes used for verification.
    /// </summary>
    public byte[] PublicKey { get; }

    /// <summary>
    /// The private key bytes used for signing. <c>null</c> for verification-only identities.
    /// </summary>
    public byte[]? PrivateKey { get; }

    /// <summary>
    /// Verification key identifier used in JWK and DID exports.
    /// </summary>
    public string VerificationKeyId { get; }

    /// <summary>
    /// Signing implementation used by this identity.
    /// </summary>
    public IdentitySigningAlgorithm SigningAlgorithm { get; }

    /// <summary>
    /// Human sponsor email for this identity.
    /// </summary>
    public string SponsorEmail { get; }

    /// <summary>
    /// Whether the sponsor has been verified.
    /// </summary>
    public bool SponsorVerified { get; }

    /// <summary>
    /// Whether external attestation for this identity has been verified.
    /// </summary>
    public bool AttestationVerified { get; }

    /// <summary>
    /// Organization name, if present.
    /// </summary>
    public string? Organization { get; }

    /// <summary>
    /// Organization identifier, if present.
    /// </summary>
    public string? OrganizationId { get; }

    /// <summary>
    /// Capabilities granted to this identity.
    /// </summary>
    public IReadOnlyList<string> Capabilities { get; }

    /// <summary>
    /// When the identity was created.
    /// </summary>
    public DateTime CreatedAt { get; }

    /// <summary>
    /// When the identity was last updated.
    /// </summary>
    public DateTime UpdatedAt { get; private set; }

    /// <summary>
    /// Optional expiration for this identity.
    /// </summary>
    public DateTime? ExpiresAt { get; }

    /// <summary>
    /// The current lifecycle status of this identity.
    /// </summary>
    public IdentityStatus Status { get; private set; } = IdentityStatus.Active;

    /// <summary>
    /// Optional revocation or suspension reason.
    /// </summary>
    public string? RevocationReason { get; private set; }

    /// <summary>
    /// Parent DID if this identity was delegated.
    /// </summary>
    public string? ParentDid { get; internal set; }

    /// <summary>
    /// Depth of this identity in the delegation chain.
    /// </summary>
    public int DelegationDepth { get; internal set; }

    /// <summary>
    /// Optional upper bound on the initial trust score of delegated identities.
    /// </summary>
    public int? MaxInitialTrustScore { get; internal set; }

    /// <summary>
    /// Returns whether this identity is currently active and unexpired.
    /// </summary>
    public bool IsActive()
    {
        if (Status != IdentityStatus.Active)
        {
            return false;
        }

        return ExpiresAt is null || DateTime.UtcNow <= ExpiresAt.Value;
    }

    /// <summary>
    /// Initializes a new <see cref="AgentIdentity"/>.
    /// </summary>
    public AgentIdentity(
        string did,
        byte[] publicKey,
        byte[]? privateKey = null,
        string? name = null,
        string? description = null,
        string? sponsorEmail = null,
        bool sponsorVerified = false,
        string? organization = null,
        string? organizationId = null,
        IEnumerable<string>? capabilities = null,
        DateTime? createdAt = null,
        DateTime? updatedAt = null,
        DateTime? expiresAt = null,
        string? parentDid = null,
        int delegationDepth = 0,
        int? maxInitialTrustScore = null,
        string? verificationKeyId = null,
        bool attestationVerified = false,
        IdentityStatus status = IdentityStatus.Active,
        string? revocationReason = null,
        IdentitySigningAlgorithm signingAlgorithm = IdentitySigningAlgorithm.Compatibility)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(did);
        ArgumentNullException.ThrowIfNull(publicKey);

        Did = NormalizeDid(did);
        PublicKey = (byte[])publicKey.Clone();
        PrivateKey = privateKey is null ? null : (byte[])privateKey.Clone();
        Name = string.IsNullOrWhiteSpace(name) ? ExtractNameFromDid(Did) : name.Trim();
        Description = description;
        SponsorEmail = NormalizeSponsorEmail(sponsorEmail, Name);
        SponsorVerified = sponsorVerified;
        AttestationVerified = attestationVerified;
        Organization = organization;
        OrganizationId = organizationId;
        Capabilities = NormalizeCapabilities(capabilities);
        CreatedAt = EnsureUtc(createdAt ?? DateTime.UtcNow);
        UpdatedAt = EnsureUtc(updatedAt ?? CreatedAt);
        ExpiresAt = expiresAt is null ? null : EnsureUtc(expiresAt.Value);
        ParentDid = string.IsNullOrWhiteSpace(parentDid) ? null : NormalizeDid(parentDid);
        DelegationDepth = delegationDepth;
        MaxInitialTrustScore = maxInitialTrustScore;
        VerificationKeyId = string.IsNullOrWhiteSpace(verificationKeyId)
            ? CreateVerificationKeyId(PublicKey)
            : verificationKeyId;
        Status = status;
        RevocationReason = revocationReason;
        SigningAlgorithm = signingAlgorithm;
    }

    /// <summary>
    /// Creates a new agent identity with a freshly generated key pair.
    /// </summary>
    public static AgentIdentity Create(
        string name,
        string? sponsor = null,
        IEnumerable<string>? capabilities = null,
        string? organization = null,
        string? description = null,
        string? organizationId = null,
        bool sponsorVerified = false,
        DateTime? expiresAt = null,
        bool attestationVerified = false)
    {
        return CreateCompatibility(
            name,
            sponsor,
            capabilities,
            organization,
            description,
            organizationId,
            sponsorVerified,
            expiresAt,
            attestationVerified);
    }

    /// <summary>
    /// Creates a new agent identity using the legacy compatibility signing mode.
    /// </summary>
    public static AgentIdentity CreateCompatibility(
        string name,
        string? sponsor = null,
        IEnumerable<string>? capabilities = null,
        string? organization = null,
        string? description = null,
        string? organizationId = null,
        bool sponsorVerified = false,
        DateTime? expiresAt = null,
        bool attestationVerified = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        var privateKey = RandomNumberGenerator.GetBytes(KeySizeBytes);
        var publicKey = DerivePublicKey(privateKey);

        return new AgentIdentity(
            did: GenerateDid(name, organization),
            publicKey: publicKey,
            privateKey: privateKey,
            name: name,
            description: description,
            sponsorEmail: sponsor,
            sponsorVerified: sponsorVerified,
            organization: organization,
            organizationId: organizationId,
            capabilities: capabilities,
            expiresAt: expiresAt,
            attestationVerified: attestationVerified,
            signingAlgorithm: IdentitySigningAlgorithm.Compatibility);
    }

    /// <summary>
    /// Creates a new agent identity with native asymmetric ECDSA P-256 signing.
    /// </summary>
    public static AgentIdentity CreateAsymmetric(
        string name,
        string? sponsor = null,
        IEnumerable<string>? capabilities = null,
        string? organization = null,
        string? description = null,
        string? organizationId = null,
        bool sponsorVerified = false,
        DateTime? expiresAt = null,
        bool attestationVerified = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        var privateKey = ecdsa.ExportPkcs8PrivateKey();

        return new AgentIdentity(
            did: GenerateDid(name, organization),
            publicKey: publicKey,
            privateKey: privateKey,
            name: name,
            description: description,
            sponsorEmail: sponsor,
            sponsorVerified: sponsorVerified,
            organization: organization,
            organizationId: organizationId,
            capabilities: capabilities,
            expiresAt: expiresAt,
            attestationVerified: attestationVerified,
            signingAlgorithm: IdentitySigningAlgorithm.EcdsaP256);
    }

    /// <summary>
    /// Suspends this identity.
    /// </summary>
    public void Suspend(string? reason = null)
    {
        if (Status == IdentityStatus.Revoked)
        {
            throw new InvalidOperationException("Cannot suspend a revoked identity.");
        }

        Status = IdentityStatus.Suspended;
        RevocationReason = reason ?? RevocationReason;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Permanently revokes this identity.
    /// </summary>
    public void Revoke(string? reason = null)
    {
        Status = IdentityStatus.Revoked;
        RevocationReason = reason ?? RevocationReason;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Reactivates a suspended identity.
    /// </summary>
    public void Reactivate(bool overrideReason = false)
    {
        if (Status == IdentityStatus.Revoked)
        {
            throw new InvalidOperationException("Cannot reactivate a revoked identity.");
        }

        if (Status == IdentityStatus.Suspended
            && !overrideReason
            && !string.IsNullOrWhiteSpace(RevocationReason)
            && RevocationReason.Contains("security", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Identity was suspended for security reasons. Pass overrideReason=true to reactivate.");
        }

        Status = IdentityStatus.Active;
        RevocationReason = null;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Signs data using the configured identity signing implementation.
    /// </summary>
    public byte[] Sign(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        if (PrivateKey is null)
        {
            throw new InvalidOperationException(
                "Cannot sign data: this identity does not have a private key.");
        }

        return SigningAlgorithm switch
        {
            IdentitySigningAlgorithm.Compatibility => SignCompatibility(data, PrivateKey),
            IdentitySigningAlgorithm.EcdsaP256 => SignEcdsaP256(data, PrivateKey),
            _ => throw new InvalidOperationException($"Unsupported signing algorithm '{SigningAlgorithm}'.")
        };
    }

    /// <summary>
    /// Signs a string message using UTF-8 encoding.
    /// </summary>
    public byte[] Sign(string message)
    {
        ArgumentNullException.ThrowIfNull(message);
        return Sign(Encoding.UTF8.GetBytes(message));
    }

    /// <summary>
    /// Verifies a signature using this identity's available key material.
    /// </summary>
    public bool Verify(byte[] data, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);

        return SigningAlgorithm switch
        {
            IdentitySigningAlgorithm.Compatibility => VerifyCompatibility(data, signature, PrivateKey),
            IdentitySigningAlgorithm.EcdsaP256 => VerifyEcdsaP256(PublicKey, data, signature),
            _ => throw new InvalidOperationException($"Unsupported signing algorithm '{SigningAlgorithm}'.")
        };
    }

    /// <summary>
    /// Verifies a signature using standalone key material.
    /// </summary>
    public static bool VerifySignature(
        byte[] publicKey,
        byte[] data,
        byte[] signature,
        byte[]? privateKey = null,
        IdentitySigningAlgorithm signingAlgorithm = IdentitySigningAlgorithm.Compatibility)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);

        return signingAlgorithm switch
        {
            IdentitySigningAlgorithm.Compatibility => VerifyCompatibility(data, signature, privateKey),
            IdentitySigningAlgorithm.EcdsaP256 => VerifyEcdsaP256(publicKey, data, signature),
            _ => throw new InvalidOperationException($"Unsupported signing algorithm '{signingAlgorithm}'.")
        };
    }

    /// <summary>
    /// Checks whether the identity has a specific capability.
    /// Supports exact matches and prefix wildcards such as <c>read:*</c>.
    /// </summary>
    public bool HasCapability(string capability)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(capability);

        foreach (var granted in Capabilities)
        {
            if (granted == "*" || string.Equals(granted, capability, StringComparison.Ordinal))
            {
                return true;
            }

            if (granted.EndsWith(":*", StringComparison.Ordinal) && granted.Length > 2)
            {
                var prefix = granted[..^2];
                if (capability.StartsWith(prefix + ":", StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Delegates a narrowed set of capabilities to a child identity.
    /// </summary>
    public AgentIdentity Delegate(
        string name,
        IEnumerable<string> capabilities,
        string? description = null,
        int? maxInitialTrustScore = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(capabilities);

        if (DelegationDepth >= MaxDelegationDepth)
        {
            throw new InvalidOperationException(
                $"Maximum delegation depth ({MaxDelegationDepth}) exceeded.");
        }

        var delegated = NormalizeCapabilities(capabilities);
        if (delegated.Contains("*", StringComparer.Ordinal))
        {
            throw new InvalidOperationException(
                "Cannot delegate wildcard capability '*'. Explicitly list delegated capabilities.");
        }

        foreach (var capability in delegated)
        {
            if (!HasCapability(capability))
            {
                throw new InvalidOperationException(
                    $"Cannot delegate capability '{capability}' because it is not in the parent scope.");
            }
        }

        var child = SigningAlgorithm == IdentitySigningAlgorithm.EcdsaP256
            ? CreateAsymmetric(
                name: name,
                sponsor: SponsorEmail,
                capabilities: delegated,
                organization: Organization,
                description: description,
                organizationId: OrganizationId,
                sponsorVerified: SponsorVerified,
                expiresAt: ExpiresAt,
                attestationVerified: AttestationVerified)
            : CreateCompatibility(
                name: name,
                sponsor: SponsorEmail,
                capabilities: delegated,
                organization: Organization,
                description: description,
                organizationId: OrganizationId,
                sponsorVerified: SponsorVerified,
                expiresAt: ExpiresAt,
                attestationVerified: AttestationVerified);

        child.ParentDid = Did;
        child.DelegationDepth = DelegationDepth + 1;
        child.MaxInitialTrustScore = maxInitialTrustScore;
        return child;
    }

    /// <summary>
    /// Verifies that an identity's delegation chain is structurally valid.
    /// </summary>
    public static bool VerifyDelegationChain(
        AgentIdentity identity,
        IdentityRegistry? registry = null,
        HashSet<string>? visited = null)
    {
        ArgumentNullException.ThrowIfNull(identity);

        visited ??= new HashSet<string>(StringComparer.Ordinal);
        if (!visited.Add(identity.Did))
        {
            return false;
        }

        if (identity.ParentDid is null)
        {
            return identity.DelegationDepth == 0;
        }

        if (identity.DelegationDepth <= 0)
        {
            return false;
        }

        if (registry is null)
        {
            return true;
        }

        if (!registry.TryGet(identity.ParentDid, out var parent) || parent is null)
        {
            return false;
        }

        if (!parent.IsActive())
        {
            return false;
        }

        foreach (var capability in identity.Capabilities)
        {
            if (!parent.HasCapability(capability))
            {
                return false;
            }
        }

        if (identity.DelegationDepth != parent.DelegationDepth + 1)
        {
            return false;
        }

        return VerifyDelegationChain(parent, registry, visited);
    }

    /// <summary>
    /// Returns the intersection of capabilities across the full delegation chain.
    /// </summary>
    public IReadOnlyList<string> GetEffectiveCapabilities(IdentityRegistry? registry = null)
    {
        var current = new HashSet<string>(Capabilities, StringComparer.Ordinal);
        if (ParentDid is null || registry is null)
        {
            return current.OrderBy(capability => capability, StringComparer.Ordinal).ToList();
        }

        var visited = new HashSet<string>(StringComparer.Ordinal) { Did };
        var identity = this;

        while (identity.ParentDid is not null)
        {
            if (!visited.Add(identity.ParentDid))
            {
                break;
            }

            if (!registry.TryGet(identity.ParentDid, out var parent) || parent is null)
            {
                break;
            }

            current.IntersectWith(parent.Capabilities);
            identity = parent;
        }

        return current.OrderBy(capability => capability, StringComparer.Ordinal).ToList();
    }

    /// <summary>
    /// Normalizes a DID into the canonical AgentMesh form.
    /// </summary>
    public static string NormalizeDid(string did)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(did);

        var trimmed = did.Trim();
        if (trimmed.StartsWith(LegacyDidPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return CanonicalDidPrefix + trimmed[LegacyDidPrefix.Length..];
        }

        if (trimmed.StartsWith(CanonicalDidPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return CanonicalDidPrefix + trimmed[CanonicalDidPrefix.Length..];
        }

        if (trimmed.StartsWith(McpDidPrefix, StringComparison.OrdinalIgnoreCase))
        {
            // Accept MCP DIDs as-is (do not normalize to did:mesh:)
            return trimmed;
        }

        throw new ArgumentException(
            $"Invalid AgentMesh DID '{did}'. Expected prefix '{CanonicalDidPrefix}' or legacy prefix '{LegacyDidPrefix}'.",
            nameof(did));
    }

    /// <inheritdoc />
    public override string ToString() => Did;

    private static string GenerateDid(string name, string? organization)
    {
        var uniqueId = GenerateUniqueId(name, organization);
        return CanonicalDidPrefix + uniqueId;
    }

    private static string GenerateUniqueId(string name, string? organization)
    {
        var seed = $"{name}:{organization ?? "default"}:{Convert.ToHexString(RandomNumberGenerator.GetBytes(4))}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(seed));
        return Convert.ToHexString(hash[..16]).ToLowerInvariant();
    }

    private static byte[] DerivePublicKey(byte[] privateKey)
    {
        return SHA256.HashData(privateKey)[..KeySizeBytes];
    }

    private static byte[] SignCompatibility(byte[] data, byte[]? privateKey)
    {
        if (privateKey is null)
        {
            throw new InvalidOperationException(
                "Cannot sign data: this identity does not have a private key.");
        }

        using var hmac = new HMACSHA256(privateKey);
        return hmac.ComputeHash(data);
    }

    private static byte[] SignEcdsaP256(byte[] data, byte[]? privateKey)
    {
        if (privateKey is null)
        {
            throw new InvalidOperationException(
                "Cannot sign data: this identity does not have a private key.");
        }

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportPkcs8PrivateKey(privateKey, out _);
        return ecdsa.SignData(data, HashAlgorithmName.SHA256);
    }

    private static bool VerifyCompatibility(byte[] data, byte[] signature, byte[]? privateKey)
    {
        if (privateKey is null)
        {
            throw new InvalidOperationException(
                "Cannot verify signature without private key material in the compatibility implementation.");
        }

        using var hmac = new HMACSHA256(privateKey);
        var expected = hmac.ComputeHash(data);
        return CryptographicOperations.FixedTimeEquals(expected, signature);
    }

    private static bool VerifyEcdsaP256(byte[] publicKey, byte[] data, byte[] signature)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(publicKey, out _);
        return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
    }

    private static string CreateVerificationKeyId(byte[] publicKey)
    {
        var hash = SHA256.HashData(publicKey);
        return $"key-{Convert.ToHexString(hash[..8]).ToLowerInvariant()}";
    }

    private static string NormalizeSponsorEmail(string? sponsorEmail, string name)
    {
        if (string.IsNullOrWhiteSpace(sponsorEmail))
        {
            return $"{Slugify(name)}@{DefaultSponsorDomain}";
        }

        var trimmed = sponsorEmail.Trim();
        if (!trimmed.Contains('@', StringComparison.Ordinal))
        {
            throw new ArgumentException($"Invalid sponsor email format: '{trimmed}'.", nameof(sponsorEmail));
        }

        return trimmed;
    }

    private static IReadOnlyList<string> NormalizeCapabilities(IEnumerable<string>? capabilities)
    {
        if (capabilities is null)
        {
            return Array.Empty<string>();
        }

        return capabilities
            .Where(capability => !string.IsNullOrWhiteSpace(capability))
            .Select(capability => capability.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToList();
    }

    private static string Slugify(string name)
    {
        var builder = new StringBuilder();
        foreach (var character in name.ToLowerInvariant())
        {
            builder.Append(char.IsLetterOrDigit(character) ? character : '-');
        }

        var slug = builder.ToString().Trim('-');
        return string.IsNullOrWhiteSpace(slug) ? "agent" : slug;
    }

    private static string ExtractNameFromDid(string did)
    {
        var lastSegment = did[(did.LastIndexOf(':') + 1)..];
        return string.IsNullOrWhiteSpace(lastSegment) ? "agent" : lastSegment;
    }

    private static DateTime EnsureUtc(DateTime value)
    {
        return value.Kind == DateTimeKind.Utc
            ? value
            : DateTime.SpecifyKind(value, DateTimeKind.Utc);
    }
}
