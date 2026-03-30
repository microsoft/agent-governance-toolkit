// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace AgentGovernance.Trust;

/// <summary>
/// Provides JWK (JSON Web Key) and DID Document serialisation for <see cref="AgentIdentity"/>.
/// </summary>
public static class Jwk
{
    /// <summary>
    /// Converts an <see cref="AgentIdentity"/>'s public key to a JWK (JSON Web Key) dictionary.
    /// Uses the OKP key type with Ed25519 curve, following RFC 8037.
    /// </summary>
    /// <param name="identity">The agent identity to convert.</param>
    /// <returns>
    /// A dictionary with keys <c>kty</c>, <c>crv</c>, and <c>x</c> representing
    /// an OKP/Ed25519 JWK.
    /// </returns>
    public static Dictionary<string, string> ToJwk(this AgentIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);

        return new Dictionary<string, string>
        {
            ["kty"] = "OKP",
            ["crv"] = "Ed25519",
            ["x"] = Base64UrlEncode(identity.PublicKey)
        };
    }

    /// <summary>
    /// Creates an <see cref="AgentIdentity"/> from a JWK dictionary.
    /// The JWK must have <c>kty=OKP</c> and <c>crv=Ed25519</c>.
    /// </summary>
    /// <param name="jwk">
    /// A dictionary containing at minimum <c>kty</c>, <c>crv</c>, <c>x</c>,
    /// and optionally <c>kid</c> (used as the DID).
    /// </param>
    /// <returns>A verification-only <see cref="AgentIdentity"/>.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when required keys are missing or values are invalid.
    /// </exception>
    public static AgentIdentity FromJwk(Dictionary<string, string> jwk)
    {
        ArgumentNullException.ThrowIfNull(jwk);

        if (!jwk.TryGetValue("kty", out var kty) || kty != "OKP")
        {
            throw new ArgumentException("JWK must have kty=OKP.", nameof(jwk));
        }

        if (!jwk.TryGetValue("crv", out var crv) || crv != "Ed25519")
        {
            throw new ArgumentException("JWK must have crv=Ed25519.", nameof(jwk));
        }

        if (!jwk.TryGetValue("x", out var x) || string.IsNullOrWhiteSpace(x))
        {
            throw new ArgumentException("JWK must have a non-empty 'x' value.", nameof(jwk));
        }

        var publicKey = Base64UrlDecode(x);
        var did = jwk.TryGetValue("kid", out var kid) && !string.IsNullOrWhiteSpace(kid)
            ? kid
            : $"did:mesh:{Convert.ToHexString(publicKey[..4]).ToLowerInvariant()}";

        return new AgentIdentity(did, publicKey);
    }

    /// <summary>
    /// Produces a W3C DID Document as a dictionary for the given <see cref="AgentIdentity"/>.
    /// Follows the DID Core specification.
    /// </summary>
    /// <param name="identity">The agent identity to represent.</param>
    /// <returns>A dictionary representing a DID Document with verification method.</returns>
    public static Dictionary<string, object> ToDIDDocument(this AgentIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);

        var verificationMethodId = $"{identity.Did}#key-1";

        var verificationMethod = new Dictionary<string, object>
        {
            ["id"] = verificationMethodId,
            ["type"] = "JsonWebKey2020",
            ["controller"] = identity.Did,
            ["publicKeyJwk"] = identity.ToJwk()
        };

        return new Dictionary<string, object>
        {
            ["@context"] = "https://www.w3.org/ns/did/v1",
            ["id"] = identity.Did,
            ["verificationMethod"] = new List<object> { verificationMethod },
            ["authentication"] = new List<object> { verificationMethodId }
        };
    }

    /// <summary>
    /// Encodes bytes to a base64url string (no padding), per RFC 4648 §5.
    /// </summary>
    internal static string Base64UrlEncode(byte[] data)
    {
        return Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    /// <summary>
    /// Decodes a base64url string to bytes, per RFC 4648 §5.
    /// </summary>
    internal static byte[] Base64UrlDecode(string base64Url)
    {
        var padded = base64Url
            .Replace('-', '+')
            .Replace('_', '/');

        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }

        return Convert.FromBase64String(padded);
    }
}
