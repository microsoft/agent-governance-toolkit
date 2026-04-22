// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace AgentGovernance.Trust;

/// <summary>
/// Provides JWK, JWKS, and DID Document serialization helpers for <see cref="AgentIdentity"/>.
/// </summary>
public static class Jwk
{
    /// <summary>
    /// Converts an <see cref="AgentIdentity"/> to an Ed25519-shaped JWK.
    /// </summary>
    public static Dictionary<string, string> ToJwk(this AgentIdentity identity, bool includePrivate = false)
    {
        ArgumentNullException.ThrowIfNull(identity);

        var jwk = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["kty"] = "OKP",
            ["crv"] = "Ed25519",
            ["kid"] = $"{identity.Did}#{identity.VerificationKeyId}",
            ["x"] = Base64UrlEncode(identity.PublicKey),
        };

        if (includePrivate && identity.PrivateKey is not null)
        {
            jwk["d"] = Base64UrlEncode(identity.PrivateKey);
        }

        return jwk;
    }

    /// <summary>
    /// Creates an <see cref="AgentIdentity"/> from a JWK dictionary.
    /// </summary>
    public static AgentIdentity FromJwk(Dictionary<string, string> jwk)
    {
        ArgumentNullException.ThrowIfNull(jwk);

        if (!jwk.TryGetValue("kty", out var kty) || !string.Equals(kty, "OKP", StringComparison.Ordinal))
        {
            throw new ArgumentException("JWK must have kty=OKP.", nameof(jwk));
        }

        if (!jwk.TryGetValue("crv", out var crv) || !string.Equals(crv, "Ed25519", StringComparison.Ordinal))
        {
            throw new ArgumentException("JWK must have crv=Ed25519.", nameof(jwk));
        }

        if (!jwk.TryGetValue("x", out var x) || string.IsNullOrWhiteSpace(x))
        {
            throw new ArgumentException("JWK must have a non-empty 'x' value.", nameof(jwk));
        }

        var publicKey = Base64UrlDecode(x);
        var privateKey = jwk.TryGetValue("d", out var d) && !string.IsNullOrWhiteSpace(d)
            ? Base64UrlDecode(d)
            : null;
        var kid = jwk.TryGetValue("kid", out var kidValue) ? kidValue : null;
        var did = TryGetDidFromKid(kid)
            ?? $"{AgentIdentity.CanonicalDidPrefix}{Convert.ToHexString(publicKey[..16]).ToLowerInvariant()}";
        var verificationKeyId = TryGetVerificationKeyIdFromKid(kid);

        return new AgentIdentity(
            did: did,
            publicKey: publicKey,
            privateKey: privateKey,
            verificationKeyId: verificationKeyId);
    }

    /// <summary>
    /// Exports an identity as a JWK Set.
    /// </summary>
    public static Dictionary<string, object> ToJwks(this AgentIdentity identity, bool includePrivate = false)
    {
        ArgumentNullException.ThrowIfNull(identity);

        return new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["keys"] = new List<Dictionary<string, string>> { identity.ToJwk(includePrivate) }
        };
    }

    /// <summary>
    /// Imports an identity from a JWK Set.
    /// </summary>
    public static AgentIdentity FromJwks(Dictionary<string, object> jwks, string? kid = null)
    {
        ArgumentNullException.ThrowIfNull(jwks);

        if (!jwks.TryGetValue("keys", out var keysObject) || keysObject is null)
        {
            throw new ArgumentException("JWKS must contain a 'keys' collection.", nameof(jwks));
        }

        var keys = ExtractJwkEntries(keysObject);
        if (keys.Count == 0)
        {
            throw new ArgumentException("JWKS must contain at least one JWK entry.", nameof(jwks));
        }

        var selected = string.IsNullOrWhiteSpace(kid)
            ? keys[0]
            : keys.FirstOrDefault(candidate =>
                candidate.TryGetValue("kid", out var candidateKid)
                && string.Equals(candidateKid, kid, StringComparison.Ordinal));

        if (selected is null)
        {
            throw new ArgumentException($"JWKS does not contain key '{kid}'.", nameof(kid));
        }

        return FromJwk(selected);
    }

    /// <summary>
    /// Produces a W3C DID Document for the given <see cref="AgentIdentity"/>.
    /// </summary>
    public static Dictionary<string, object> ToDIDDocument(this AgentIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);

        var verificationMethodId = $"{identity.Did}#{identity.VerificationKeyId}";
        return new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["@context"] = new List<object> { "https://www.w3.org/ns/did/v1" },
            ["id"] = identity.Did,
            ["verificationMethod"] = new List<object>
            {
                new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["id"] = verificationMethodId,
                    ["type"] = "JsonWebKey2020",
                    ["controller"] = identity.Did,
                    ["publicKeyJwk"] = identity.ToJwk(),
                }
            },
            ["authentication"] = new List<object> { verificationMethodId },
            ["service"] = new List<object>
            {
                new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["id"] = $"{identity.Did}#agentmesh",
                    ["type"] = "AgentMeshIdentity",
                    ["serviceEndpoint"] = AgentIdentity.DefaultServiceEndpoint,
                }
            }
        };
    }

    internal static string Base64UrlEncode(byte[] data)
    {
        return Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    internal static byte[] Base64UrlDecode(string base64Url)
    {
        var padded = base64Url
            .Replace('-', '+')
            .Replace('_', '/');

        switch (padded.Length % 4)
        {
            case 2:
                padded += "==";
                break;
            case 3:
                padded += "=";
                break;
        }

        return Convert.FromBase64String(padded);
    }

    private static string? TryGetDidFromKid(string? kid)
    {
        if (string.IsNullOrWhiteSpace(kid))
        {
            return null;
        }

        var hashIndex = kid.IndexOf('#');
        return hashIndex >= 0 ? AgentIdentity.NormalizeDid(kid[..hashIndex]) : AgentIdentity.NormalizeDid(kid);
    }

    private static string? TryGetVerificationKeyIdFromKid(string? kid)
    {
        if (string.IsNullOrWhiteSpace(kid))
        {
            return null;
        }

        var hashIndex = kid.IndexOf('#');
        return hashIndex >= 0 && hashIndex < kid.Length - 1 ? kid[(hashIndex + 1)..] : null;
    }

    private static List<Dictionary<string, string>> ExtractJwkEntries(object keysObject)
    {
        return keysObject switch
        {
            IEnumerable<Dictionary<string, string>> typed => typed.Select(CloneDictionary).ToList(),
            IEnumerable<object> objects => objects.Select(ConvertObjectJwk).ToList(),
            _ => throw new ArgumentException("JWKS 'keys' must be a collection of JWK dictionaries.")
        };
    }

    private static Dictionary<string, string> ConvertObjectJwk(object entry)
    {
        return entry switch
        {
            Dictionary<string, string> typed => CloneDictionary(typed),
            IReadOnlyDictionary<string, string> readOnly => readOnly.ToDictionary(kvp => kvp.Key, kvp => kvp.Value, StringComparer.Ordinal),
            IReadOnlyDictionary<string, object> objectDictionary => objectDictionary.ToDictionary(
                kvp => kvp.Key,
                kvp => kvp.Value?.ToString() ?? string.Empty,
                StringComparer.Ordinal),
            IDictionary<string, object> mutableObjectDictionary => mutableObjectDictionary.ToDictionary(
                kvp => kvp.Key,
                kvp => kvp.Value?.ToString() ?? string.Empty,
                StringComparer.Ordinal),
            _ => throw new ArgumentException("JWKS entries must be dictionaries.")
        };
    }

    private static Dictionary<string, string> CloneDictionary(IReadOnlyDictionary<string, string> source)
    {
        return source.ToDictionary(kvp => kvp.Key, kvp => kvp.Value, StringComparer.Ordinal);
    }
}
