// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Trust;
using Xunit;

namespace AgentGovernance.Tests;

public class JwkTests
{
    [Fact]
    public void ToJwk_ReturnsCorrectStructure()
    {
        var identity = AgentIdentity.Create("test-agent");

        var jwk = identity.ToJwk();

        Assert.Equal("OKP", jwk["kty"]);
        Assert.Equal("Ed25519", jwk["crv"]);
        Assert.Equal($"{identity.Did}#{identity.VerificationKeyId}", jwk["kid"]);
        Assert.NotEmpty(jwk["x"]);
    }

    [Fact]
    public void ToJwk_AsymmetricIdentity_ReturnsEcStructure()
    {
        var identity = AgentIdentity.CreateAsymmetric("test-agent");

        var jwk = identity.ToJwk();

        Assert.Equal("EC", jwk["kty"]);
        Assert.Equal("P-256", jwk["crv"]);
        Assert.Equal($"{identity.Did}#{identity.VerificationKeyId}", jwk["kid"]);
        Assert.NotEmpty(jwk["x"]);
        Assert.NotEmpty(jwk["y"]);
    }

    [Fact]
    public void ToJwk_WithPrivateKey_EmitsPrivateComponent()
    {
        var identity = AgentIdentity.Create("test-agent");

        var jwk = identity.ToJwk(includePrivate: true);

        Assert.Contains("d", jwk.Keys);
    }

    [Fact]
    public void FromJwk_ReconstructsIdentity()
    {
        var original = AgentIdentity.Create("test-agent");
        var jwk = original.ToJwk();

        var restored = Jwk.FromJwk(jwk);

        Assert.Equal(original.Did, restored.Did);
        Assert.Equal(original.PublicKey, restored.PublicKey);
        Assert.Null(restored.PrivateKey);
        Assert.Equal(original.VerificationKeyId, restored.VerificationKeyId);
    }

    [Fact]
    public void FromJwk_WithPrivateKey_RestoresSigningMaterial()
    {
        var original = AgentIdentity.Create("test-agent");
        var jwk = original.ToJwk(includePrivate: true);

        var restored = Jwk.FromJwk(jwk);

        Assert.NotNull(restored.PrivateKey);
        Assert.True(restored.Verify("payload"u8.ToArray(), restored.Sign("payload")));
    }

    [Fact]
    public void FromJwk_AsymmetricWithPrivateKey_RestoresSigningMaterial()
    {
        var original = AgentIdentity.CreateAsymmetric("test-agent");
        var jwk = original.ToJwk(includePrivate: true);

        var restored = Jwk.FromJwk(jwk);

        Assert.Equal(IdentitySigningAlgorithm.EcdsaP256, restored.SigningAlgorithm);
        Assert.NotNull(restored.PrivateKey);
        Assert.True(restored.Verify("payload"u8.ToArray(), restored.Sign("payload")));
    }

    [Fact]
    public void FromJwk_WithoutKid_GeneratesCanonicalDid()
    {
        var identity = AgentIdentity.Create("test-agent");
        var jwk = identity.ToJwk();
        jwk.Remove("kid");

        var restored = Jwk.FromJwk(jwk);

        Assert.StartsWith("did:mesh:", restored.Did);
    }

    [Fact]
    public void FromJwk_InvalidKty_Throws()
    {
        var jwk = new Dictionary<string, string>
        {
            ["kty"] = "RSA",
            ["crv"] = "Ed25519",
            ["x"] = "AAAA"
        };

        Assert.Throws<ArgumentException>(() => Jwk.FromJwk(jwk));
    }

    [Fact]
    public void FromJwk_InvalidCrv_Throws()
    {
        var jwk = new Dictionary<string, string>
        {
            ["kty"] = "OKP",
            ["crv"] = "P-256",
            ["x"] = "AAAA"
        };

        Assert.Throws<ArgumentException>(() => Jwk.FromJwk(jwk));
    }

    [Fact]
    public void FromJwk_EcMissingY_Throws()
    {
        var jwk = new Dictionary<string, string>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = "AAAA"
        };

        Assert.Throws<ArgumentException>(() => Jwk.FromJwk(jwk));
    }

    [Fact]
    public void FromJwk_MissingX_Throws()
    {
        var jwk = new Dictionary<string, string>
        {
            ["kty"] = "OKP",
            ["crv"] = "Ed25519"
        };

        Assert.Throws<ArgumentException>(() => Jwk.FromJwk(jwk));
    }

    [Fact]
    public void FromJwk_Null_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => Jwk.FromJwk(null!));
    }

    [Fact]
    public void ToJwk_Null_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => Jwk.ToJwk(null!));
    }

    [Fact]
    public void Base64Url_RoundTrip_ViaJwk()
    {
        var identity = AgentIdentity.Create("b64-test");
        var jwk = identity.ToJwk();

        var restored = Jwk.FromJwk(jwk);
        Assert.Equal(identity.PublicKey, restored.PublicKey);

        Assert.DoesNotContain("+", jwk["x"]);
        Assert.DoesNotContain("/", jwk["x"]);
        Assert.DoesNotContain("=", jwk["x"]);
    }

    [Fact]
    public void ToJwks_RoundTripsIdentity()
    {
        var identity = AgentIdentity.Create("jwks-agent");
        var jwks = identity.ToJwks();

        var restored = Jwk.FromJwks(jwks, $"{identity.Did}#{identity.VerificationKeyId}");

        Assert.Equal(identity.Did, restored.Did);
        Assert.Equal(identity.VerificationKeyId, restored.VerificationKeyId);
    }

    [Fact]
    public void ToDIDDocument_ReturnsValidStructure()
    {
        var identity = AgentIdentity.Create("test-agent");

        var doc = identity.ToDIDDocument();

        var context = Assert.IsType<List<object>>(doc["@context"]);
        Assert.Single(context);
        Assert.Equal("https://www.w3.org/ns/did/v1", context[0]);
        Assert.Equal(identity.Did, doc["id"]);

        var methods = Assert.IsType<List<object>>(doc["verificationMethod"]);
        Assert.Single(methods);

        var method = Assert.IsType<Dictionary<string, object>>(methods[0]);
        Assert.Equal($"{identity.Did}#{identity.VerificationKeyId}", method["id"]);
        Assert.Equal("JsonWebKey2020", method["type"]);
        Assert.Equal(identity.Did, method["controller"]);

        var authList = Assert.IsType<List<object>>(doc["authentication"]);
        Assert.Single(authList);
        Assert.Equal($"{identity.Did}#{identity.VerificationKeyId}", authList[0]);

        var serviceList = Assert.IsType<List<object>>(doc["service"]);
        Assert.Single(serviceList);
        var service = Assert.IsType<Dictionary<string, object>>(serviceList[0]);
        Assert.Equal("AgentMeshIdentity", service["type"]);
    }

    [Fact]
    public void ToDIDDocument_Null_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => Jwk.ToDIDDocument(null!));
    }
}
