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
        Assert.NotEmpty(jwk["x"]);
    }

    [Fact]
    public void FromJwk_ReconstructsIdentity()
    {
        var original = AgentIdentity.Create("test-agent");
        var jwk = original.ToJwk();
        jwk["kid"] = original.Did;

        var restored = Jwk.FromJwk(jwk);

        Assert.Equal(original.Did, restored.Did);
        Assert.Equal(original.PublicKey, restored.PublicKey);
        Assert.Null(restored.PrivateKey);
    }

    [Fact]
    public void FromJwk_WithoutKid_GeneratesDid()
    {
        var identity = AgentIdentity.Create("test-agent");
        var jwk = identity.ToJwk();

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
        // Verify base64url encoding works correctly through ToJwk/FromJwk roundtrip.
        var identity = AgentIdentity.Create("b64-test");
        var jwk = identity.ToJwk();
        jwk["kid"] = identity.Did;

        var restored = Jwk.FromJwk(jwk);
        Assert.Equal(identity.PublicKey, restored.PublicKey);

        // The 'x' value should not contain standard base64 padding or unsafe chars.
        Assert.DoesNotContain("+", jwk["x"]);
        Assert.DoesNotContain("/", jwk["x"]);
        Assert.DoesNotContain("=", jwk["x"]);
    }

    [Fact]
    public void ToDIDDocument_ReturnsValidStructure()
    {
        var identity = AgentIdentity.Create("test-agent");

        var doc = identity.ToDIDDocument();

        Assert.Equal("https://www.w3.org/ns/did/v1", doc["@context"]);
        Assert.Equal(identity.Did, doc["id"]);
        Assert.NotNull(doc["verificationMethod"]);
        Assert.NotNull(doc["authentication"]);

        var methods = (List<object>)doc["verificationMethod"];
        Assert.Single(methods);

        var method = (Dictionary<string, object>)methods[0];
        Assert.Equal($"{identity.Did}#key-1", method["id"]);
        Assert.Equal("JsonWebKey2020", method["type"]);
        Assert.Equal(identity.Did, method["controller"]);

        var authList = (List<object>)doc["authentication"];
        Assert.Single(authList);
        Assert.Equal($"{identity.Did}#key-1", authList[0]);
    }

    [Fact]
    public void ToDIDDocument_Null_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => Jwk.ToDIDDocument(null!));
    }
}
