// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Mcp;
using Xunit;

namespace AgentGovernance.Tests;

public class McpCredentialRedactorTests
{
    private readonly McpCredentialRedactor _redactor = new();

    [Fact]
    public void Redact_BearerToken()
    {
        var result = _redactor.Redact("Authorization: Bearer abcdefghijklmnop");

        Assert.Contains("[REDACTED_BEARER_TOKEN]", result.Sanitized);
        Assert.Contains(CredentialKind.BearerToken, result.Detected);
        Assert.True(result.Modified);
    }

    [Fact]
    public void Redact_ApiKey()
    {
        var result = _redactor.Redact("api_key=123456789012");

        Assert.Contains("[REDACTED_API_KEY]", result.Sanitized);
        Assert.Contains(CredentialKind.ApiKey, result.Detected);
    }

    [Fact]
    public void Redact_SecretAssignment()
    {
        var result = _redactor.Redact("password=hunter2");

        Assert.Contains("[REDACTED_SECRET]", result.Sanitized);
        Assert.Contains(CredentialKind.SecretAssignment, result.Detected);
    }

    [Fact]
    public void Redact_ConnectionString()
    {
        var result = _redactor.Redact("Endpoint=myserver.database.windows.net;Password=VerySecret123!");

        Assert.Contains("[REDACTED_CONNECTION_STRING]", result.Sanitized);
        Assert.Contains(CredentialKind.ConnectionString, result.Detected);
    }

    [Fact]
    public void Redact_MultipleTypes()
    {
        var result = _redactor.Redact(
            "Authorization: Bearer abcdefghijklmnop api_key=123456789012 secret=hunter2");

        Assert.Contains("[REDACTED_BEARER_TOKEN]", result.Sanitized);
        Assert.Contains("[REDACTED_API_KEY]", result.Sanitized);
        Assert.True(result.Detected.Count >= 2);
    }

    [Fact]
    public void Redact_CleanText_ReturnsUnmodified()
    {
        var result = _redactor.Redact("Hello, this is a normal message.");

        Assert.Equal("Hello, this is a normal message.", result.Sanitized);
        Assert.Empty(result.Detected);
        Assert.False(result.Modified);
    }

    [Fact]
    public void InferKindFromKey_RecognizesCommonKeys()
    {
        Assert.Equal(CredentialKind.BearerToken, McpCredentialRedactor.InferKindFromKey("authorization"));
        Assert.Equal(CredentialKind.ApiKey, McpCredentialRedactor.InferKindFromKey("x-api-key"));
        Assert.Equal(CredentialKind.SecretAssignment, McpCredentialRedactor.InferKindFromKey("password"));
        Assert.Null(McpCredentialRedactor.InferKindFromKey("username"));
    }

    [Theory]
    [InlineData("ghp_FAKEFORTESTING000000000000000000")]
    [InlineData("ghs_FAKEFORTESTING000000000000000000")]
    [InlineData("gho_FAKEFORTESTING000000000000000000")]
    [InlineData("ghu_FAKEFORTESTING000000000000000000")]
    [InlineData("ghr_FAKEFORTESTING000000000000000000")]
    [InlineData("github_pat_FAKE_FOR_TESTING_0000000000000000000000")]
    public void Redact_GitHubTokenPrefixes(string token)
    {
        var result = _redactor.Redact($"value {token} end");

        Assert.Equal("value [REDACTED_GITHUB_TOKEN] end", result.Sanitized);
        Assert.Contains(CredentialKind.GitHubToken, result.Detected);
    }

    [Theory]
    [InlineData("RSA PRIVATE KEY")]
    [InlineData("EC PRIVATE KEY")]
    [InlineData("DSA PRIVATE KEY")]
    [InlineData("OPENSSH PRIVATE KEY")]
    [InlineData("ENCRYPTED PRIVATE KEY")]
    [InlineData("PRIVATE KEY")]
    public void Redact_PemPrivateKeyVariants(string label)
    {
        var pem = $"-----BEGIN {label}-----\nZmFrZSBmb3IgdGVzdGluZw==\n-----END {label}-----";

        var result = _redactor.Redact($"before\n{pem}\nafter");

        Assert.Equal("before\n[REDACTED_PEM_PRIVATE_KEY]\nafter", result.Sanitized);
        Assert.Contains(CredentialKind.PemPrivateKey, result.Detected);
    }

    [Theory]
    [InlineData("-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----")]
    [InlineData("-----BEGIN RSA PRIVATE KEY-----\nZmFrZQ==\n-----END EC PRIVATE KEY-----")]
    [InlineData("github_pat_short")]
    public void Redact_DoesNotRedactMalformedCredentialLookalikes(string text)
    {
        var result = _redactor.Redact(text);

        Assert.Equal(text, result.Sanitized);
        Assert.Empty(result.Detected);
    }
}
