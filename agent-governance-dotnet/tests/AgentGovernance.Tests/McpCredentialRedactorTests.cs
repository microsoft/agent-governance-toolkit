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
}
