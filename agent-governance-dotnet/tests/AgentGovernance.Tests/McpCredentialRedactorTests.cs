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

    [Fact]
    public void Redact_ModernProviderTokenPatterns()
    {
        var openAiToken = $"sk-FAKEFORTESTING{new string('x', 20)}";
        var slackToken = "xoxb-FAKE-FOR-TESTING-0000000000";
        var awsAccessKey = $"AKIA{new string('A', 16)}";
        var googleApiKey = $"AIza{new string('A', 35)}";

        var result = _redactor.Redact(
            $"openai {openAiToken} slack {slackToken} aws {awsAccessKey} google {googleApiKey}");

        Assert.Equal(
            "openai [REDACTED_OPENAI_TOKEN] slack [REDACTED_SLACK_TOKEN] aws [REDACTED_AWS_ACCESS_KEY] google [REDACTED_GOOGLE_API_KEY]",
            result.Sanitized);
        Assert.Contains(CredentialKind.OpenAiToken, result.Detected);
        Assert.Contains(CredentialKind.SlackToken, result.Detected);
        Assert.Contains(CredentialKind.AwsAccessKey, result.Detected);
        Assert.Contains(CredentialKind.GoogleApiKey, result.Detected);
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
    [InlineData("sk-short")]
    [InlineData("xoxq-FAKE-FOR-TESTING-0000000000")]
    [InlineData("AKIAFAKEFORTEST0000")]
    [InlineData("AIzaFAKE_FOR_TESTING_000000000000000")]
    public void Redact_DoesNotRedactMalformedCredentialLookalikes(string text)
    {
        var result = _redactor.Redact(text);

        Assert.Equal(text, result.Sanitized);
        Assert.Empty(result.Detected);
    }

    // Regression: GitHubToken, OpenAiToken, AwsAccessKey and GoogleApiKey used an
    // excluded-character set (or, for the latter two, plain \b) that treated "_"
    // as an ordinary word character. AwsAccessKey and GoogleApiKey are fixed
    // length, and GitHubToken's gh[psour]_ alternative has no "_" in its own
    // value class, so none of the three had a shorter match to fall back to when
    // the boundary check rejected a suffix like "_old" — the whole pattern
    // failed, and a complete, valid secret passed through unredacted rather than
    // being truncated.
    [Theory]
    [InlineData("ghp_FAKEFORTESTING000000000000000000_old", "[REDACTED_GITHUB_TOKEN]_old", CredentialKind.GitHubToken)]
    [InlineData("ghs_FAKEFORTESTING000000000000000000_deprecated", "[REDACTED_GITHUB_TOKEN]_deprecated", CredentialKind.GitHubToken)]
    [InlineData("sk-FAKEFORTESTING00000000000000000000_old", "[REDACTED_OPENAI_TOKEN]", CredentialKind.OpenAiToken)]
    public void Redact_RedactsSecretGluedToAFollowingUnderscoreSuffix(string text, string expectedSanitized, CredentialKind expectedKind)
    {
        var result = _redactor.Redact(text);

        Assert.Equal(expectedSanitized, result.Sanitized);
        Assert.Contains(expectedKind, result.Detected);
    }

    [Fact]
    public void Redact_RedactsAwsAndGoogleKeysGluedToAFollowingSuffix()
    {
        var awsAccessKey = $"AKIA{new string('A', 16)}";
        var googleApiKey = $"AIza{new string('A', 35)}";

        var result = _redactor.Redact($"{awsAccessKey}_old and {googleApiKey}_rotated");

        Assert.Equal("[REDACTED_AWS_ACCESS_KEY]_old and [REDACTED_GOOGLE_API_KEY]_rotated", result.Sanitized);
        Assert.Contains(CredentialKind.AwsAccessKey, result.Detected);
        Assert.Contains(CredentialKind.GoogleApiKey, result.Detected);
    }

    // Mirror of the suffix regression above, on the left edge: a secret glued
    // directly after "_" was missed because "_" was excluded from the left side
    // of the same boundary check.
    [Theory]
    [InlineData("session_ghp_FAKEFORTESTING000000000000000000", "session_[REDACTED_GITHUB_TOKEN]", CredentialKind.GitHubToken)]
    [InlineData("session_sk-FAKEFORTESTING00000000000000000000", "session_[REDACTED_OPENAI_TOKEN]", CredentialKind.OpenAiToken)]
    public void Redact_RedactsSecretGluedToAPrecedingUnderscore(string text, string expectedSanitized, CredentialKind expectedKind)
    {
        var result = _redactor.Redact(text);

        Assert.Equal(expectedSanitized, result.Sanitized);
        Assert.Contains(expectedKind, result.Detected);
    }

    [Fact]
    public void Redact_RedactsAwsAndGoogleKeysGluedToAPrecedingUnderscore()
    {
        var awsAccessKey = $"AKIA{new string('A', 16)}";
        var googleApiKey = $"AIza{new string('A', 35)}";

        var result = _redactor.Redact($"session_{awsAccessKey} svc_{googleApiKey}");

        Assert.Equal("session_[REDACTED_AWS_ACCESS_KEY] svc_[REDACTED_GOOGLE_API_KEY]", result.Sanitized);
        Assert.Contains(CredentialKind.AwsAccessKey, result.Detected);
        Assert.Contains(CredentialKind.GoogleApiKey, result.Detected);
    }

    // The mirror assertion on AwsAccessKey/GoogleApiKey's right edge is exactly
    // as strict about what may follow as the fixed length already was: one more
    // alphanumeric character is a longer, different token, not the same key
    // with an annotation, and must stay unmatched. Same for one more
    // alphanumeric character directly before the key on the left.
    [Theory]
    [InlineData("AKIAAAAAAAAAAAAAAAAAX")]
    [InlineData("XAKIAAAAAAAAAAAAAAAAA")]
    public void Redact_DoesNotWidenAwsAccessKeyMatch(string text)
    {
        var result = _redactor.Redact(text);

        Assert.Equal(text, result.Sanitized);
        Assert.DoesNotContain(CredentialKind.AwsAccessKey, result.Detected);
    }

    [Theory]
    [InlineData("AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA9")]
    [InlineData("XAIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public void Redact_DoesNotWidenGoogleApiKeyMatch(string text)
    {
        var result = _redactor.Redact(text);

        Assert.Equal(text, result.Sanitized);
        Assert.DoesNotContain(CredentialKind.GoogleApiKey, result.Detected);
    }
}
