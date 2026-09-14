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

    // ---------------------------------------------------------------
    // Boundary regression tests for issue #3933
    // A valid credential glued to a preceding or following word
    // character via _ or - must still be detected and redacted.
    // ---------------------------------------------------------------

    [Theory]
    [InlineData("ghp_FAKEFORTESTING000000000000000000_old")]
    [InlineData("ghp_FAKEFORTESTING000000000000000000_deprecated")]
    [InlineData("ghp_FAKEFORTESTING000000000000000000_rotated")]
    public void Redact_GitHubToken_RightEdgeUnderscore(string input)
    {
        var result = _redactor.Redact(input);

        Assert.Contains("[REDACTED_GITHUB_TOKEN]", result.Sanitized);
        Assert.Contains(CredentialKind.GitHubToken, result.Detected);
        Assert.True(result.Modified);
    }

    [Theory]
    [InlineData("session_ghp_FAKEFORTESTING000000000000000000")]
    [InlineData("env_ghp_FAKEFORTESTING000000000000000000")]
    [InlineData("old_github_pat_FAKE_FOR_TESTING_0000000000000000000000")]
    public void Redact_GitHubToken_LeftEdgeUnderscore(string input)
    {
        var result = _redactor.Redact(input);

        Assert.Contains("[REDACTED_GITHUB_TOKEN]", result.Sanitized);
        Assert.Contains(CredentialKind.GitHubToken, result.Detected);
        Assert.True(result.Modified);
    }

    [Theory]
    [InlineData("session_sk-FAKEFORTESTING000000000000000000")]
    [InlineData("env_sk-FAKEFORTESTING000000000000000000")]
    public void Redact_OpenAiToken_LeftEdgeUnderscore(string input)
    {
        var result = _redactor.Redact(input);

        Assert.Contains("[REDACTED_OPENAI_TOKEN]", result.Sanitized);
        Assert.Contains(CredentialKind.OpenAiToken, result.Detected);
        Assert.True(result.Modified);
    }

    [Fact]
    public void Redact_OpenAiToken_RightEdgeUnderscore()
    {
        var token = $"sk-FAKEFORTESTING{new string('x', 20)}";
        var result = _redactor.Redact($"{token}_old");

        Assert.Contains("[REDACTED_OPENAI_TOKEN]", result.Sanitized);
        Assert.Contains(CredentialKind.OpenAiToken, result.Detected);
    }

    [Theory]
    [InlineData("AKIAAAAAAAAAAAAAAAAA_old")]
    [InlineData("AKIAAAAAAAAAAAAAAAAA_deprecated")]
    [InlineData("AKIAAAAAAAAAAAAAAAAA_rotated")]
    public void Redact_AwsAccessKey_RightEdgeUnderscore(string input)
    {
        var result = _redactor.Redact(input);

        Assert.Contains("[REDACTED_AWS_ACCESS_KEY]", result.Sanitized);
        Assert.Contains(CredentialKind.AwsAccessKey, result.Detected);
        Assert.True(result.Modified);
    }

    [Theory]
    [InlineData("session_AKIAAAAAAAAAAAAAAAAA")]
    [InlineData("env_AKIAAAAAAAAAAAAAAAAA")]
    [InlineData("key_AKIAAAAAAAAAAAAAAAAA")]
    public void Redact_AwsAccessKey_LeftEdgeUnderscore(string input)
    {
        var result = _redactor.Redact(input);

        Assert.Contains("[REDACTED_AWS_ACCESS_KEY]", result.Sanitized);
        Assert.Contains(CredentialKind.AwsAccessKey, result.Detected);
        Assert.True(result.Modified);
    }

    [Fact]
    public void Redact_GoogleApiKey_RightEdgeUnderscore()
    {
        var key = $"AIza{new string('A', 35)}";
        var result = _redactor.Redact($"{key}_old");

        Assert.Contains("[REDACTED_GOOGLE_API_KEY]", result.Sanitized);
        Assert.Contains(CredentialKind.GoogleApiKey, result.Detected);
    }

    [Fact]
    public void Redact_GoogleApiKey_LeftEdgeUnderscore()
    {
        var key = $"AIza{new string('A', 35)}";
        var result = _redactor.Redact($"svc_{key}");

        Assert.Contains("[REDACTED_GOOGLE_API_KEY]", result.Sanitized);
        Assert.Contains(CredentialKind.GoogleApiKey, result.Detected);
    }

    [Fact]
    public void Redact_BothEdgesGluedToUnderscore()
    {
        // A credential sandwiched between underscored identifiers
        // must be detected regardless of which edge is tested.
        var result = _redactor.Redact("old_AKIAAAAAAAAAAAAAAAAA_new");

        Assert.Contains("[REDACTED_AWS_ACCESS_KEY]", result.Sanitized);
        Assert.Contains(CredentialKind.AwsAccessKey, result.Detected);
    }

    [Theory]
    [InlineData("fooghp_FAKEFORTESTING000000000000000000")]
    [InlineData("0ghp_FAKEFORTESTING000000000000000000")]
    public void Redact_GitHubToken_StillRejectedWhenGluedToAlphanumeric(string input)
    {
        // The fix lets _ and - through but must still reject a
        // token prefix embedded in a contiguous alphanumeric word.
        var result = _redactor.Redact(input);

        Assert.Equal(input, result.Sanitized);
        Assert.Empty(result.Detected);
    }

    [Theory]
    [InlineData("fooAKIAAAAAAAAAAAAAAAAA")]
    [InlineData("0AKIAAAAAAAAAAAAAAAAA")]
    public void Redact_AwsAccessKey_StillRejectedWhenGluedToAlphanumeric(string input)
    {
        var result = _redactor.Redact(input);

        Assert.Equal(input, result.Sanitized);
        Assert.Empty(result.Detected);
    }

    [Fact]
    public void Redact_MultipleGluedCredentials_AllDetected()
    {
        var aws = "AKIAAAAAAAAAAAAAAAAA";
        var github = "ghp_FAKEFORTESTING000000000000000000";
        var google = $"AIza{new string('A', 35)}";
        var openai = $"sk-FAKEFORTESTING{new string('x', 20)}";

        var result = _redactor.Redact(
            $"env_{aws}_old cfg_{github}_rotated svc_{google}_deprecated session_{openai}_bak");

        Assert.Contains(CredentialKind.AwsAccessKey, result.Detected);
        Assert.Contains(CredentialKind.GitHubToken, result.Detected);
        Assert.Contains(CredentialKind.GoogleApiKey, result.Detected);
        Assert.Contains(CredentialKind.OpenAiToken, result.Detected);
        Assert.DoesNotContain(aws, result.Sanitized);
        Assert.DoesNotContain(github, result.Sanitized);
        Assert.DoesNotContain(google, result.Sanitized);
        Assert.DoesNotContain(openai, result.Sanitized);
    }

    [Fact]
    public void Redact_SlackTokenBoundary_UnchangedByFix()
    {
        // SlackToken was already correct before this fix — verify
        // the lookaround contract remains intact.
        var result = _redactor.Redact("env_xoxb-FAKE-FOR-TESTING-0000000000_old");

        Assert.Contains("[REDACTED_SLACK_TOKEN]", result.Sanitized);
        Assert.Contains(CredentialKind.SlackToken, result.Detected);
    }

    [Fact]
    public void PlaceholderFor_ReturnsExpectedStrings()
    {
        Assert.Equal("[REDACTED_GITHUB_TOKEN]", McpCredentialRedactor.PlaceholderFor(CredentialKind.GitHubToken));
        Assert.Equal("[REDACTED_OPENAI_TOKEN]", McpCredentialRedactor.PlaceholderFor(CredentialKind.OpenAiToken));
        Assert.Equal("[REDACTED_AWS_ACCESS_KEY]", McpCredentialRedactor.PlaceholderFor(CredentialKind.AwsAccessKey));
        Assert.Equal("[REDACTED_GOOGLE_API_KEY]", McpCredentialRedactor.PlaceholderFor(CredentialKind.GoogleApiKey));
    }
}
