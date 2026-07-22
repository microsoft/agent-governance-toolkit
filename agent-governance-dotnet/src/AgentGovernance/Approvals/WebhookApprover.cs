// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace AgentGovernance.Approvals;

/// <summary>
/// Sends versioned, action-bound approval requests to an HTTP endpoint.
/// Approve responses require an independently verified principal and matching request binding.
/// </summary>
public sealed class WebhookApprover : IApprovalTransport, IDisposable
{
    private static readonly HashSet<string> BlockedHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "169.254.169.254",
        "fd00:ec2::254",
        "metadata.google.internal"
    };

    private readonly Uri _endpoint;
    private readonly HttpClient _httpClient;
    private readonly bool _ownsClient;
    private readonly IReadOnlyDictionary<string, string> _headers;
    private readonly WebhookResponseVerifier? _responseVerifier;

    /// <summary>Creates a versioned webhook approval transport.</summary>
    /// <param name="endpoint">The HTTP or HTTPS approval endpoint.</param>
    /// <param name="httpClient">An optional caller-owned HTTP client.</param>
    /// <param name="headers">Optional authentication or routing headers.</param>
    /// <param name="responseVerifier">Verifies the principal behind approve responses.</param>
    public WebhookApprover(
        Uri endpoint,
        HttpClient? httpClient = null,
        IReadOnlyDictionary<string, string>? headers = null,
        WebhookResponseVerifier? responseVerifier = null)
    {
        ValidateEndpoint(endpoint);
        _endpoint = endpoint;
        _httpClient = httpClient ?? new HttpClient();
        _ownsClient = httpClient is null;
        _headers = headers is null
            ? new Dictionary<string, string>(StringComparer.Ordinal)
            : new Dictionary<string, string>(headers, StringComparer.Ordinal);
        _responseVerifier = responseVerifier;
    }

    /// <summary>Builds the versioned request payload required by ADR-0030.</summary>
    public static IReadOnlyDictionary<string, object?> BuildRequestPayload(ApprovalRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var payload = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schema_version"] = ApprovalProtocol.SchemaVersion,
            ["type"] = "approval_request",
            ["input_digest"] = request.InputDigest()
        };

        foreach (var field in request.PresentedCanonical())
        {
            payload[field.Key] = field.Value;
        }

        return payload;
    }

    /// <inheritdoc />
    public async Task<ApprovalVote> RequestApprovalAsync(
        ApprovalRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        using var message = new HttpRequestMessage(HttpMethod.Post, _endpoint)
        {
            Content = JsonContent.Create(BuildRequestPayload(request))
        };
        foreach (var header in _headers)
        {
            if (!message.Headers.TryAddWithoutValidation(header.Key, header.Value))
            {
                message.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }

        using var response = await _httpClient.SendAsync(message, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        await using var responseStream = await response.Content.ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        using var document = await JsonDocument.ParseAsync(
            responseStream,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        return ParseResponse(document.RootElement, request, _responseVerifier);
    }

    /// <summary>Releases an internally created HTTP client.</summary>
    public void Dispose()
    {
        if (_ownsClient)
        {
            _httpClient.Dispose();
        }
    }

    internal static ApprovalVote ParseResponse(
        JsonElement body,
        ApprovalRequest request,
        WebhookResponseVerifier? responseVerifier)
    {
        if (body.ValueKind != JsonValueKind.Object)
        {
            throw new ApprovalTransportProtocolException("malformed_webhook_response");
        }

        if (!Matches(body, "approval_request_id", request.ApprovalRequestId))
        {
            throw new ApprovalTransportProtocolException("approval_request_id_mismatch");
        }

        if (!Matches(body, "action_digest", request.ActionDigest))
        {
            throw new ApprovalTransportProtocolException("action_digest_mismatch");
        }

        var approved = ReadDecision(body);
        var reason = ReadString(body, "reason") ?? (approved ? "approved" : "denied_by_webhook");
        var chainEntryId = ReadString(body, "chain_entry_id");

        if (!approved)
        {
            return new ApprovalVote
            {
                ApproverKind = ReadApproverKind(body),
                ApproverIdentity = ReadString(body, "approver") ?? "webhook",
                IdentityAssurance = ReadString(body, "identity_assurance") ?? "webhook",
                Decision = ApprovalEntryDecision.Deny,
                ReasonCode = reason,
                ChainEntryId = chainEntryId
            };
        }

        WebhookVerifiedIdentity? verifiedIdentity;
        try
        {
            verifiedIdentity = responseVerifier?.Invoke(body, request);
        }
        catch (Exception exception)
        {
            throw new ApprovalTransportProtocolException(
                $"identity_verification_error:{exception.GetType().Name}");
        }

        if (verifiedIdentity is null || string.IsNullOrWhiteSpace(verifiedIdentity.Identity))
        {
            throw new ApprovalTransportProtocolException("unverified_approver_identity");
        }

        return new ApprovalVote
        {
            ApproverKind = ReadApproverKind(body),
            ApproverIdentity = verifiedIdentity.Identity,
            IdentityAssurance = verifiedIdentity.Assurance,
            Decision = ApprovalEntryDecision.Allow,
            ReasonCode = reason,
            Roles = verifiedIdentity.Roles.ToArray(),
            ChainEntryId = chainEntryId
        };
    }

    private static void ValidateEndpoint(Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!endpoint.IsAbsoluteUri ||
            (endpoint.Scheme != Uri.UriSchemeHttp && endpoint.Scheme != Uri.UriSchemeHttps))
        {
            throw new ArgumentException("Approval webhook endpoint must use HTTP or HTTPS.", nameof(endpoint));
        }

        var normalizedHost = endpoint.Host.Trim('[', ']');
        if (BlockedHosts.Contains(normalizedHost))
        {
            throw new ArgumentException("Approval webhook endpoint host is blocked.", nameof(endpoint));
        }

        if (IPAddress.TryParse(normalizedHost, out var address) && IsLinkLocal(address))
        {
            throw new ArgumentException("Approval webhook endpoint host is blocked.", nameof(endpoint));
        }
    }

    private static bool IsLinkLocal(IPAddress address)
    {
        if (address.IsIPv6LinkLocal)
        {
            return true;
        }

        var bytes = address.GetAddressBytes();
        return bytes.Length == 4 && bytes[0] == 169 && bytes[1] == 254;
    }

    private static bool Matches(JsonElement body, string propertyName, string expected) =>
        body.TryGetProperty(propertyName, out var property) &&
        property.ValueKind == JsonValueKind.String &&
        string.Equals(property.GetString(), expected, StringComparison.Ordinal);

    private static bool ReadDecision(JsonElement body)
    {
        if (body.TryGetProperty("approved", out var approved) &&
            approved.ValueKind is JsonValueKind.True or JsonValueKind.False)
        {
            return approved.GetBoolean();
        }

        var decision = ReadString(body, "decision")?.ToLowerInvariant();
        return decision switch
        {
            "allow" or "approve" or "approved" => true,
            "deny" or "denied" or "reject" or "rejected" => false,
            _ => throw new ApprovalTransportProtocolException("missing_or_malformed_decision")
        };
    }

    private static ApproverKind ReadApproverKind(JsonElement body) =>
        ReadString(body, "approver_kind")?.ToLowerInvariant() switch
        {
            "human" => ApproverKind.Human,
            "llm_advisory" => ApproverKind.LlmAdvisory,
            _ => ApproverKind.Service
        };

    private static string? ReadString(JsonElement body, string propertyName) =>
        body.TryGetProperty(propertyName, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;
}
