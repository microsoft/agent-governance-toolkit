// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
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
        "metadata.google",
        "metadata.google.internal"
    };

    private readonly Uri _endpoint;
    private readonly HttpClient _httpClient;
    private readonly bool _ownsClient;
    private readonly IReadOnlyDictionary<string, string> _headers;
    private readonly WebhookResponseVerifier? _responseVerifier;
    private readonly WebhookAddressResolver _addressResolver;

    /// <summary>Creates a versioned webhook approval transport.</summary>
    /// <param name="endpoint">The HTTP or HTTPS approval endpoint.</param>
    /// <param name="httpClient">An optional caller-owned HTTP client.</param>
    /// <param name="headers">Optional authentication or routing headers.</param>
    /// <param name="responseVerifier">Verifies the principal behind approve responses.</param>
    /// <param name="addressResolver">
    /// Optional DNS resolver for service discovery or testing. Every returned address is still validated.
    /// </param>
    public WebhookApprover(
        Uri endpoint,
        HttpClient? httpClient = null,
        IReadOnlyDictionary<string, string>? headers = null,
        WebhookResponseVerifier? responseVerifier = null,
        WebhookAddressResolver? addressResolver = null)
    {
        ValidateEndpoint(endpoint);
        _endpoint = endpoint;
        _addressResolver = addressResolver ?? Dns.GetHostAddressesAsync;
        _httpClient = httpClient ?? CreateHttpClient(_addressResolver);
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

        if (!_ownsClient)
        {
            _ = await ResolveAllowedAddressesAsync(
                _endpoint.DnsSafeHost,
                _addressResolver,
                cancellationToken).ConfigureAwait(false);
        }

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

        if (verifiedIdentity is null ||
            string.IsNullOrWhiteSpace(verifiedIdentity.Identity) ||
            string.IsNullOrWhiteSpace(verifiedIdentity.Assurance))
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
            Roles = verifiedIdentity.Roles?.ToArray() ?? Array.Empty<string>(),
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

        var normalizedHost = endpoint.IdnHost.Trim('[', ']').TrimEnd('.');
        if (IsBlockedHostName(normalizedHost))
        {
            throw new ArgumentException("Approval webhook endpoint host is blocked.", nameof(endpoint));
        }

        if (IPAddress.TryParse(normalizedHost, out var address) && IsBlockedAddress(address))
        {
            throw new ArgumentException("Approval webhook endpoint host is blocked.", nameof(endpoint));
        }
    }

    private static HttpClient CreateHttpClient(WebhookAddressResolver addressResolver)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            ConnectCallback = async (context, cancellationToken) =>
            {
                var addresses = await ResolveAllowedAddressesAsync(
                    context.DnsEndPoint.Host,
                    addressResolver,
                    cancellationToken).ConfigureAwait(false);
                Exception? lastException = null;
                foreach (var address in addresses)
                {
                    var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    try
                    {
                        await socket.ConnectAsync(
                            new IPEndPoint(address, context.DnsEndPoint.Port),
                            cancellationToken).ConfigureAwait(false);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch (SocketException exception)
                    {
                        socket.Dispose();
                        lastException = exception;
                    }
                    catch
                    {
                        socket.Dispose();
                        throw;
                    }
                }

                throw new HttpRequestException("No resolved webhook address accepted the connection.", lastException);
            }
        };
        return new HttpClient(handler);
    }

    private static async Task<IPAddress[]> ResolveAllowedAddressesAsync(
        string host,
        WebhookAddressResolver addressResolver,
        CancellationToken cancellationToken)
    {
        if (IPAddress.TryParse(host.Trim('[', ']'), out var literalAddress))
        {
            return IsBlockedAddress(literalAddress)
                ? throw new ApprovalTransportProtocolException("blocked_webhook_endpoint")
                : new[] { NormalizeAddress(literalAddress) };
        }

        IPAddress[] addresses;
        try
        {
            addresses = await addressResolver(host, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            throw new ApprovalTransportProtocolException("webhook_endpoint_resolution_failed");
        }

        if (addresses is null || addresses.Length == 0)
        {
            throw new ApprovalTransportProtocolException("webhook_endpoint_resolution_failed");
        }

        if (addresses.Any(IsBlockedAddress))
        {
            throw new ApprovalTransportProtocolException("blocked_webhook_endpoint");
        }

        return addresses.Select(NormalizeAddress).Distinct().ToArray();
    }

    private static bool IsBlockedHostName(string host) =>
        string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) ||
        host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase) ||
        BlockedHosts.Any(blocked =>
            string.Equals(host, blocked, StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith($".{blocked}", StringComparison.OrdinalIgnoreCase));

    private static bool IsBlockedAddress(IPAddress address)
    {
        address = NormalizeAddress(address);
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            return bytes[0] is 0 or 10 or 127 ||
                (bytes[0] == 100 && bytes[1] is >= 64 and <= 127) ||
                (bytes[0] == 169 && bytes[1] == 254) ||
                (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) ||
                (bytes[0] == 192 && bytes[1] is 0 or 2 or 168) ||
                (bytes[0] == 192 && bytes[1] == 88 && bytes[2] == 99) ||
                (bytes[0] == 198 && bytes[1] is 18 or 19) ||
                (bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100) ||
                (bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113) ||
                bytes[0] >= 224;
        }

        var ipv6 = address.GetAddressBytes();
        return IPAddress.IsLoopback(address) ||
            address.Equals(IPAddress.IPv6Any) ||
            address.IsIPv6LinkLocal ||
            address.IsIPv6SiteLocal ||
            address.IsIPv6Multicast ||
            (ipv6[0] & 0xfe) == 0xfc ||
            (ipv6[0] == 0x20 && ipv6[1] == 0x01 && ipv6[2] == 0x0d && ipv6[3] == 0xb8);
    }

    private static IPAddress NormalizeAddress(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            return address.MapToIPv4();
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var bytes = address.GetAddressBytes();
            if (bytes.Take(12).All(value => value == 0) &&
                (bytes[12] != 0 || bytes[13] != 0 || bytes[14] != 0 || bytes[15] > 1))
            {
                return new IPAddress(bytes[^4..]);
            }
        }

        return address;
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
