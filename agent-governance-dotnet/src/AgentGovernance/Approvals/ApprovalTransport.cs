// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;

namespace AgentGovernance.Approvals;

/// <summary>Requests an approval vote from an external workflow.</summary>
public interface IApprovalTransport
{
    /// <summary>Requests one approval vote for the supplied action-bound request.</summary>
    Task<ApprovalVote> RequestApprovalAsync(
        ApprovalRequest request,
        CancellationToken cancellationToken = default);
}

/// <summary>An approval protocol configuration or lifecycle error.</summary>
public class ApprovalProtocolException : Exception
{
    /// <summary>Creates an approval protocol exception.</summary>
    public ApprovalProtocolException(string message)
        : base(message)
    {
    }

    /// <summary>Creates an approval protocol exception with an inner exception.</summary>
    public ApprovalProtocolException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>A fail-closed webhook response validation error.</summary>
public sealed class ApprovalTransportProtocolException : ApprovalProtocolException
{
    /// <summary>Creates a transport protocol exception with a machine-readable reason.</summary>
    public ApprovalTransportProtocolException(string reasonCode)
        : base($"Approval transport protocol failure: {reasonCode}.")
    {
        ReasonCode = reasonCode;
    }

    /// <summary>The machine-readable reason code.</summary>
    public string ReasonCode { get; }
}

/// <summary>A principal and roles verified independently of a webhook response body assertion.</summary>
public sealed record WebhookVerifiedIdentity
{
    /// <summary>The verified principal identifier.</summary>
    public required string Identity { get; init; }

    /// <summary>The verification assurance mechanism.</summary>
    public required string Assurance { get; init; }

    /// <summary>The roles bound to the verified principal.</summary>
    public IReadOnlyList<string> Roles { get; init; } = Array.Empty<string>();
}

/// <summary>Verifies the authenticated principal behind a webhook approval response.</summary>
/// <param name="body">The parsed response body.</param>
/// <param name="request">The approval request being answered.</param>
/// <returns>A verified identity, or <c>null</c> when identity cannot be established.</returns>
public delegate WebhookVerifiedIdentity? WebhookResponseVerifier(
    JsonElement body,
    ApprovalRequest request);
