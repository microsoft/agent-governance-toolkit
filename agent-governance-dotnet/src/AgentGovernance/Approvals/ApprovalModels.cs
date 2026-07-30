// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Policy;

namespace AgentGovernance.Approvals;

/// <summary>Constants shared by the action-bound approval protocol.</summary>
public static class ApprovalProtocol
{
    /// <summary>The protocol and action-binding schema version.</summary>
    public const string SchemaVersion = "1.0";
}

/// <summary>The lifecycle state of an approval request.</summary>
public enum ApprovalStatus
{
    /// <summary>The request is waiting for approval entries.</summary>
    Pending,

    /// <summary>The required approval stages have allowed the request.</summary>
    Allowed,

    /// <summary>An approval stage denied the request.</summary>
    Denied,

    /// <summary>The request expired before execution.</summary>
    Expired,

    /// <summary>The request was explicitly cancelled.</summary>
    Cancelled,

    /// <summary>The one-time approval was consumed at execution.</summary>
    Consumed
}

/// <summary>Classifies the principal recorded on an approval entry.</summary>
public enum ApproverKind
{
    /// <summary>An authenticated human approver.</summary>
    Human,

    /// <summary>An authenticated service approver.</summary>
    Service,

    /// <summary>An advisory LLM output that cannot authorize or deny execution.</summary>
    LlmAdvisory
}

/// <summary>An individual approval entry decision.</summary>
public enum ApprovalEntryDecision
{
    /// <summary>The approver allows the stage.</summary>
    Allow,

    /// <summary>The approver denies the request.</summary>
    Deny
}

/// <summary>The terminal outcome of an approval request.</summary>
public enum ApprovalOutcome
{
    /// <summary>All required stages allowed the request.</summary>
    Allow,

    /// <summary>An authenticated stage denied the request.</summary>
    Deny,

    /// <summary>The request expired.</summary>
    Expired,

    /// <summary>The request was cancelled.</summary>
    Cancelled
}

/// <summary>Identifies the tool or resource targeted by an action.</summary>
public sealed record ActionTarget
{
    /// <summary>The tool name.</summary>
    public required string ToolName { get; init; }

    /// <summary>The version of the tool input schema.</summary>
    public required string ToolSchemaVersion { get; init; }

    /// <summary>The optional resource targeted by the action.</summary>
    public string? Resource { get; init; }

    internal IReadOnlyDictionary<string, object?> ToCanonical() =>
        new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["tool_name"] = ToolName,
            ["tool_schema_version"] = ToolSchemaVersion,
            ["resource"] = Resource
        };
}

/// <summary>
/// Captures the exact executable request authorized by an approval.
/// Changing the agent, subject, operation, target, or parameters changes the digest.
/// </summary>
public sealed record ActionBinding
{
    private const int MaxStringLength = 4096;

    /// <summary>The action-binding schema version.</summary>
    public string SchemaVersion { get; init; } = ApprovalProtocol.SchemaVersion;

    /// <summary>The operation kind, such as <c>tool.invoke</c>.</summary>
    public required string Operation { get; init; }

    /// <summary>The acting agent identifier.</summary>
    public required string AgentId { get; init; }

    /// <summary>The represented subject, when applicable.</summary>
    public string? SubjectId { get; init; }

    /// <summary>The target tool and resource.</summary>
    public required ActionTarget Target { get; init; }

    /// <summary>The exact parameters that will be executed.</summary>
    public IReadOnlyDictionary<string, object?> Parameters { get; init; } =
        new Dictionary<string, object?>(StringComparer.Ordinal);

    /// <summary>Validates required fields and canonical parameter support.</summary>
    /// <exception cref="ApprovalProtocolException">The binding is malformed or cannot be canonicalized.</exception>
    public void Validate()
    {
        if (!string.Equals(SchemaVersion, ApprovalProtocol.SchemaVersion, StringComparison.Ordinal))
        {
            throw new ApprovalProtocolException($"Unsupported action-binding schema version '{SchemaVersion}'.");
        }

        ValidateString(nameof(Operation), Operation, required: true);
        ValidateString(nameof(AgentId), AgentId, required: true);
        ValidateString(nameof(SubjectId), SubjectId, required: false);
        ArgumentNullException.ThrowIfNull(Target);
        ValidateString(nameof(Target.ToolName), Target.ToolName, required: true);
        ValidateString(nameof(Target.ToolSchemaVersion), Target.ToolSchemaVersion, required: true);
        ValidateString(nameof(Target.Resource), Target.Resource, required: false);

        try
        {
            _ = ApprovalDigest.Canonicalize(Parameters);
        }
        catch (Exception exception) when (exception is not ApprovalProtocolException)
        {
            throw new ApprovalProtocolException("Action parameters cannot be canonicalized.", exception);
        }
    }

    /// <summary>Returns the SHA-256-prefixed canonical digest for this binding.</summary>
    public string Digest()
    {
        Validate();
        return ApprovalDigest.Sha256(ToCanonical());
    }

    internal IReadOnlyDictionary<string, object?> ToCanonical() =>
        new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schema_version"] = SchemaVersion,
            ["operation"] = Operation,
            ["agent_id"] = AgentId,
            ["subject_id"] = SubjectId,
            ["target"] = Target.ToCanonical(),
            ["parameters"] = Parameters
        };

    private static void ValidateString(string field, string? value, bool required)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            if (required)
            {
                throw new ApprovalProtocolException($"{field} is required.");
            }

            return;
        }

        if (value.Contains('\0', StringComparison.Ordinal))
        {
            throw new ApprovalProtocolException($"{field} must not contain NUL characters.");
        }

        if (value.Length > MaxStringLength)
        {
            throw new ApprovalProtocolException($"{field} exceeds {MaxStringLength} characters.");
        }
    }
}

/// <summary>The policy decision that suspended execution pending approval.</summary>
public sealed record ApprovalPolicyDecisionRecord
{
    /// <summary>The unique policy decision identifier.</summary>
    public string PolicyDecisionId { get; init; } = ApprovalIds.New("pd");

    /// <summary>The explicit policy action.</summary>
    public PolicyAction Verdict { get; init; } = PolicyAction.RequireApproval;

    /// <summary>The digest of the exact action under review.</summary>
    public required string ActionDigest { get; init; }

    /// <summary>The matched policy rule identifier.</summary>
    public required string PolicyRuleId { get; init; }

    /// <summary>The active policy version.</summary>
    public required string PolicyVersion { get; init; }

    /// <summary>The configured approval chain identifier.</summary>
    public required string ApprovalChainId { get; init; }

    /// <summary>The immutable approval chain version.</summary>
    public required string ApprovalChainVersion { get; init; }

    /// <summary>The UTC decision time.</summary>
    public DateTimeOffset DecidedAt { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>A pending approval request bound to one action digest.</summary>
public sealed record ApprovalRequest
{
    /// <summary>The unique approval request identifier.</summary>
    public string ApprovalRequestId { get; init; } = ApprovalIds.New("ar");

    /// <summary>The policy decision that created this request.</summary>
    public required string PolicyDecisionId { get; init; }

    /// <summary>The digest of the exact action under review.</summary>
    public required string ActionDigest { get; init; }

    /// <summary>The acting agent identifier.</summary>
    public required string AgentId { get; init; }

    /// <summary>The represented subject, when applicable.</summary>
    public string? SubjectId { get; init; }

    /// <summary>The operation kind.</summary>
    public required string Operation { get; init; }

    /// <summary>The target resource, when applicable.</summary>
    public string? TargetResource { get; init; }

    /// <summary>The policy version bound to the request.</summary>
    public required string PolicyVersion { get; init; }

    /// <summary>The approval chain identifier.</summary>
    public required string ApprovalChainId { get; init; }

    /// <summary>The approval chain version bound to the request.</summary>
    public required string ApprovalChainVersion { get; init; }

    /// <summary>The UTC request creation time.</summary>
    public DateTimeOffset RequestedAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>The UTC expiry time.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>The current request lifecycle status.</summary>
    public ApprovalStatus Status { get; init; } = ApprovalStatus.Pending;

    /// <summary>Whether timeout must fail closed. This protocol always sets it to <c>true</c>.</summary>
    public bool FailClosedOnTimeout { get; init; } = true;

    /// <summary>Returns the request fields presented to an approver.</summary>
    public IReadOnlyDictionary<string, object?> PresentedCanonical() =>
        new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["approval_request_id"] = ApprovalRequestId,
            ["policy_decision_id"] = PolicyDecisionId,
            ["action_digest"] = ActionDigest,
            ["agent_id"] = AgentId,
            ["subject_id"] = SubjectId,
            ["operation"] = Operation,
            ["target_resource"] = TargetResource,
            ["policy_version"] = PolicyVersion,
            ["approval_chain_id"] = ApprovalChainId,
            ["approval_chain_version"] = ApprovalChainVersion,
            ["expires_at"] = ExpiresAt.UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture)
        };

    /// <summary>Returns the digest of the exact request presentation.</summary>
    public string InputDigest() => ApprovalDigest.Sha256(PresentedCanonical());
}

/// <summary>A transport-normalized approver decision.</summary>
public sealed record ApprovalVote
{
    /// <summary>The approver kind.</summary>
    public ApproverKind ApproverKind { get; init; } = ApproverKind.Service;

    /// <summary>The verified approver identity.</summary>
    public required string ApproverIdentity { get; init; }

    /// <summary>The assurance mechanism used to verify the identity.</summary>
    public required string IdentityAssurance { get; init; }

    /// <summary>The allow or deny decision.</summary>
    public required ApprovalEntryDecision Decision { get; init; }

    /// <summary>A machine-readable reason code.</summary>
    public string ReasonCode { get; init; } = string.Empty;

    /// <summary>The verified roles carried by the approver identity.</summary>
    public IReadOnlyList<string> Roles { get; init; } = Array.Empty<string>();

    /// <summary>An optional caller-supplied idempotency identifier.</summary>
    public string? ChainEntryId { get; init; }
}

/// <summary>One append-only, digest-linked approval decision.</summary>
public sealed record ApprovalChainEntry
{
    /// <summary>The owning approval request identifier.</summary>
    public required string ApprovalRequestId { get; init; }

    /// <summary>The idempotent chain entry identifier.</summary>
    public string ChainEntryId { get; init; } = ApprovalIds.New("ace");

    /// <summary>The approval stage index.</summary>
    public required int StageIndex { get; init; }

    /// <summary>The approver kind.</summary>
    public required ApproverKind ApproverKind { get; init; }

    /// <summary>The verified approver identity.</summary>
    public required string ApproverIdentity { get; init; }

    /// <summary>The identity assurance mechanism.</summary>
    public required string IdentityAssurance { get; init; }

    /// <summary>The allow or deny entry decision.</summary>
    public required ApprovalEntryDecision Decision { get; init; }

    /// <summary>The reason code supplied with the decision.</summary>
    public string ReasonCode { get; init; } = string.Empty;

    /// <summary>The verified roles used for stage authorization.</summary>
    public IReadOnlyList<string> Roles { get; init; } = Array.Empty<string>();

    /// <summary>The digest of the request presentation reviewed by the approver.</summary>
    public required string InputDigest { get; init; }

    /// <summary>The previous approval entry digest, or <c>null</c> for the first entry.</summary>
    public string? PreviousEntryDigest { get; init; }

    /// <summary>The digest of this complete entry excluding this property.</summary>
    public string? EntryDigest { get; init; }

    /// <summary>The UTC decision time.</summary>
    public DateTimeOffset DecidedAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>Returns a copy with its tamper-evident digest populated.</summary>
    public ApprovalChainEntry Seal() => this with { EntryDigest = ComputeDigest() };

    /// <summary>Returns whether the stored entry digest matches the entry contents.</summary>
    public bool VerifyDigest() =>
        EntryDigest is not null &&
        string.Equals(EntryDigest, ComputeDigest(), StringComparison.Ordinal);

    internal string ComputeDigest() => ApprovalDigest.Sha256(CanonicalWithoutDigest());

    internal IReadOnlyDictionary<string, object?> CanonicalWithoutDigest() =>
        new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["approval_request_id"] = ApprovalRequestId,
            ["chain_entry_id"] = ChainEntryId,
            ["stage_index"] = StageIndex,
            ["approver_kind"] = ApprovalNames.Value(ApproverKind),
            ["approver_identity"] = ApproverIdentity,
            ["identity_assurance"] = IdentityAssurance,
            ["decision"] = ApprovalNames.Value(Decision),
            ["reason_code"] = ReasonCode,
            ["roles"] = Roles,
            ["input_digest"] = InputDigest,
            ["previous_entry_digest"] = PreviousEntryDigest,
            ["decided_at"] = DecidedAt.UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture)
        };
}

/// <summary>The terminal resolution of an approval request.</summary>
public sealed record ApprovalResolution
{
    /// <summary>The unique resolution identifier.</summary>
    public string ApprovalResolutionId { get; init; } = ApprovalIds.New("apr");

    /// <summary>The resolved approval request identifier.</summary>
    public required string ApprovalRequestId { get; init; }

    /// <summary>The terminal outcome.</summary>
    public required ApprovalOutcome Outcome { get; init; }

    /// <summary>The approved action digest.</summary>
    public required string ActionDigest { get; init; }

    /// <summary>The approved policy version.</summary>
    public required string PolicyVersion { get; init; }

    /// <summary>The approved chain version.</summary>
    public required string ApprovalChainVersion { get; init; }

    /// <summary>The digest of the final approval chain entry.</summary>
    public string? FinalEntryDigest { get; init; }

    /// <summary>The UTC resolution time.</summary>
    public DateTimeOffset ResolvedAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>The machine-readable resolution reason.</summary>
    public string ReasonCode { get; init; } = string.Empty;
}

/// <summary>The result of execution-time approval validation.</summary>
public sealed record ApprovalExecutionDecision
{
    /// <summary>The approval request identifier.</summary>
    public required string ApprovalRequestId { get; init; }

    /// <summary>Whether execution may proceed.</summary>
    public required bool Allowed { get; init; }

    /// <summary>The machine-readable validation reason.</summary>
    public required string ReasonCode { get; init; }

    /// <summary>Whether validation atomically consumed the approval.</summary>
    public bool Consumed { get; init; }
}

/// <summary>One ordered stage of a versioned approval chain.</summary>
public sealed record ApprovalStage
{
    /// <summary>The unique stage index within the chain.</summary>
    public required int StageIndex { get; init; }

    /// <summary>The expected approver kind.</summary>
    public ApproverKind ApproverKind { get; init; } = ApproverKind.Human;

    /// <summary>The identities permitted to satisfy this stage.</summary>
    public IReadOnlyCollection<string> AllowedIdentities { get; init; } = Array.Empty<string>();

    /// <summary>The verified roles permitted to satisfy this stage.</summary>
    public IReadOnlyCollection<string> AllowedRoles { get; init; } = Array.Empty<string>();

    /// <summary>Whether this stage is required for a terminal allow.</summary>
    public bool Required { get; init; } = true;

    /// <summary>The transport used by automatic chain execution.</summary>
    public IApprovalTransport? Transport { get; init; }

    internal bool IsAdvisory => ApproverKind == ApproverKind.LlmAdvisory;

    internal bool Authorizes(string identity, IEnumerable<string> roles) =>
        AllowedIdentities.Contains(identity, StringComparer.Ordinal) ||
        roles.Any(role => AllowedRoles.Contains(role, StringComparer.Ordinal));
}

/// <summary>A versioned, immutable approval-chain configuration.</summary>
public sealed record ApprovalChain
{
    /// <summary>The chain identifier.</summary>
    public required string ChainId { get; init; }

    /// <summary>The immutable chain version.</summary>
    public required string Version { get; init; }

    /// <summary>The configured approval stages.</summary>
    public required IReadOnlyList<ApprovalStage> Stages { get; init; }

    internal ApprovalStage? FindStage(int stageIndex) =>
        Stages.FirstOrDefault(stage => stage.StageIndex == stageIndex);
}

/// <summary>The complete persisted approval state for one request.</summary>
public sealed record ApprovalResult
{
    /// <summary>The policy decision that suspended execution.</summary>
    public required ApprovalPolicyDecisionRecord PolicyDecision { get; init; }

    /// <summary>The approval request.</summary>
    public required ApprovalRequest Request { get; init; }

    /// <summary>The append-only approval entries.</summary>
    public IReadOnlyList<ApprovalChainEntry> Entries { get; init; } = Array.Empty<ApprovalChainEntry>();

    /// <summary>The terminal resolution, when resolved.</summary>
    public ApprovalResolution? Resolution { get; init; }

    /// <summary>The execution-time validation result, when attempted.</summary>
    public ApprovalExecutionDecision? Execution { get; init; }
}

internal static class ApprovalIds
{
    internal static string New(string prefix) => $"{prefix}_{Guid.NewGuid():N}";
}

internal static class ApprovalNames
{
    internal static string Value(ApprovalStatus value) => value switch
    {
        ApprovalStatus.Pending => "pending",
        ApprovalStatus.Allowed => "allowed",
        ApprovalStatus.Denied => "denied",
        ApprovalStatus.Expired => "expired",
        ApprovalStatus.Cancelled => "cancelled",
        ApprovalStatus.Consumed => "consumed",
        _ => throw new ArgumentOutOfRangeException(nameof(value))
    };

    internal static string Value(ApproverKind value) => value switch
    {
        ApproverKind.Human => "human",
        ApproverKind.Service => "service",
        ApproverKind.LlmAdvisory => "llm_advisory",
        _ => throw new ArgumentOutOfRangeException(nameof(value))
    };

    internal static string Value(ApprovalEntryDecision value) => value switch
    {
        ApprovalEntryDecision.Allow => "allow",
        ApprovalEntryDecision.Deny => "deny",
        _ => throw new ArgumentOutOfRangeException(nameof(value))
    };

    internal static string Value(ApprovalOutcome value) => value switch
    {
        ApprovalOutcome.Allow => "allow",
        ApprovalOutcome.Deny => "deny",
        ApprovalOutcome.Expired => "expired",
        ApprovalOutcome.Cancelled => "cancelled",
        _ => throw new ArgumentOutOfRangeException(nameof(value))
    };
}
