// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;
using AgentGovernance.Policy;

namespace AgentGovernance.Approvals;

/// <summary>Machine-readable execution-time validation reasons.</summary>
public static class ApprovalReasonCodes
{
    /// <summary>The approval is valid for execution.</summary>
    public const string Approved = "approved";

    /// <summary>The request could not be found.</summary>
    public const string RequestNotFound = "approval_request_not_found";

    /// <summary>The request has not reached a terminal resolution.</summary>
    public const string NotResolved = "approval_not_resolved";

    /// <summary>The request is still pending.</summary>
    public const string Pending = "approval_pending";

    /// <summary>The request was denied.</summary>
    public const string Denied = "approval_denied";

    /// <summary>The request expired.</summary>
    public const string Expired = "approval_expired";

    /// <summary>The request was cancelled.</summary>
    public const string Cancelled = "approval_cancelled";

    /// <summary>The one-time approval was already consumed.</summary>
    public const string Consumed = "approval_consumed";

    /// <summary>The action differs from the approved action.</summary>
    public const string ActionDigestMismatch = "action_digest_mismatch";

    /// <summary>The policy version differs from the approved version.</summary>
    public const string PolicyVersionMismatch = "policy_version_mismatch";

    /// <summary>The approval chain identifier differs from the approved chain.</summary>
    public const string ChainIdMismatch = "approval_chain_id_mismatch";

    /// <summary>The approval chain version differs from the approved version.</summary>
    public const string ChainVersionMismatch = "approval_chain_version_mismatch";

    /// <summary>The entry hash chain or authority checks failed.</summary>
    public const string ChainTampered = "approval_chain_tampered";

    /// <summary>Required approval stages are incomplete.</summary>
    public const string ChainIncomplete = "approval_chain_incomplete";

    /// <summary>No required non-advisory stage exists.</summary>
    public const string NoRequiredStage = "no_required_approval_stage";

    /// <summary>An unexpected validation error occurred.</summary>
    public const string InternalError = "approval_internal_error";
}

/// <summary>Configures an <see cref="ApprovalCoordinator"/>.</summary>
public sealed record ApprovalCoordinatorOptions
{
    /// <summary>The default policy rule identifier.</summary>
    public string PolicyRuleId { get; init; } = "unspecified";

    /// <summary>The active policy version.</summary>
    public string PolicyVersion { get; init; } = "unspecified";

    /// <summary>The lifetime of a newly opened approval request.</summary>
    public TimeSpan RequestTtl { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>The maximum wait for each approval transport.</summary>
    public TimeSpan StageTimeout { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>An optional clock for deterministic tests.</summary>
    public Func<DateTimeOffset> Clock { get; init; } = static () => DateTimeOffset.UtcNow;

    /// <summary>An optional structured audit sink.</summary>
    public IApprovalAuditSink? AuditSink { get; init; }
}

/// <summary>
/// Creates, advances, resolves, and execution-validates action-bound approval requests.
/// Every ambiguous or unexpected path fails closed.
/// </summary>
public sealed class ApprovalCoordinator
{
    private readonly ApprovalChain _chain;
    private readonly IApprovalStore _store;
    private readonly ApprovalCoordinatorOptions _options;
    private readonly ConcurrentDictionary<string, object> _requestLocks = new(StringComparer.Ordinal);

    /// <summary>Creates a coordinator for one versioned approval chain.</summary>
    public ApprovalCoordinator(
        ApprovalChain chain,
        IApprovalStore? store = null,
        ApprovalCoordinatorOptions? options = null)
    {
        _chain = chain ?? throw new ArgumentNullException(nameof(chain));
        _store = store ?? new InMemoryApprovalStore();
        _options = options ?? new ApprovalCoordinatorOptions();
        ValidateConfiguration();
    }

    /// <summary>Opens a durable approval request without collecting votes.</summary>
    public ApprovalResult OpenRequest(ActionBinding binding, string? policyRuleId = null)
    {
        ArgumentNullException.ThrowIfNull(binding);
        binding.Validate();

        var now = _options.Clock().ToUniversalTime();
        var actionDigest = binding.Digest();
        var policyDecision = new ApprovalPolicyDecisionRecord
        {
            ActionDigest = actionDigest,
            PolicyRuleId = string.IsNullOrWhiteSpace(policyRuleId) ? _options.PolicyRuleId : policyRuleId,
            PolicyVersion = _options.PolicyVersion,
            ApprovalChainId = _chain.ChainId,
            ApprovalChainVersion = _chain.Version,
            DecidedAt = now
        };
        var request = new ApprovalRequest
        {
            PolicyDecisionId = policyDecision.PolicyDecisionId,
            ActionDigest = actionDigest,
            AgentId = binding.AgentId,
            SubjectId = binding.SubjectId,
            Operation = binding.Operation,
            TargetResource = binding.Target.Resource,
            PolicyVersion = _options.PolicyVersion,
            ApprovalChainId = _chain.ChainId,
            ApprovalChainVersion = _chain.Version,
            RequestedAt = now,
            ExpiresAt = now.Add(_options.RequestTtl),
            Status = ApprovalStatus.Pending,
            FailClosedOnTimeout = true
        };

        _store.SaveRequest(policyDecision, request);
        Emit(ApprovalAuditEventType.PolicyDecision, policyDecision, request);
        Emit(ApprovalAuditEventType.ApprovalRequested, policyDecision, request);
        return BuildResult(policyDecision, request);
    }

    /// <summary>
    /// Opens a request from an existing <c>require_approval</c> policy decision.
    /// </summary>
    /// <exception cref="ApprovalProtocolException">The decision is not <c>require_approval</c>.</exception>
    public ApprovalResult OpenRequest(PolicyDecision policyDecision, ActionBinding binding)
    {
        ArgumentNullException.ThrowIfNull(policyDecision);
        EnsureRequiresApproval(policyDecision);
        return OpenRequest(binding, policyDecision.MatchedRule);
    }

    /// <summary>Appends an authenticated entry and resolves the request when the chain is complete.</summary>
    public ApprovalResult SubmitEntry(string approvalRequestId, int stageIndex, ApprovalVote vote)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(approvalRequestId);
        ArgumentNullException.ThrowIfNull(vote);

        lock (RequestLock(approvalRequestId))
        {
            var (policyDecision, request) = LoadRequest(approvalRequestId);
            var entries = _store.GetEntries(approvalRequestId);

            if (!string.IsNullOrWhiteSpace(vote.ChainEntryId))
            {
                var existing = entries.FirstOrDefault(entry =>
                    string.Equals(entry.ChainEntryId, vote.ChainEntryId, StringComparison.Ordinal));
                if (existing is not null)
                {
                    return BuildResult(policyDecision, request);
                }
            }

            if (request.Status != ApprovalStatus.Pending)
            {
                throw new ApprovalProtocolException(
                    $"Approval request '{approvalRequestId}' is {ApprovalNames.Value(request.Status)}.");
            }

            if (_options.Clock().ToUniversalTime() >= request.ExpiresAt)
            {
                return ResolveLocked(policyDecision, request, ApprovalOutcome.Expired, ApprovalReasonCodes.Expired);
            }

            var stage = _chain.FindStage(stageIndex) ??
                throw new ApprovalProtocolException($"Unknown approval stage '{stageIndex}'.");
            var isAdvisory = stage.IsAdvisory || vote.ApproverKind == ApproverKind.LlmAdvisory;
            if (!isAdvisory && !stage.Authorizes(vote.ApproverIdentity, vote.Roles))
            {
                throw new ApprovalProtocolException(
                    $"Identity '{vote.ApproverIdentity}' is not permitted for approval stage {stageIndex}.");
            }

            if (!isAdvisory && entries.Any(entry =>
                    entry.StageIndex == stageIndex && entry.ApproverKind != ApproverKind.LlmAdvisory))
            {
                throw new ApprovalProtocolException(
                    $"Approval stage {stageIndex} already has a non-advisory decision.");
            }

            var effectiveKind = isAdvisory ? ApproverKind.LlmAdvisory : vote.ApproverKind;
            var entry = new ApprovalChainEntry
            {
                ApprovalRequestId = approvalRequestId,
                ChainEntryId = string.IsNullOrWhiteSpace(vote.ChainEntryId)
                    ? ApprovalIds.New("ace")
                    : vote.ChainEntryId,
                StageIndex = stageIndex,
                ApproverKind = effectiveKind,
                ApproverIdentity = vote.ApproverIdentity,
                IdentityAssurance = vote.IdentityAssurance,
                Decision = vote.Decision,
                ReasonCode = string.IsNullOrWhiteSpace(vote.ReasonCode)
                    ? ApprovalNames.Value(vote.Decision)
                    : vote.ReasonCode,
                Roles = vote.Roles.OrderBy(role => role, StringComparer.Ordinal).ToArray(),
                InputDigest = request.InputDigest(),
                PreviousEntryDigest = entries.LastOrDefault()?.EntryDigest,
                DecidedAt = _options.Clock().ToUniversalTime()
            }.Seal();

            _store.AppendEntry(entry);
            Emit(
                ApprovalAuditEventType.ApprovalChainEntry,
                policyDecision,
                request,
                chainEntry: entry,
                reasonCode: entry.ReasonCode);

            if (isAdvisory)
            {
                return BuildResult(policyDecision, request);
            }

            if (entry.Decision == ApprovalEntryDecision.Deny)
            {
                return ResolveLocked(policyDecision, request, ApprovalOutcome.Deny, entry.ReasonCode);
            }

            var updatedEntries = _store.GetEntries(approvalRequestId);
            return RequiredStagesSatisfied(updatedEntries)
                ? ResolveLocked(policyDecision, request, ApprovalOutcome.Allow, ApprovalReasonCodes.Approved)
                : BuildResult(policyDecision, request);
        }
    }

    /// <summary>Runs all required stages, then validates and consumes a terminal allow.</summary>
    public Task<ApprovalResult> ResolveAsync(
        ActionBinding binding,
        CancellationToken cancellationToken = default) =>
        ResolveCoreAsync(binding, null, cancellationToken);

    /// <summary>Routes an existing <c>require_approval</c> decision through this chain.</summary>
    public Task<ApprovalResult> ResolveAsync(
        PolicyDecision policyDecision,
        ActionBinding binding,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policyDecision);
        EnsureRequiresApproval(policyDecision);
        return ResolveCoreAsync(binding, policyDecision.MatchedRule, cancellationToken);
    }

    /// <summary>Revalidates and atomically consumes an allowed approval before execution.</summary>
    public ApprovalExecutionDecision ValidateForExecution(
        string approvalRequestId,
        ActionBinding binding) =>
        ValidateForExecutionCore(approvalRequestId, binding, consume: true);

    /// <summary>Revalidates an allowed approval without consuming it.</summary>
    public ApprovalExecutionDecision CheckForExecution(
        string approvalRequestId,
        ActionBinding binding) =>
        ValidateForExecutionCore(approvalRequestId, binding, consume: false);

    /// <summary>Cancels a pending request and records a terminal deny.</summary>
    public ApprovalResult CancelRequest(string approvalRequestId, string reasonCode = ApprovalReasonCodes.Cancelled)
    {
        lock (RequestLock(approvalRequestId))
        {
            var (policyDecision, request) = LoadRequest(approvalRequestId);
            if (request.Status != ApprovalStatus.Pending)
            {
                throw new ApprovalProtocolException(
                    $"Approval request '{approvalRequestId}' is {ApprovalNames.Value(request.Status)}.");
            }

            return ResolveLocked(policyDecision, request, ApprovalOutcome.Cancelled, reasonCode);
        }
    }

    /// <summary>Returns the current persisted state for an approval request.</summary>
    public ApprovalResult GetResult(string approvalRequestId)
    {
        var (policyDecision, request) = LoadRequest(approvalRequestId);
        return BuildResult(policyDecision, request);
    }

    private async Task<ApprovalResult> ResolveCoreAsync(
        ActionBinding binding,
        string? policyRuleId,
        CancellationToken cancellationToken)
    {
        var result = OpenRequest(binding, policyRuleId);
        var requiredNonAdvisorySeen = false;

        foreach (var stage in _chain.Stages.OrderBy(stage => stage.StageIndex))
        {
            if (!stage.Required)
            {
                continue;
            }

            if (!stage.IsAdvisory)
            {
                requiredNonAdvisorySeen = true;
            }

            if (_options.Clock().ToUniversalTime() >= result.Request.ExpiresAt)
            {
                return ResolveSystemDeny(
                    result.Request.ApprovalRequestId,
                    stage.StageIndex,
                    ApprovalOutcome.Expired,
                    ApprovalReasonCodes.Expired);
            }

            if (stage.Transport is null)
            {
                return ResolveSystemDeny(
                    result.Request.ApprovalRequestId,
                    stage.StageIndex,
                    ApprovalOutcome.Deny,
                    "missing_approval_transport");
            }

            ApprovalVote vote;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(_options.StageTimeout);
            try
            {
                vote = await stage.Transport.RequestApprovalAsync(result.Request, timeout.Token)
                    .ConfigureAwait(false);
            }
            catch (ApprovalTransportProtocolException exception)
            {
                return ResolveSystemDeny(
                    result.Request.ApprovalRequestId,
                    stage.StageIndex,
                    ApprovalOutcome.Deny,
                    exception.ReasonCode);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return ResolveSystemDeny(
                    result.Request.ApprovalRequestId,
                    stage.StageIndex,
                    ApprovalOutcome.Deny,
                    "approval_timeout");
            }
            catch (OperationCanceledException)
            {
                return ResolveSystemDeny(
                    result.Request.ApprovalRequestId,
                    stage.StageIndex,
                    ApprovalOutcome.Cancelled,
                    ApprovalReasonCodes.Cancelled);
            }
            catch (Exception)
            {
                return ResolveSystemDeny(
                    result.Request.ApprovalRequestId,
                    stage.StageIndex,
                    ApprovalOutcome.Deny,
                    "approval_transport_error");
            }

            result = SubmitEntry(result.Request.ApprovalRequestId, stage.StageIndex, vote);
            if (result.Resolution is null)
            {
                continue;
            }

            if (result.Resolution.Outcome != ApprovalOutcome.Allow)
            {
                return result;
            }

            var execution = ValidateForExecution(result.Request.ApprovalRequestId, binding);
            return GetResult(result.Request.ApprovalRequestId) with { Execution = execution };
        }

        return !requiredNonAdvisorySeen
            ? ResolveSystemDeny(
                result.Request.ApprovalRequestId,
                0,
                ApprovalOutcome.Deny,
                ApprovalReasonCodes.NoRequiredStage)
            : ResolveSystemDeny(
                result.Request.ApprovalRequestId,
                0,
                ApprovalOutcome.Deny,
                ApprovalReasonCodes.ChainIncomplete);
    }

    private ApprovalExecutionDecision ValidateForExecutionCore(
        string approvalRequestId,
        ActionBinding binding,
        bool consume)
    {
        try
        {
            binding.Validate();
            var currentDigest = binding.Digest();

            lock (RequestLock(approvalRequestId))
            {
                var (policyDecision, request) = LoadRequest(approvalRequestId);
                if (request.Status == ApprovalStatus.Consumed)
                {
                    return DenyExecution(policyDecision, request, ApprovalReasonCodes.Consumed);
                }

                if (request.Status == ApprovalStatus.Cancelled)
                {
                    return DenyExecution(policyDecision, request, ApprovalReasonCodes.Cancelled);
                }

                if (_options.Clock().ToUniversalTime() >= request.ExpiresAt)
                {
                    if (request.Status == ApprovalStatus.Pending)
                    {
                        _ = ResolveLocked(policyDecision, request, ApprovalOutcome.Expired, ApprovalReasonCodes.Expired);
                    }
                    else
                    {
                        _store.TryUpdateStatus(approvalRequestId, ApprovalStatus.Expired, out request);
                        Emit(
                            ApprovalAuditEventType.ApprovalExpired,
                            policyDecision,
                            request,
                            reasonCode: ApprovalReasonCodes.Expired);
                    }

                    return DenyExecution(policyDecision, request, ApprovalReasonCodes.Expired);
                }

                if (!_store.TryGetResolution(approvalRequestId, out var resolution))
                {
                    return DenyExecution(policyDecision, request, ApprovalReasonCodes.NotResolved);
                }

                if (resolution.Outcome != ApprovalOutcome.Allow || request.Status != ApprovalStatus.Allowed)
                {
                    return DenyExecution(
                        policyDecision,
                        request,
                        string.IsNullOrWhiteSpace(resolution.ReasonCode)
                            ? StatusReason(request.Status)
                            : resolution.ReasonCode,
                        resolution);
                }

                if (!string.Equals(currentDigest, request.ActionDigest, StringComparison.Ordinal) ||
                    !string.Equals(resolution.ActionDigest, request.ActionDigest, StringComparison.Ordinal))
                {
                    return DenyExecution(policyDecision, request, ApprovalReasonCodes.ActionDigestMismatch, resolution);
                }

                if (!string.Equals(_options.PolicyVersion, request.PolicyVersion, StringComparison.Ordinal) ||
                    !string.Equals(resolution.PolicyVersion, request.PolicyVersion, StringComparison.Ordinal))
                {
                    return DenyExecution(policyDecision, request, ApprovalReasonCodes.PolicyVersionMismatch, resolution);
                }

                if (!string.Equals(_chain.ChainId, request.ApprovalChainId, StringComparison.Ordinal))
                {
                    return DenyExecution(policyDecision, request, ApprovalReasonCodes.ChainIdMismatch, resolution);
                }

                if (!string.Equals(_chain.Version, request.ApprovalChainVersion, StringComparison.Ordinal) ||
                    !string.Equals(resolution.ApprovalChainVersion, request.ApprovalChainVersion, StringComparison.Ordinal))
                {
                    return DenyExecution(policyDecision, request, ApprovalReasonCodes.ChainVersionMismatch, resolution);
                }

                var entries = _store.GetEntries(approvalRequestId);
                var integrityReason = VerifyEntryChain(request, resolution, entries);
                if (integrityReason is not null)
                {
                    return DenyExecution(policyDecision, request, integrityReason, resolution);
                }

                if (consume && !_store.TryConsume(approvalRequestId, out request))
                {
                    return DenyExecution(policyDecision, request, ApprovalReasonCodes.Consumed, resolution);
                }

                var decision = new ApprovalExecutionDecision
                {
                    ApprovalRequestId = approvalRequestId,
                    Allowed = true,
                    ReasonCode = ApprovalReasonCodes.Approved,
                    Consumed = consume
                };
                if (consume)
                {
                    Emit(
                        ApprovalAuditEventType.ApprovalConsumed,
                        policyDecision,
                        request,
                        resolution,
                        reasonCode: ApprovalReasonCodes.Approved);
                }

                Emit(
                    ApprovalAuditEventType.ExecutionAllowed,
                    policyDecision,
                    request,
                    resolution,
                    reasonCode: ApprovalReasonCodes.Approved);
                return decision;
            }
        }
        catch (Exception)
        {
            return new ApprovalExecutionDecision
            {
                ApprovalRequestId = approvalRequestId,
                Allowed = false,
                ReasonCode = ApprovalReasonCodes.InternalError
            };
        }
    }

    private ApprovalResult ResolveSystemDeny(
        string approvalRequestId,
        int stageIndex,
        ApprovalOutcome outcome,
        string reasonCode)
    {
        lock (RequestLock(approvalRequestId))
        {
            var (policyDecision, request) = LoadRequest(approvalRequestId);
            if (request.Status != ApprovalStatus.Pending)
            {
                return BuildResult(policyDecision, request);
            }

            var entries = _store.GetEntries(approvalRequestId);
            var systemEntry = new ApprovalChainEntry
            {
                ApprovalRequestId = approvalRequestId,
                StageIndex = stageIndex,
                ApproverKind = ApproverKind.Service,
                ApproverIdentity = "system:approval-coordinator",
                IdentityAssurance = "system",
                Decision = ApprovalEntryDecision.Deny,
                ReasonCode = reasonCode,
                InputDigest = request.InputDigest(),
                PreviousEntryDigest = entries.LastOrDefault()?.EntryDigest,
                DecidedAt = _options.Clock().ToUniversalTime()
            }.Seal();
            _store.AppendEntry(systemEntry);
            Emit(
                ApprovalAuditEventType.ApprovalChainEntry,
                policyDecision,
                request,
                chainEntry: systemEntry,
                reasonCode: reasonCode);
            return ResolveLocked(policyDecision, request, outcome, reasonCode);
        }
    }

    private ApprovalResult ResolveLocked(
        ApprovalPolicyDecisionRecord policyDecision,
        ApprovalRequest request,
        ApprovalOutcome outcome,
        string reasonCode)
    {
        if (request.Status != ApprovalStatus.Pending)
        {
            return BuildResult(policyDecision, request);
        }

        var entries = _store.GetEntries(request.ApprovalRequestId);
        var resolution = new ApprovalResolution
        {
            ApprovalRequestId = request.ApprovalRequestId,
            Outcome = outcome,
            ActionDigest = request.ActionDigest,
            PolicyVersion = request.PolicyVersion,
            ApprovalChainVersion = request.ApprovalChainVersion,
            FinalEntryDigest = entries.LastOrDefault()?.EntryDigest,
            ResolvedAt = _options.Clock().ToUniversalTime(),
            ReasonCode = reasonCode
        };
        _store.SaveResolution(resolution);
        _store.TryUpdateStatus(request.ApprovalRequestId, StatusForOutcome(outcome), out request);
        Emit(
            ApprovalAuditEventType.ApprovalResolved,
            policyDecision,
            request,
            resolution,
            reasonCode: reasonCode);

        if (outcome == ApprovalOutcome.Expired)
        {
            Emit(
                ApprovalAuditEventType.ApprovalExpired,
                policyDecision,
                request,
                resolution,
                reasonCode: reasonCode);
        }
        else if (outcome == ApprovalOutcome.Cancelled)
        {
            Emit(
                ApprovalAuditEventType.ApprovalCancelled,
                policyDecision,
                request,
                resolution,
                reasonCode: reasonCode);
        }

        return BuildResult(policyDecision, request);
    }

    private string? VerifyEntryChain(
        ApprovalRequest request,
        ApprovalResolution resolution,
        IReadOnlyList<ApprovalChainEntry> entries)
    {
        if (entries.Count == 0)
        {
            return ApprovalReasonCodes.ChainTampered;
        }

        var inputDigest = request.InputDigest();
        string? previous = null;
        foreach (var entry in entries)
        {
            if (!string.Equals(entry.ApprovalRequestId, request.ApprovalRequestId, StringComparison.Ordinal) ||
                !string.Equals(entry.InputDigest, inputDigest, StringComparison.Ordinal) ||
                !string.Equals(entry.PreviousEntryDigest, previous, StringComparison.Ordinal) ||
                !entry.VerifyDigest())
            {
                return ApprovalReasonCodes.ChainTampered;
            }

            if (entry.ApproverKind != ApproverKind.LlmAdvisory)
            {
                var stage = _chain.FindStage(entry.StageIndex);
                var isSystemDeny = entry.ApproverIdentity == "system:approval-coordinator" &&
                    entry.Decision == ApprovalEntryDecision.Deny;
                if (stage is null || (!isSystemDeny && !stage.Authorizes(entry.ApproverIdentity, entry.Roles)))
                {
                    return ApprovalReasonCodes.ChainTampered;
                }
            }

            previous = entry.EntryDigest;
        }

        if (!string.Equals(resolution.FinalEntryDigest, previous, StringComparison.Ordinal))
        {
            return ApprovalReasonCodes.ChainTampered;
        }

        return RequiredStagesSatisfied(entries) ? null : ApprovalReasonCodes.ChainIncomplete;
    }

    private bool RequiredStagesSatisfied(IReadOnlyList<ApprovalChainEntry> entries)
    {
        var required = _chain.Stages
            .Where(stage => stage.Required && !stage.IsAdvisory)
            .Select(stage => stage.StageIndex)
            .ToHashSet();
        if (required.Count == 0)
        {
            return false;
        }

        foreach (var entry in entries)
        {
            if (entry.ApproverKind != ApproverKind.LlmAdvisory &&
                entry.Decision == ApprovalEntryDecision.Allow)
            {
                required.Remove(entry.StageIndex);
            }
        }

        return required.Count == 0;
    }

    private ApprovalExecutionDecision DenyExecution(
        ApprovalPolicyDecisionRecord policyDecision,
        ApprovalRequest request,
        string reasonCode,
        ApprovalResolution? resolution = null)
    {
        Emit(
            ApprovalAuditEventType.ExecutionDenied,
            policyDecision,
            request,
            resolution,
            reasonCode: reasonCode);
        return new ApprovalExecutionDecision
        {
            ApprovalRequestId = request.ApprovalRequestId,
            Allowed = false,
            ReasonCode = reasonCode
        };
    }

    private ApprovalResult BuildResult(
        ApprovalPolicyDecisionRecord policyDecision,
        ApprovalRequest request)
    {
        _store.TryGetRequest(request.ApprovalRequestId, out policyDecision, out request);
        _store.TryGetResolution(request.ApprovalRequestId, out var resolution);
        return new ApprovalResult
        {
            PolicyDecision = policyDecision,
            Request = request,
            Entries = _store.GetEntries(request.ApprovalRequestId),
            Resolution = resolution
        };
    }

    private (ApprovalPolicyDecisionRecord PolicyDecision, ApprovalRequest Request) LoadRequest(
        string approvalRequestId)
    {
        if (!_store.TryGetRequest(approvalRequestId, out var policyDecision, out var request))
        {
            throw new ApprovalProtocolException($"Unknown approval request '{approvalRequestId}'.");
        }

        return (policyDecision, request);
    }

    private object RequestLock(string approvalRequestId) =>
        _requestLocks.GetOrAdd(approvalRequestId, static _ => new object());

    private void ValidateConfiguration()
    {
        if (string.IsNullOrWhiteSpace(_chain.ChainId) || string.IsNullOrWhiteSpace(_chain.Version))
        {
            throw new ApprovalProtocolException("Approval chain id and version are required.");
        }

        if (_chain.Stages.Count == 0)
        {
            throw new ApprovalProtocolException("Approval chain must contain at least one stage.");
        }

        if (_chain.Stages.Select(stage => stage.StageIndex).Distinct().Count() != _chain.Stages.Count)
        {
            throw new ApprovalProtocolException("Approval stage indexes must be unique.");
        }

        if (_options.RequestTtl <= TimeSpan.Zero || _options.StageTimeout <= TimeSpan.Zero)
        {
            throw new ApprovalProtocolException("Approval TTL and stage timeout must be positive.");
        }

        if (string.IsNullOrWhiteSpace(_options.PolicyVersion))
        {
            throw new ApprovalProtocolException("Policy version is required.");
        }
    }

    private static void EnsureRequiresApproval(PolicyDecision policyDecision)
    {
        var normalized = policyDecision.Action
            .Replace("_", string.Empty, StringComparison.Ordinal)
            .Replace("-", string.Empty, StringComparison.Ordinal)
            .ToLowerInvariant();
        if (normalized != "requireapproval")
        {
            throw new ApprovalProtocolException("Only require_approval decisions enter an approval chain.");
        }
    }

    private static ApprovalStatus StatusForOutcome(ApprovalOutcome outcome) => outcome switch
    {
        ApprovalOutcome.Allow => ApprovalStatus.Allowed,
        ApprovalOutcome.Deny => ApprovalStatus.Denied,
        ApprovalOutcome.Expired => ApprovalStatus.Expired,
        ApprovalOutcome.Cancelled => ApprovalStatus.Cancelled,
        _ => throw new ArgumentOutOfRangeException(nameof(outcome))
    };

    private static string StatusReason(ApprovalStatus status) => status switch
    {
        ApprovalStatus.Pending => ApprovalReasonCodes.Pending,
        ApprovalStatus.Allowed => ApprovalReasonCodes.Approved,
        ApprovalStatus.Denied => ApprovalReasonCodes.Denied,
        ApprovalStatus.Expired => ApprovalReasonCodes.Expired,
        ApprovalStatus.Cancelled => ApprovalReasonCodes.Cancelled,
        ApprovalStatus.Consumed => ApprovalReasonCodes.Consumed,
        _ => ApprovalReasonCodes.InternalError
    };

    private void Emit(
        ApprovalAuditEventType type,
        ApprovalPolicyDecisionRecord policyDecision,
        ApprovalRequest request,
        ApprovalResolution? resolution = null,
        ApprovalChainEntry? chainEntry = null,
        string? reasonCode = null)
    {
        _options.AuditSink?.Write(new ApprovalAuditEvent
        {
            Type = type,
            Timestamp = _options.Clock().ToUniversalTime(),
            AgentId = request.AgentId,
            PolicyDecisionId = policyDecision.PolicyDecisionId,
            ApprovalRequestId = request.ApprovalRequestId,
            ApprovalResolutionId = resolution?.ApprovalResolutionId,
            ChainEntryId = chainEntry?.ChainEntryId,
            ActionDigest = request.ActionDigest,
            PolicyVersion = request.PolicyVersion,
            ApprovalChainVersion = request.ApprovalChainVersion,
            ReasonCode = reasonCode
        });
    }
}
