// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics;

namespace AgentGovernance.Policy;

/// <summary>
/// Main governance policy evaluation engine. Loads one or more <see cref="Policy"/>
/// documents, evaluates agent requests against all loaded rules, and resolves
/// conflicts when multiple rules match.
/// </summary>
public sealed class PolicyEngine
{
    private readonly List<Policy> _policies = new();
    private readonly object _policyLock = new();
    private readonly object _rateLimitLock = new();
    private readonly object _externalBackendLock = new();
    private readonly Dictionary<string, RateLimitWindow> _rateLimits = new(StringComparer.Ordinal);
    private readonly List<IExternalPolicyBackend> _externalBackends = new();

    /// <summary>
    /// The conflict resolution strategy to use when multiple rules match.
    /// Defaults to <see cref="ConflictResolutionStrategy.PriorityFirstMatch"/>.
    /// </summary>
    public ConflictResolutionStrategy ConflictStrategy { get; set; } =
        ConflictResolutionStrategy.PriorityFirstMatch;

    /// <summary>
    /// Loads a pre-parsed <see cref="Policy"/> into the engine.
    /// </summary>
    public void LoadPolicy(Policy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        lock (_policyLock)
        {
            _policies.Add(policy);
        }
    }

    /// <summary>
    /// Parses a YAML string into a <see cref="Policy"/> and loads it into the engine.
    /// </summary>
    public void LoadYaml(string yaml)
    {
        LoadPolicy(Policy.FromYaml(yaml));
    }

    /// <summary>
    /// Parses a JSON string into a <see cref="Policy"/> and loads it into the engine.
    /// </summary>
    public void LoadJson(string json)
    {
        LoadPolicy(Policy.FromJson(json));
    }

    /// <summary>
    /// Loads a policy from a YAML file on disk.
    /// </summary>
    public void LoadYamlFile(string path)
    {
        LoadPolicy(Policy.FromYamlFile(path));
    }

    /// <summary>
    /// Loads a policy from a JSON file on disk.
    /// </summary>
    public void LoadJsonFile(string path)
    {
        LoadPolicy(Policy.FromJsonFile(path));
    }

    /// <summary>
    /// Registers an external policy backend.
    /// </summary>
    public void AddExternalBackend(IExternalPolicyBackend backend)
    {
        ArgumentNullException.ThrowIfNull(backend);

        lock (_externalBackendLock)
        {
            _externalBackends.Add(backend);
        }
    }

    /// <summary>
    /// Adds an OPA/Rego backend to the engine.
    /// </summary>
    public void LoadOpa(
        string? regoContent = null,
        string? regoPath = null,
        string query = "data.agentgovernance.allow",
        string opaUrl = "http://localhost:8181",
        OpaEvaluationMode mode = OpaEvaluationMode.Auto)
    {
        AddExternalBackend(new OpaPolicyBackend(regoContent, regoPath, query, opaUrl, mode));
    }

    /// <summary>
    /// Adds a Cedar backend to the engine.
    /// </summary>
    public void LoadCedar(
        string? policyContent = null,
        string? policyPath = null,
        CedarEvaluationMode mode = CedarEvaluationMode.Auto)
    {
        AddExternalBackend(new CedarPolicyBackend(policyContent, policyPath, mode));
    }

    /// <summary>
    /// Returns a read-only snapshot of registered external backends.
    /// </summary>
    public IReadOnlyList<string> ListExternalBackends()
    {
        lock (_externalBackendLock)
        {
            return _externalBackends.Select(backend => backend.Name).ToList().AsReadOnly();
        }
    }

    /// <summary>
    /// Returns a read-only snapshot of all loaded policies.
    /// </summary>
    public IReadOnlyList<Policy> ListPolicies()
    {
        lock (_policyLock)
        {
            return _policies.ToList().AsReadOnly();
        }
    }

    /// <summary>
    /// Removes all loaded policies from the engine.
    /// </summary>
    public void ClearPolicies()
    {
        lock (_policyLock)
        {
            _policies.Clear();
        }

        lock (_externalBackendLock)
        {
            _externalBackends.Clear();
        }

        lock (_rateLimitLock)
        {
            _rateLimits.Clear();
        }
    }

    /// <summary>
    /// Evaluates an agent request against all loaded policies.
    /// </summary>
    public PolicyDecision Evaluate(string agentDid, Dictionary<string, object> context)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentDid);
        ArgumentNullException.ThrowIfNull(context);

        var normalizedDid = AgentGovernance.Trust.AgentIdentity.NormalizeDid(agentDid);
        var evaluatedAt = DateTime.UtcNow;
        var sw = Stopwatch.StartNew();

        List<Policy> snapshot;
        lock (_policyLock)
        {
            snapshot = _policies.ToList();
        }

        var evalContext = new Dictionary<string, object>(context, StringComparer.OrdinalIgnoreCase)
        {
            ["agent_did"] = normalizedDid
        };

        var internalEvaluation = EvaluateInternalPolicies(snapshot, evalContext, evaluatedAt, sw);
        var externalSnapshot = GetExternalBackendsSnapshot();
        sw.Stop();

        if (externalSnapshot.Count == 0)
        {
            return CloneDecision(
                internalEvaluation.Decision,
                sw.Elapsed.TotalMilliseconds,
                internalEvaluation.Decision.Metadata);
        }

        var externalDecisions = externalSnapshot
            .Select(backend => backend.Evaluate(evalContext))
            .ToList();

        var metadata = CreateExternalMetadata(internalEvaluation.Decision.Metadata, externalDecisions);
        var failingDecision = externalDecisions.FirstOrDefault(decision => !string.IsNullOrWhiteSpace(decision.Error) || !decision.Allowed);

        if (failingDecision is not null)
        {
            return new PolicyDecision
            {
                Allowed = false,
                Action = "deny",
                MatchedRule = internalEvaluation.Decision.MatchedRule,
                PolicyName = internalEvaluation.Decision.PolicyName,
                Reason = string.IsNullOrWhiteSpace(failingDecision.Error)
                    ? $"External policy backend '{failingDecision.Backend}' denied the request."
                    : $"External policy backend '{failingDecision.Backend}' failed: {failingDecision.Error}",
                Approvers = internalEvaluation.Decision.Approvers,
                RateLimited = internalEvaluation.Decision.RateLimited,
                RateLimitReset = internalEvaluation.Decision.RateLimitReset,
                EvaluatedAt = evaluatedAt,
                EvaluationMs = sw.Elapsed.TotalMilliseconds + externalDecisions.Sum(decision => decision.EvaluationMs),
                Metadata = metadata
            };
        }

        if (internalEvaluation.HadMatches)
        {
            return CloneDecision(
                internalEvaluation.Decision,
                sw.Elapsed.TotalMilliseconds + externalDecisions.Sum(decision => decision.EvaluationMs),
                metadata);
        }

        var externalAllowed = externalDecisions.Count > 0;
        if (externalAllowed)
        {
            return new PolicyDecision
            {
                Allowed = true,
                Action = "allow",
                Reason = $"Allowed by external policy backend(s): {string.Join(", ", externalDecisions.Select(decision => decision.Backend).Distinct(StringComparer.Ordinal))}.",
                EvaluatedAt = evaluatedAt,
                EvaluationMs = sw.Elapsed.TotalMilliseconds + externalDecisions.Sum(decision => decision.EvaluationMs),
                Metadata = metadata
            };
        }

        return CloneDecision(
            internalEvaluation.Decision,
            sw.Elapsed.TotalMilliseconds,
            metadata);
    }

    private static Dictionary<string, object> CreateExternalMetadata(
        Dictionary<string, object>? existingMetadata,
        IReadOnlyList<ExternalPolicyDecision> decisions)
    {
        var metadata = existingMetadata is null
            ? new Dictionary<string, object>(StringComparer.Ordinal)
            : new Dictionary<string, object>(existingMetadata, StringComparer.Ordinal);

        metadata["external_backends"] = decisions
            .Select(decision => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["backend"] = decision.Backend,
                ["allowed"] = decision.Allowed,
                ["reason"] = decision.Reason,
                ["evaluation_ms"] = decision.EvaluationMs,
                ["error"] = decision.Error ?? string.Empty
            })
            .ToList();

        return metadata;
    }

    private InternalEvaluation EvaluateInternalPolicies(
        IReadOnlyList<Policy> snapshot,
        Dictionary<string, object> evalContext,
        DateTime evaluatedAt,
        Stopwatch sw)
    {
        if (snapshot.Count == 0)
        {
            return new InternalEvaluation(PolicyDecision.AllowDefault(evaluatedAt, sw.Elapsed.TotalMilliseconds), HadPolicies: false, HadMatches: false);
        }

        var candidates = new List<CandidateDecision>();
        PolicyAction lastDefaultAction = PolicyAction.Deny;

        foreach (var policy in snapshot)
        {
            lastDefaultAction = policy.DefaultAction;

            foreach (var rule in policy.Rules)
            {
                if (!rule.Enabled)
                {
                    continue;
                }

                if (rule.Evaluate(evalContext))
                {
                    var decision = CreateDecisionFromRule(policy, rule, evaluatedAt, sw.Elapsed.TotalMilliseconds);
                    candidates.Add(new CandidateDecision(rule, decision, policy.Scope));
                }
            }
        }

        sw.Stop();
        var elapsed = sw.Elapsed.TotalMilliseconds;

        if (candidates.Count == 0)
        {
            var decision = lastDefaultAction == PolicyAction.Allow
                ? PolicyDecision.AllowDefault(evaluatedAt, elapsed)
                : PolicyDecision.DenyDefault(evaluatedAt, elapsed);
            return new InternalEvaluation(decision, HadPolicies: true, HadMatches: false);
        }

        var resolved = PolicyConflictResolver.Resolve(candidates, ConflictStrategy);
        if (resolved is null)
        {
            return new InternalEvaluation(PolicyDecision.DenyDefault(evaluatedAt, elapsed), HadPolicies: true, HadMatches: false);
        }

        return new InternalEvaluation(new PolicyDecision
        {
            Allowed = resolved.Allowed,
            Action = resolved.Action,
            MatchedRule = resolved.MatchedRule,
            PolicyName = resolved.PolicyName,
            Reason = resolved.Reason,
            Approvers = resolved.Approvers,
            RateLimited = resolved.RateLimited,
            RateLimitReset = resolved.RateLimitReset,
            EvaluatedAt = evaluatedAt,
            EvaluationMs = elapsed,
            Metadata = resolved.Metadata
        }, HadPolicies: true, HadMatches: true);
    }

    private PolicyDecision CreateDecisionFromRule(Policy policy, PolicyRule rule, DateTime evaluatedAt, double evaluationMs)
    {
        DateTime? rateLimitReset = null;
        string? reason = null;

        if (rule.Action == PolicyAction.RateLimit && !string.IsNullOrWhiteSpace(rule.Limit))
        {
            rateLimitReset = ReserveRateLimitWindow(policy.Name, rule.Name, rule.Limit!, out var exceeded);
            reason = exceeded
                ? $"Rate limit exceeded for rule '{rule.Name}': {rule.Limit}."
                : $"Matched rate-limit rule '{rule.Name}' ({rule.Limit}).";
        }

        var decision = PolicyDecision.FromRule(
            rule,
            policy.Name,
            evaluatedAt,
            evaluationMs,
            rateLimitReset);

        return reason is null
            ? decision
            : new PolicyDecision
            {
                Allowed = decision.Allowed,
                Action = decision.Action,
                MatchedRule = decision.MatchedRule,
                PolicyName = decision.PolicyName,
                Reason = reason,
                Approvers = decision.Approvers,
                RateLimited = decision.RateLimited,
                RateLimitReset = decision.RateLimitReset,
                EvaluatedAt = decision.EvaluatedAt,
                EvaluationMs = decision.EvaluationMs,
                Metadata = decision.Metadata
            };
    }

    private DateTime ReserveRateLimitWindow(string policyName, string ruleName, string limit, out bool exceeded)
    {
        var (maxCount, window) = ParseLimit(limit);
        var key = $"{policyName}:{ruleName}";
        var now = DateTime.UtcNow;

        lock (_rateLimitLock)
        {
            if (!_rateLimits.TryGetValue(key, out var state) || now >= state.ResetAt)
            {
                state = new RateLimitWindow(0, now.Add(window));
            }

            state = state with { Count = state.Count + 1 };
            _rateLimits[key] = state;
            exceeded = state.Count > maxCount;
            return state.ResetAt;
        }
    }

    private static (int Count, TimeSpan Window) ParseLimit(string limit)
    {
        var parts = limit.Split('/', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 2 || !int.TryParse(parts[0], out var count) || count <= 0)
        {
            throw new ArgumentException($"Invalid rate limit expression '{limit}'.", nameof(limit));
        }

        return parts[1].ToLowerInvariant() switch
        {
            "second" => (count, TimeSpan.FromSeconds(1)),
            "minute" => (count, TimeSpan.FromMinutes(1)),
            "hour" => (count, TimeSpan.FromHours(1)),
            "day" => (count, TimeSpan.FromDays(1)),
            _ => throw new ArgumentException($"Unsupported rate limit window '{parts[1]}'.", nameof(limit))
        };
    }

    private sealed record RateLimitWindow(int Count, DateTime ResetAt);
    private sealed record InternalEvaluation(PolicyDecision Decision, bool HadPolicies, bool HadMatches);

    private static PolicyDecision CloneDecision(PolicyDecision decision, double evaluationMs, Dictionary<string, object>? metadata)
    {
        return new PolicyDecision
        {
            Allowed = decision.Allowed,
            Action = decision.Action,
            MatchedRule = decision.MatchedRule,
            PolicyName = decision.PolicyName,
            Reason = decision.Reason,
            Approvers = new List<string>(decision.Approvers),
            RateLimited = decision.RateLimited,
            RateLimitReset = decision.RateLimitReset,
            EvaluatedAt = decision.EvaluatedAt,
            EvaluationMs = evaluationMs,
            Metadata = metadata
        };
    }

    private List<IExternalPolicyBackend> GetExternalBackendsSnapshot()
    {
        lock (_externalBackendLock)
        {
            return _externalBackends.ToList();
        }
    }
}
