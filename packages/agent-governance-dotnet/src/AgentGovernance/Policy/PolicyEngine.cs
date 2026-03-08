// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Diagnostics;

namespace AgentGovernance.Policy;

/// <summary>
/// Main governance policy evaluation engine. Loads one or more <see cref="Policy"/>
/// documents, evaluates agent requests against all loaded rules, and resolves
/// conflicts when multiple rules match.
/// <para>
/// This class is thread-safe. Policies are stored in a lock-protected list and
/// evaluation is side-effect free.
/// </para>
/// </summary>
public sealed class PolicyEngine
{
    private readonly List<Policy> _policies = new();
    private readonly object _lock = new();

    /// <summary>
    /// The conflict resolution strategy to use when multiple rules match.
    /// Defaults to <see cref="ConflictResolutionStrategy.PriorityFirstMatch"/>.
    /// </summary>
    public ConflictResolutionStrategy ConflictStrategy { get; set; } =
        ConflictResolutionStrategy.PriorityFirstMatch;

    /// <summary>
    /// Loads a pre-parsed <see cref="Policy"/> into the engine.
    /// </summary>
    /// <param name="policy">The policy to load.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="policy"/> is <c>null</c>.</exception>
    public void LoadPolicy(Policy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        lock (_lock)
        {
            _policies.Add(policy);
        }
    }

    /// <summary>
    /// Parses a YAML string into a <see cref="Policy"/> and loads it into the engine.
    /// </summary>
    /// <param name="yaml">YAML content representing a policy document.</param>
    public void LoadYaml(string yaml)
    {
        var policy = Policy.FromYaml(yaml);
        LoadPolicy(policy);
    }

    /// <summary>
    /// Loads a policy from a YAML file on disk.
    /// </summary>
    /// <param name="path">Path to the YAML policy file.</param>
    public void LoadYamlFile(string path)
    {
        var policy = Policy.FromYamlFile(path);
        LoadPolicy(policy);
    }

    /// <summary>
    /// Returns a read-only snapshot of all loaded policies.
    /// </summary>
    /// <returns>An immutable list of loaded policies.</returns>
    public IReadOnlyList<Policy> ListPolicies()
    {
        lock (_lock)
        {
            return _policies.ToList().AsReadOnly();
        }
    }

    /// <summary>
    /// Removes all loaded policies from the engine.
    /// </summary>
    public void ClearPolicies()
    {
        lock (_lock)
        {
            _policies.Clear();
        }
    }

    /// <summary>
    /// Evaluates an agent request against all loaded policies.
    /// </summary>
    /// <param name="agentDid">
    /// The decentralised identifier of the agent making the request (e.g., "did:mesh:abc123").
    /// This is injected into the evaluation context as <c>agent_did</c>.
    /// </param>
    /// <param name="context">
    /// A dictionary of contextual values for condition evaluation.
    /// Common keys include <c>tool_name</c>, <c>action.type</c>, etc.
    /// </param>
    /// <returns>
    /// A <see cref="PolicyDecision"/> representing the outcome.
    /// If no policies are loaded, the request is allowed by default.
    /// </returns>
    public PolicyDecision Evaluate(string agentDid, Dictionary<string, object> context)
    {
        var sw = Stopwatch.StartNew();

        // Snapshot policies under lock.
        List<Policy> snapshot;
        lock (_lock)
        {
            snapshot = _policies.ToList();
        }

        if (snapshot.Count == 0)
        {
            sw.Stop();
            return PolicyDecision.AllowDefault(sw.Elapsed.TotalMilliseconds);
        }

        // Inject agent DID into context so rules can reference it.
        var evalContext = new Dictionary<string, object>(context, StringComparer.OrdinalIgnoreCase)
        {
            ["agent_did"] = agentDid
        };

        // Collect all candidate decisions from all policies.
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
                    var decision = PolicyDecision.FromRule(rule, sw.Elapsed.TotalMilliseconds);
                    candidates.Add(new CandidateDecision(rule, decision, policy.Scope));
                }
            }
        }

        sw.Stop();
        var elapsed = sw.Elapsed.TotalMilliseconds;

        // No rules matched — return the default action.
        if (candidates.Count == 0)
        {
            return lastDefaultAction == PolicyAction.Allow
                ? PolicyDecision.AllowDefault(elapsed)
                : PolicyDecision.DenyDefault(elapsed);
        }

        // Resolve conflicts and return the winning decision.
        var resolved = PolicyConflictResolver.Resolve(candidates, ConflictStrategy);
        if (resolved is not null)
        {
            // Update evaluation time to include conflict resolution.
            return new PolicyDecision
            {
                Allowed = resolved.Allowed,
                Action = resolved.Action,
                MatchedRule = resolved.MatchedRule,
                Reason = resolved.Reason,
                Approvers = resolved.Approvers,
                RateLimited = resolved.RateLimited,
                EvaluationMs = elapsed
            };
        }

        return PolicyDecision.DenyDefault(elapsed);
    }
}
