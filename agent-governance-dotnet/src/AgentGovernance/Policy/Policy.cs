// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace AgentGovernance.Policy;

/// <summary>
/// Represents a complete governance policy document loaded from YAML.
/// A policy contains metadata and an ordered list of <see cref="PolicyRule"/> entries
/// that are evaluated against agent requests.
/// </summary>
public sealed class Policy
{
    /// <summary>
    /// Supported API versions for policy schema validation.
    /// </summary>
    private static readonly HashSet<string> SupportedApiVersions = new(StringComparer.OrdinalIgnoreCase)
    {
        "governance.toolkit/v1"
    };

    /// <summary>
    /// The API version of the policy schema (e.g., "governance.toolkit/v1").
    /// </summary>
    public string ApiVersion { get; init; } = "governance.toolkit/v1";

    /// <summary>
    /// The version of this policy document (e.g., "1.0").
    /// </summary>
    public string Version { get; init; } = "1.0";

    /// <summary>
    /// Unique name of the policy.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// Optional human-readable description of the policy.
    /// </summary>
    public string? Description { get; init; }

    /// <summary>
    /// The scope of this policy used for conflict resolution.
    /// </summary>
    public PolicyScope Scope { get; init; } = PolicyScope.Global;

    /// <summary>
    /// The default action to take when no rules match.
    /// </summary>
    public PolicyAction DefaultAction { get; init; } = PolicyAction.Deny;

    /// <summary>
    /// Ordered list of policy rules to evaluate.
    /// </summary>
    public List<PolicyRule> Rules { get; init; } = new();

    /// <summary>
    /// Deserializes a <see cref="Policy"/> from a YAML string.
    /// </summary>
    /// <param name="yaml">The YAML content representing a policy document.</param>
    /// <returns>A new <see cref="Policy"/> instance.</returns>
    /// <exception cref="ArgumentException">Thrown when the YAML is invalid or the API version is unsupported.</exception>
    public static Policy FromYaml(string yaml)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(yaml);

        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();

        var raw = deserializer.Deserialize<YamlPolicyDocument>(yaml)
            ?? throw new ArgumentException("Failed to parse YAML policy document.");

        // Validate API version.
        var apiVersion = raw.ApiVersion ?? "governance.toolkit/v1";
        if (!SupportedApiVersions.Contains(apiVersion))
        {
            throw new ArgumentException(
                $"Unsupported policy API version: '{apiVersion}'. " +
                $"Supported: {string.Join(", ", SupportedApiVersions)}");
        }

        var scope = PolicyConflictResolver.ParseScope(raw.Scope);
        var defaultAction = ParseDefaultAction(raw.DefaultAction);

        var rules = new List<PolicyRule>();
        if (raw.Rules is not null)
        {
            foreach (var ruleDoc in raw.Rules)
            {
                rules.Add(new PolicyRule
                {
                    Name = ruleDoc.Name ?? throw new ArgumentException("Every rule must have a 'name'."),
                    Condition = ruleDoc.Condition ?? throw new ArgumentException($"Rule '{ruleDoc.Name}' is missing a 'condition'."),
                    Action = PolicyRule.ParseAction(ruleDoc.Action ?? "deny"),
                    Priority = ruleDoc.Priority ?? 0,
                    Enabled = ruleDoc.Enabled ?? true,
                    Approvers = ruleDoc.Approvers ?? new List<string>(),
                    Limit = ruleDoc.Limit,
                    Description = ruleDoc.Description
                });
            }
        }

        return new Policy
        {
            ApiVersion = apiVersion,
            Version = raw.Version ?? "1.0",
            Name = raw.Name ?? throw new ArgumentException("Policy must have a 'name'."),
            Description = raw.Description,
            Scope = scope,
            DefaultAction = defaultAction,
            Rules = rules
        };
    }

    /// <summary>
    /// Loads a <see cref="Policy"/> from a YAML file on disk.
    /// </summary>
    /// <param name="path">Absolute or relative path to the YAML policy file.</param>
    /// <returns>A new <see cref="Policy"/> instance.</returns>
    /// <exception cref="FileNotFoundException">Thrown when the file does not exist.</exception>
    public static Policy FromYamlFile(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Policy file not found: '{path}'", path);
        }

        var yaml = File.ReadAllText(path);
        return FromYaml(yaml);
    }

    /// <summary>
    /// Parses the default_action field from YAML into a <see cref="PolicyAction"/>.
    /// Defaults to <see cref="PolicyAction.Deny"/> when not specified.
    /// </summary>
    private static PolicyAction ParseDefaultAction(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return PolicyAction.Deny;
        }

        return PolicyRule.ParseAction(value);
    }

    // ── Internal YAML deserialization models ──────────────────────────────

    /// <summary>
    /// Internal model for YAML deserialization of a policy document.
    /// Uses snake_case naming convention via YamlDotNet.
    /// </summary>
    internal sealed class YamlPolicyDocument
    {
        [YamlMember(Alias = "apiVersion", ApplyNamingConventions = false)]
        public string? ApiVersion { get; set; }
        public string? Version { get; set; }
        public string? Name { get; set; }
        public string? Description { get; set; }
        public string? Scope { get; set; }
        public string? DefaultAction { get; set; }
        public List<YamlRuleDocument>? Rules { get; set; }
    }

    /// <summary>
    /// Internal model for YAML deserialization of a policy rule.
    /// </summary>
    internal sealed class YamlRuleDocument
    {
        public string? Name { get; set; }
        public string? Description { get; set; }
        public string? Condition { get; set; }
        public string? Action { get; set; }
        public int? Priority { get; set; }
        public bool? Enabled { get; set; }
        public List<string>? Approvers { get; set; }
        public string? Limit { get; set; }
    }
}
