// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using System.Text.Json.Serialization;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace AgentGovernance.Policy;

/// <summary>
/// Represents a complete governance policy document loaded from YAML or JSON.
/// </summary>
public sealed class Policy
{
    private static readonly HashSet<string> SupportedApiVersions = new(StringComparer.OrdinalIgnoreCase)
    {
        "governance.toolkit/v1"
    };

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    // YamlDotNet's IDeserializer is documented as thread-safe once built, and
    // constructing one is non-trivial (it resolves type inspectors, converters,
    // and naming conventions). Cache a single instance so policy loading does
    // not pay that cost on every FromYaml / FromYamlFile call.
    private static readonly IDeserializer YamlDeserializer = new DeserializerBuilder()
        .WithNamingConvention(UnderscoredNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

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
    public static Policy FromYaml(string yaml)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(yaml);

        var raw = YamlDeserializer.Deserialize<PolicyDocument>(yaml)
            ?? throw new ArgumentException("Failed to parse YAML policy document.");
        return FromDocument(raw);
    }

    /// <summary>
    /// Deserializes a <see cref="Policy"/> from a JSON string.
    /// </summary>
    public static Policy FromJson(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);

        var raw = JsonSerializer.Deserialize<PolicyDocument>(json, JsonOptions)
            ?? throw new ArgumentException("Failed to parse JSON policy document.");
        return FromDocument(raw);
    }

    /// <summary>
    /// Loads a <see cref="Policy"/> from a YAML file on disk.
    /// </summary>
    public static Policy FromYamlFile(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Policy file not found: '{path}'", path);
        }

        var yaml = File.ReadAllText(path, System.Text.Encoding.UTF8);
        return FromYaml(yaml);
    }

    /// <summary>
    /// Loads a <see cref="Policy"/> from a JSON file on disk.
    /// </summary>
    public static Policy FromJsonFile(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Policy file not found: '{path}'", path);
        }

        var json = File.ReadAllText(path, System.Text.Encoding.UTF8);
        return FromJson(json);
    }

    private static Policy FromDocument(PolicyDocument raw)
    {
        var apiVersion = raw.ApiVersion ?? "governance.toolkit/v1";
        if (!SupportedApiVersions.Contains(apiVersion))
        {
            throw new ArgumentException(
                $"Unsupported policy API version: '{apiVersion}'. Supported: {string.Join(", ", SupportedApiVersions)}");
        }

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
            Scope = PolicyConflictResolver.ParseScope(raw.Scope),
            DefaultAction = ParseDefaultAction(raw.DefaultAction),
            Rules = rules
        };
    }

    private static PolicyAction ParseDefaultAction(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return PolicyAction.Deny;
        }

        return PolicyRule.ParseAction(value);
    }

    internal sealed class PolicyDocument
    {
        [YamlMember(Alias = "apiVersion", ApplyNamingConventions = false)]
        [JsonPropertyName("apiVersion")]
        public string? ApiVersion { get; set; }

        [YamlMember(Alias = "version")]
        [JsonPropertyName("version")]
        public string? Version { get; set; }

        [YamlMember(Alias = "name")]
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [YamlMember(Alias = "description")]
        [JsonPropertyName("description")]
        public string? Description { get; set; }

        [YamlMember(Alias = "scope")]
        [JsonPropertyName("scope")]
        public string? Scope { get; set; }

        [YamlMember(Alias = "default_action")]
        [JsonPropertyName("default_action")]
        public string? DefaultAction { get; set; }

        [YamlMember(Alias = "rules")]
        [JsonPropertyName("rules")]
        public List<RuleDocument>? Rules { get; set; }
    }

    internal sealed class RuleDocument
    {
        [YamlMember(Alias = "name")]
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [YamlMember(Alias = "description")]
        [JsonPropertyName("description")]
        public string? Description { get; set; }

        [YamlMember(Alias = "condition")]
        [JsonPropertyName("condition")]
        public string? Condition { get; set; }

        [YamlMember(Alias = "action")]
        [JsonPropertyName("action")]
        public string? Action { get; set; }

        [YamlMember(Alias = "priority")]
        [JsonPropertyName("priority")]
        public int? Priority { get; set; }

        [YamlMember(Alias = "enabled")]
        [JsonPropertyName("enabled")]
        public bool? Enabled { get; set; }

        [YamlMember(Alias = "approvers")]
        [JsonPropertyName("approvers")]
        public List<string>? Approvers { get; set; }

        [YamlMember(Alias = "limit")]
        [JsonPropertyName("limit")]
        public string? Limit { get; set; }
    }
}
