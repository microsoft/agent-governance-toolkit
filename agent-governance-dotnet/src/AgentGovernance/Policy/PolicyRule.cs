// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Text.RegularExpressions;

namespace AgentGovernance.Policy;

/// <summary>
/// Supported actions for a governance policy rule.
/// </summary>
public enum PolicyAction
{
    /// <summary>Allow the request.</summary>
    Allow,

    /// <summary>Deny the request.</summary>
    Deny,

    /// <summary>Warn but still allow the request.</summary>
    Warn,

    /// <summary>Require explicit approval before proceeding.</summary>
    RequireApproval,

    /// <summary>Log the request for audit purposes only.</summary>
    Log,

    /// <summary>Apply rate-limiting to the request.</summary>
    RateLimit
}

/// <summary>
/// Represents a single governance policy rule that can be evaluated against a context.
/// </summary>
public sealed class PolicyRule
{
    // Regex patterns for simple expression evaluation (mirrors Python implementation).
    private static readonly Regex EqualityPattern =
        new(@"^(\w+(?:\.\w+)*)\s*==\s*['""]([^'""]+)['""]$", RegexOptions.Compiled);

    private static readonly Regex InequalityPattern =
        new(@"^(\w+(?:\.\w+)*)\s*!=\s*['""]([^'""]+)['""]$", RegexOptions.Compiled);

    private static readonly Regex NumericComparisonPattern =
        new(@"^(\w+(?:\.\w+)*)\s*(>=|<=|>|<)\s*(\d+(?:\.\d+)?)$", RegexOptions.Compiled);

    private static readonly Regex InListPattern =
        new(@"^(\w+(?:\.\w+)*)\s+in\s+(\w+(?:\.\w+)*)$", RegexOptions.Compiled);

    private static readonly Regex BooleanFieldPattern =
        new(@"^(\w+(?:\.\w+)*)$", RegexOptions.Compiled);

    /// <summary>
    /// Unique name of the rule within a policy.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// Condition expression to evaluate (e.g., "tool_name in blocked_tools").
    /// Supports equality, inequality, numeric comparisons, <c>in</c> list checks,
    /// boolean fields, and compound <c>and</c>/<c>or</c> operators.
    /// </summary>
    public required string Condition { get; init; }

    /// <summary>
    /// Action to take when the condition matches.
    /// </summary>
    public PolicyAction Action { get; init; } = PolicyAction.Deny;

    /// <summary>
    /// Priority of the rule. Higher values are evaluated first during conflict resolution.
    /// </summary>
    public int Priority { get; init; }

    /// <summary>
    /// Whether the rule is active. Disabled rules are skipped during evaluation.
    /// </summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// Optional list of approver identifiers (e.g., email addresses) required
    /// when <see cref="Action"/> is <see cref="PolicyAction.RequireApproval"/>.
    /// </summary>
    public List<string> Approvers { get; init; } = new();

    /// <summary>
    /// Optional rate-limit expression (e.g., "100/hour") when
    /// <see cref="Action"/> is <see cref="PolicyAction.RateLimit"/>.
    /// </summary>
    public string? Limit { get; init; }

    /// <summary>
    /// Optional human-readable description of what this rule does.
    /// </summary>
    public string? Description { get; init; }

    /// <summary>
    /// Evaluates the rule condition against the provided context dictionary.
    /// </summary>
    /// <param name="context">
    /// A dictionary of contextual values (e.g., tool_name, action.type, data.contains_pii).
    /// Supports nested keys via dot notation.
    /// </param>
    /// <returns><c>true</c> if the condition matches; otherwise <c>false</c>.</returns>
    public bool Evaluate(IReadOnlyDictionary<string, object> context)
    {
        if (!Enabled)
        {
            return false;
        }

        try
        {
            return EvaluateExpression(Condition.Trim(), context);
        }
        catch
        {
            // Safe-fail: if evaluation errors, the rule does not match.
            return false;
        }
    }

    /// <summary>
    /// Recursively evaluates a condition expression string.
    /// Supports compound operators (<c>and</c>, <c>or</c>) and atomic conditions.
    /// </summary>
    private static bool EvaluateExpression(string expression, IReadOnlyDictionary<string, object> context)
    {
        // Handle compound 'or' (lowest precedence).
        var orParts = SplitCompound(expression, " or ");
        if (orParts.Count > 1)
        {
            foreach (var part in orParts)
            {
                if (EvaluateExpression(part.Trim(), context))
                {
                    return true;
                }
            }
            return false;
        }

        // Handle compound 'and'.
        var andParts = SplitCompound(expression, " and ");
        if (andParts.Count > 1)
        {
            foreach (var part in andParts)
            {
                if (!EvaluateExpression(part.Trim(), context))
                {
                    return false;
                }
            }
            return true;
        }

        // Atomic condition evaluation.
        return EvaluateAtomic(expression, context);
    }

    /// <summary>
    /// Splits an expression on a compound keyword, respecting that the keyword
    /// must be surrounded by whitespace (not inside a quoted string).
    /// </summary>
    private static List<string> SplitCompound(string expression, string keyword)
    {
        var parts = new List<string>();
        var current = new System.Text.StringBuilder();
        bool inSingleQuote = false;
        bool inDoubleQuote = false;

        for (int i = 0; i < expression.Length; i++)
        {
            char c = expression[i];

            // Toggle quote state (no escaping needed for policy expressions)
            if (c == '\'' && !inDoubleQuote)
            {
                inSingleQuote = !inSingleQuote;
                current.Append(c);
                continue;
            }
            if (c == '"' && !inSingleQuote)
            {
                inDoubleQuote = !inDoubleQuote;
                current.Append(c);
                continue;
            }

            // Only split on keyword when outside quotes
            if (!inSingleQuote && !inDoubleQuote
                && i + keyword.Length <= expression.Length
                && expression.Substring(i, keyword.Length).Equals(keyword, StringComparison.OrdinalIgnoreCase))
            {
                parts.Add(current.ToString());
                current.Clear();
                i += keyword.Length - 1; // -1 because loop increments
                continue;
            }

            current.Append(c);
        }

        parts.Add(current.ToString());
        return parts;
    }

    /// <summary>
    /// Evaluates a single atomic condition (equality, inequality, numeric comparison,
    /// <c>in</c> list membership, or boolean field).
    /// </summary>
    private static bool EvaluateAtomic(string expression, IReadOnlyDictionary<string, object> context)
    {
        // Equality: field == 'value'
        var match = EqualityPattern.Match(expression);
        if (match.Success)
        {
            var fieldValue = ResolveField(match.Groups[1].Value, context);
            return string.Equals(fieldValue?.ToString(), match.Groups[2].Value, StringComparison.Ordinal);
        }

        // Inequality: field != 'value'
        match = InequalityPattern.Match(expression);
        if (match.Success)
        {
            var fieldValue = ResolveField(match.Groups[1].Value, context);
            return !string.Equals(fieldValue?.ToString(), match.Groups[2].Value, StringComparison.Ordinal);
        }

        // Numeric comparison: field > 10, field <= 100
        match = NumericComparisonPattern.Match(expression);
        if (match.Success)
        {
            var fieldValue = ResolveField(match.Groups[1].Value, context);
            if (fieldValue is not null && double.TryParse(fieldValue.ToString(), out var left)
                && double.TryParse(match.Groups[3].Value, out var right))
            {
                return match.Groups[2].Value switch
                {
                    ">" => left > right,
                    ">=" => left >= right,
                    "<" => left < right,
                    "<=" => left <= right,
                    _ => false
                };
            }
            return false;
        }

        // In-list: field in list_field
        match = InListPattern.Match(expression);
        if (match.Success)
        {
            var itemValue = ResolveField(match.Groups[1].Value, context);
            var listValue = ResolveField(match.Groups[2].Value, context);

            if (itemValue is not null && listValue is IEnumerable<object> list)
            {
                var itemStr = itemValue.ToString();
                return list.Any(x => string.Equals(x?.ToString(), itemStr, StringComparison.Ordinal));
            }

            // Also support comma-separated string lists.
            if (itemValue is not null && listValue is string csvList)
            {
                var itemStr = itemValue.ToString();
                return csvList.Split(',').Select(s => s.Trim()).Contains(itemStr);
            }

            return false;
        }

        // Boolean field: data.contains_pii (truthiness check).
        match = BooleanFieldPattern.Match(expression);
        if (match.Success)
        {
            var fieldValue = ResolveField(match.Groups[1].Value, context);
            return IsTruthy(fieldValue);
        }

        return false;
    }

    /// <summary>
    /// Resolves a possibly dot-notated field path against the context dictionary.
    /// Supports nested dictionaries (e.g., "data.contains_pii" resolves
    /// context["data"]["contains_pii"]).
    /// </summary>
    internal static object? ResolveField(string path, IReadOnlyDictionary<string, object> context)
    {
        var segments = path.Split('.');
        object? current = null;

        // Try the full key first (some contexts use dotted keys directly).
        if (context.TryGetValue(path, out var directValue))
        {
            return directValue;
        }

        // Walk nested dictionaries.
        if (!context.TryGetValue(segments[0], out current))
        {
            return null;
        }

        for (int i = 1; i < segments.Length; i++)
        {
            if (current is IReadOnlyDictionary<string, object> roDict)
            {
                if (!roDict.TryGetValue(segments[i], out current))
                {
                    return null;
                }
            }
            else if (current is IDictionary<string, object> dict)
            {
                if (!dict.TryGetValue(segments[i], out current))
                {
                    return null;
                }
            }
            else
            {
                return null;
            }
        }

        return current;
    }

    /// <summary>
    /// Determines the truthiness of a value using Python-like semantics.
    /// </summary>
    private static bool IsTruthy(object? value) => value switch
    {
        null => false,
        bool b => b,
        int i => i != 0,
        long l => l != 0,
        double d => d != 0.0,
        string s => !string.IsNullOrEmpty(s) && !s.Equals("false", StringComparison.OrdinalIgnoreCase),
        _ => true
    };

    /// <summary>
    /// Parses a <see cref="PolicyAction"/> from a YAML/string value.
    /// </summary>
    /// <param name="value">The string representation (e.g., "deny", "require_approval").</param>
    /// <returns>The parsed <see cref="PolicyAction"/>.</returns>
    /// <exception cref="ArgumentException">Thrown when the value is not a recognised action.</exception>
    public static PolicyAction ParseAction(string value)
    {
        return value.ToLowerInvariant().Replace("_", "") switch
        {
            "allow" => PolicyAction.Allow,
            "deny" => PolicyAction.Deny,
            "warn" => PolicyAction.Warn,
            "requireapproval" => PolicyAction.RequireApproval,
            "log" => PolicyAction.Log,
            "ratelimit" => PolicyAction.RateLimit,
            _ => throw new ArgumentException($"Unknown policy action: '{value}'", nameof(value))
        };
    }
}
