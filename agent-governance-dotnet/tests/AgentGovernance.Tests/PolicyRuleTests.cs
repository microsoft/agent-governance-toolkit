// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Policy;
using Xunit;

namespace AgentGovernance.Tests;

public class PolicyRuleTests
{
    [Fact]
    public void Evaluate_EqualityCondition_MatchesWhenEqual()
    {
        var rule = new PolicyRule
        {
            Name = "test-equality",
            Condition = "tool_name == 'file_write'",
            Action = PolicyAction.Deny
        };

        var context = new Dictionary<string, object> { ["tool_name"] = "file_write" };
        Assert.True(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_EqualityCondition_DoesNotMatchWhenDifferent()
    {
        var rule = new PolicyRule
        {
            Name = "test-equality-miss",
            Condition = "tool_name == 'file_write'",
            Action = PolicyAction.Deny
        };

        var context = new Dictionary<string, object> { ["tool_name"] = "file_read" };
        Assert.False(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_InequalityCondition_Matches()
    {
        var rule = new PolicyRule
        {
            Name = "test-inequality",
            Condition = "role != 'admin'",
            Action = PolicyAction.Deny
        };

        var context = new Dictionary<string, object> { ["role"] = "user" };
        Assert.True(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_NumericGreaterThan_Matches()
    {
        var rule = new PolicyRule
        {
            Name = "test-gt",
            Condition = "request_count > 100",
            Action = PolicyAction.RateLimit
        };

        var context = new Dictionary<string, object> { ["request_count"] = 150 };
        Assert.True(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_NumericLessThanOrEqual_DoesNotMatch()
    {
        var rule = new PolicyRule
        {
            Name = "test-lte-miss",
            Condition = "request_count > 100",
            Action = PolicyAction.RateLimit
        };

        var context = new Dictionary<string, object> { ["request_count"] = 50 };
        Assert.False(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_InListCondition_MatchesWhenInList()
    {
        var rule = new PolicyRule
        {
            Name = "test-in-list",
            Condition = "tool_name in blocked_tools",
            Action = PolicyAction.Deny
        };

        var context = new Dictionary<string, object>
        {
            ["tool_name"] = "rm",
            ["blocked_tools"] = new List<object> { "rm", "format", "shutdown" }
        };

        Assert.True(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_InListCondition_DoesNotMatchWhenNotInList()
    {
        var rule = new PolicyRule
        {
            Name = "test-in-list-miss",
            Condition = "tool_name in blocked_tools",
            Action = PolicyAction.Deny
        };

        var context = new Dictionary<string, object>
        {
            ["tool_name"] = "file_read",
            ["blocked_tools"] = new List<object> { "rm", "format", "shutdown" }
        };

        Assert.False(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_BooleanFieldCondition_MatchesWhenTrue()
    {
        var rule = new PolicyRule
        {
            Name = "test-bool",
            Condition = "contains_pii",
            Action = PolicyAction.RequireApproval
        };

        var context = new Dictionary<string, object> { ["contains_pii"] = true };
        Assert.True(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_BooleanFieldCondition_DoesNotMatchWhenFalse()
    {
        var rule = new PolicyRule
        {
            Name = "test-bool-false",
            Condition = "contains_pii",
            Action = PolicyAction.RequireApproval
        };

        var context = new Dictionary<string, object> { ["contains_pii"] = false };
        Assert.False(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_CompoundAndCondition_BothMustMatch()
    {
        var rule = new PolicyRule
        {
            Name = "test-and",
            Condition = "tool_name == 'export' and contains_pii",
            Action = PolicyAction.RequireApproval
        };

        // Both conditions true.
        var context1 = new Dictionary<string, object>
        {
            ["tool_name"] = "export",
            ["contains_pii"] = true
        };
        Assert.True(rule.Evaluate(context1));

        // One condition false.
        var context2 = new Dictionary<string, object>
        {
            ["tool_name"] = "export",
            ["contains_pii"] = false
        };
        Assert.False(rule.Evaluate(context2));
    }

    [Fact]
    public void Evaluate_CompoundOrCondition_EitherCanMatch()
    {
        var rule = new PolicyRule
        {
            Name = "test-or",
            Condition = "tool_name == 'rm' or tool_name == 'format'",
            Action = PolicyAction.Deny
        };

        var context1 = new Dictionary<string, object> { ["tool_name"] = "rm" };
        Assert.True(rule.Evaluate(context1));

        var context2 = new Dictionary<string, object> { ["tool_name"] = "format" };
        Assert.True(rule.Evaluate(context2));

        var context3 = new Dictionary<string, object> { ["tool_name"] = "read" };
        Assert.False(rule.Evaluate(context3));
    }

    [Fact]
    public void Evaluate_DisabledRule_NeverMatches()
    {
        var rule = new PolicyRule
        {
            Name = "test-disabled",
            Condition = "tool_name == 'anything'",
            Action = PolicyAction.Deny,
            Enabled = false
        };

        var context = new Dictionary<string, object> { ["tool_name"] = "anything" };
        Assert.False(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_NestedDotNotation_ResolvesCorrectly()
    {
        var rule = new PolicyRule
        {
            Name = "test-nested",
            Condition = "data.classification == 'secret'",
            Action = PolicyAction.Deny
        };

        var context = new Dictionary<string, object>
        {
            ["data"] = new Dictionary<string, object> { ["classification"] = "secret" }
        };

        Assert.True(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_MissingField_ReturnsFalseSafely()
    {
        var rule = new PolicyRule
        {
            Name = "test-missing",
            Condition = "nonexistent_field == 'value'",
            Action = PolicyAction.Deny
        };

        var context = new Dictionary<string, object>();
        Assert.False(rule.Evaluate(context));
    }

    [Fact]
    public void ParseAction_ValidValues_ParseCorrectly()
    {
        Assert.Equal(PolicyAction.Allow, PolicyRule.ParseAction("allow"));
        Assert.Equal(PolicyAction.Deny, PolicyRule.ParseAction("deny"));
        Assert.Equal(PolicyAction.Warn, PolicyRule.ParseAction("warn"));
        Assert.Equal(PolicyAction.RequireApproval, PolicyRule.ParseAction("require_approval"));
        Assert.Equal(PolicyAction.Log, PolicyRule.ParseAction("log"));
        Assert.Equal(PolicyAction.RateLimit, PolicyRule.ParseAction("rate_limit"));
    }

    [Fact]
    public void ParseAction_InvalidValue_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => PolicyRule.ParseAction("invalid"));
    }

    [Fact]
    public void Evaluate_UnexpectedException_Propagates_NotSilentlyFalse()
    {
        // Regression: Evaluate used to catch every exception and return false.
        // Under DefaultAction=Allow, a buggy DENY rule that threw would silently
        // fail open. Unexpected exception types (NRE, NotSupportedException,
        // etc.) must now propagate so the engine fails closed.
        var rule = new PolicyRule
        {
            Name = "broken-equality",
            Condition = "tool_name == 'file_write'",
            Action = PolicyAction.Deny
        };

        var context = new Dictionary<string, object>
        {
            ["tool_name"] = new ThrowingToString()
        };

        Assert.Throws<NotSupportedException>(() => rule.Evaluate(context));
    }

    private sealed class ThrowingToString
    {
        public override string ToString() =>
            throw new NotSupportedException("simulated rule-data bug");
    }

    [Fact]
    public void Evaluate_NestedDotNotation_WinsOverFlatDottedKey()
    {
        var rule = new PolicyRule
        {
            Name = "nested-wins",
            Condition = "data.classification == 'secret'",
            Action = PolicyAction.Deny
        };

        var context = new Dictionary<string, object>
        {
            ["data"] = new Dictionary<string, object>
            {
                ["classification"] = "secret",
            },
            ["data.classification"] = "public",
        };

        Assert.True(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_FallsBackToFlatDottedKey_WhenNoNestedShape()
    {
        var rule = new PolicyRule
        {
            Name = "flat-fallback",
            Condition = "data.classification == 'public'",
            Action = PolicyAction.Allow
        };

        var context = new Dictionary<string, object>
        {
            ["data.classification"] = "public",
        };

        Assert.True(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_NumericEquality_MatchesInteger()
    {
        var rule = new PolicyRule
        {
            Name = "test-numeric-eq-int",
            Condition = "count == 5",
            Action = PolicyAction.Deny
        };

        var context = new Dictionary<string, object> { ["count"] = 5 };
        Assert.True(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_NumericEquality_MatchesDecimal()
    {
        var rule = new PolicyRule
        {
            Name = "test-numeric-eq-decimal",
            Condition = "score == 3.14",
            Action = PolicyAction.Deny
        };

        var context = new Dictionary<string, object> { ["score"] = 3.14 };
        Assert.True(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_NumericEquality_MatchesNegative()
    {
        var rule = new PolicyRule
        {
            Name = "test-numeric-eq-negative",
            Condition = "temperature == -5",
            Action = PolicyAction.Deny
        };

        var context = new Dictionary<string, object> { ["temperature"] = -5 };
        Assert.True(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_NumericEquality_MatchesZero()
    {
        var rule = new PolicyRule
        {
            Name = "test-numeric-eq-zero",
            Condition = "count == 0",
            Action = PolicyAction.Deny
        };

        var context = new Dictionary<string, object> { ["count"] = 0 };
        Assert.True(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_NumericInequality_MatchesInteger()
    {
        var rule = new PolicyRule
        {
            Name = "test-numeric-neq-int",
            Condition = "count != 6",
            Action = PolicyAction.Deny
        };

        var context = new Dictionary<string, object> { ["count"] = 5 };
        Assert.True(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_NumericInequality_MatchesNegative()
    {
        var rule = new PolicyRule
        {
            Name = "test-numeric-neq-negative",
            Condition = "temperature != 5",
            Action = PolicyAction.Allow
        };

        var context = new Dictionary<string, object> { ["temperature"] = -5 };
        Assert.True(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_NumericEquality_DoesNotMatchWrongInteger()
    {
        var rule = new PolicyRule
        {
            Name = "test-numeric-eq-miss-int",
            Condition = "count == 6",
            Action = PolicyAction.Deny
        };

        var context = new Dictionary<string, object> { ["count"] = 5 };
        Assert.False(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_NumericEquality_DoesNotMatchWrongDecimal()
    {
        var rule = new PolicyRule
        {
            Name = "test-numeric-eq-miss-decimal",
            Condition = "score == 2.71",
            Action = PolicyAction.Deny
        };

        var context = new Dictionary<string, object> { ["score"] = 3.14 };
        Assert.False(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_NumericEquality_MissingField_ReturnsFalse()
    {
        var rule = new PolicyRule
        {
            Name = "test-numeric-eq-missing",
            Condition = "count == 5",
            Action = PolicyAction.Deny
        };

        var context = new Dictionary<string, object>();
        Assert.False(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_NumericEquality_StringFieldCannotParse_ReturnsFalse()
    {
        var rule = new PolicyRule
        {
            Name = "test-numeric-eq-unparseable",
            Condition = "count == 5",
            Action = PolicyAction.Deny
        };

        var context = new Dictionary<string, object> { ["count"] = "five" };
        Assert.False(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_NumericEquality_InsideAndCompound()
    {
        var rule = new PolicyRule
        {
            Name = "test-numeric-eq-compound-and",
            Condition = "count == 5 and risk < 0.5",
            Action = PolicyAction.Deny
        };

        var context = new Dictionary<string, object>
        {
            ["count"] = 5,
            ["risk"] = 0.3
        };
        Assert.True(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_NumericInequality_InsideOrCompound()
    {
        var rule = new PolicyRule
        {
            Name = "test-numeric-neq-compound-or",
            Condition = "count != 5 or count == 5",
            Action = PolicyAction.Deny
        };

        var context = new Dictionary<string, object> { ["count"] = 5 };
        Assert.True(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_NumericEquality_DotNotationResolves()
    {
        var rule = new PolicyRule
        {
            Name = "test-numeric-eq-dot",
            Condition = "data.count == 5",
            Action = PolicyAction.Deny
        };

        var context = new Dictionary<string, object>
        {
            ["data"] = new Dictionary<string, object> { ["count"] = 5 }
        };
        Assert.True(rule.Evaluate(context));
    }

    [Fact]
    public void Evaluate_OrderedComparison_StringLiteralDoesNotMatchNumericBranch()
    {
        var rule = new PolicyRule
        {
            Name = "test-ordered-string-literal",
            Condition = "count >= 'high'",
            Action = PolicyAction.Deny
        };

        var context = new Dictionary<string, object> { ["count"] = 5 };
        Assert.False(rule.Evaluate(context));
    }
}
