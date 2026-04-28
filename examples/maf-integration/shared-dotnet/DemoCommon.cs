// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using YamlDotNet.Serialization;

namespace MafIntegration.Shared;

public static class Display
{
    private static readonly bool Enabled =
        !Console.IsOutputRedirected || Environment.GetEnvironmentVariable("FORCE_COLOR") != null;

    private static string Esc(string code) => Enabled ? code : "";

    public static string Reset => Esc("\x1b[0m");
    public static string Bold => Esc("\x1b[1m");
    public static string Dim => Esc("\x1b[2m");
    public static string Red => Esc("\x1b[91m");
    public static string Green => Esc("\x1b[92m");
    public static string Yellow => Esc("\x1b[93m");
    public static string Blue => Esc("\x1b[94m");
    public static string Magenta => Esc("\x1b[95m");
    public static string Cyan => Esc("\x1b[96m");
    public static string White => Esc("\x1b[97m");

    public static void Header(string title, string subtitle)
    {
        const int width = 60;
        Console.WriteLine($"{Cyan}{Bold}╔{"".PadRight(width, '═')}╗{Reset}");
        Console.WriteLine($"{Cyan}{Bold}║  {White}{title.PadRight(width - 2)}{Cyan}║{Reset}");
        Console.WriteLine($"{Cyan}{Bold}║  {Dim}{White}{subtitle.PadRight(width - 2)}{Cyan}{Bold}║{Reset}");
        Console.WriteLine($"{Cyan}{Bold}╚{"".PadRight(width, '═')}╝{Reset}");
    }

    public static void Section(string title)
    {
        var pad = Math.Max(0, 56 - title.Length);
        Console.WriteLine($"\n{Yellow}{Bold}{"".PadRight(3, '━')} {title} {"".PadRight(pad, '━')}{Reset}\n");
    }

    public static void Request(string message) => Console.WriteLine($"  {Blue}📨 Request:{Reset} \"{message}\"");

    public static void Allowed(string detail) => Console.WriteLine($"  {Green}✅ ALLOWED{Reset} — {detail}");

    public static void Denied(string detail) => Console.WriteLine($"  {Red}❌ DENIED{Reset} — {detail}");

    public static void Policy(string ruleName) => Console.WriteLine($"  {Dim}📋 Governance rule: {ruleName}{Reset}");

    public static void ToolCall(string name, IEnumerable<KeyValuePair<string, object?>>? arguments)
    {
        var formattedArgs = arguments is not null && arguments.Any()
            ? string.Join(", ", arguments.Select(pair => $"{pair.Key}: {pair.Value}"))
            : "(no arguments)";
        Console.WriteLine($"  {Yellow}🛠 Tool Call:{Reset} {name}({formattedArgs})");
    }

    public static void ToolResult(string text, bool blocked)
    {
        var color = blocked ? Red : Green;
        var icon = blocked ? "❌" : "✅";
        Console.WriteLine($"  {color}{icon} Tool Result:{Reset} {text}");
    }

    public static void LlmResponse(string text) => Console.WriteLine($"  {Magenta}🤖 Agent:{Reset} {text}");
    public static void Info(string text) => Console.WriteLine($"  {Cyan}{text}{Reset}");
    public static void Warning(string text) => Console.WriteLine($"  {Yellow}{text}{Reset}");
    public static void DimLine(string text) => Console.WriteLine($"  {Dim}{text}{Reset}");
}

public record AnomalyScore(double ZScore, double Entropy, double CapabilityDeviation, bool IsAnomalous, bool Quarantine);

public sealed class RogueDetectionMiddleware
{
    private readonly int _windowSize;
    private readonly double _zThreshold;
    private readonly List<double> _callTimestamps = new();
    private readonly Dictionary<string, int> _toolCounts = new(StringComparer.OrdinalIgnoreCase);

    public RogueDetectionMiddleware(int windowSize = 20, double zThreshold = 2.5)
    {
        _windowSize = windowSize;
        _zThreshold = zThreshold;
    }

    public AnomalyScore RecordCall(string toolName)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;
        _callTimestamps.Add(now);
        _toolCounts[toolName] = _toolCounts.GetValueOrDefault(toolName) + 1;

        if (_callTimestamps.Count < 5)
        {
            return new AnomalyScore(0, 0, 0, false, false);
        }

        var recent = _callTimestamps.TakeLast(_windowSize).ToList();
        double zScore = 0;
        if (recent.Count >= 2)
        {
            var intervals = new List<double>();
            for (var index = 1; index < recent.Count; index++)
            {
                intervals.Add(recent[index] - recent[index - 1]);
            }

            var mean = intervals.Average();
            var standardDeviation = Math.Sqrt(intervals.Average(value => Math.Pow(value - mean, 2)));
            if (standardDeviation < 0.001)
            {
                standardDeviation = 0.001;
            }

            zScore = Math.Abs((intervals[^1] - mean) / standardDeviation);
        }

        var totalCalls = _toolCounts.Values.Sum();
        double entropy = 0;
        foreach (var count in _toolCounts.Values)
        {
            var probability = (double)count / totalCalls;
            if (probability > 0)
            {
                entropy -= probability * Math.Log2(probability);
            }
        }

        var maxCount = _toolCounts.Values.Max();
        var capabilityDeviation = (double)maxCount / totalCalls;

        var anomalous = zScore > _zThreshold || capabilityDeviation > 0.8;
        var quarantine = zScore > _zThreshold * 1.5 || (anomalous && capabilityDeviation > 0.85);

        return new AnomalyScore(
            Math.Round(zScore, 2),
            Math.Round(entropy, 3),
            Math.Round(capabilityDeviation, 3),
            anomalous,
            quarantine);
    }
}

public record AuditEntry(int Index, string Timestamp, string AgentId, string EventType, string Action, string Detail, string Hash, string PreviousHash);

public sealed class AuditTrail
{
    private readonly List<AuditEntry> _entries = new();
    private string _lastHash = new('0', 64);

    public IReadOnlyList<AuditEntry> Entries => _entries;

    public AuditEntry Log(string agentId, string eventType, string action, string detail)
    {
        var timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        var payload = $"{_entries.Count}|{timestamp}|{agentId}|{eventType}|{action}|{detail}|{_lastHash}";
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload))).ToLowerInvariant();
        var entry = new AuditEntry(_entries.Count, timestamp, agentId, eventType, action, detail, hash, _lastHash);
        _entries.Add(entry);
        _lastHash = hash;
        return entry;
    }

    public (bool IsValid, int VerifiedCount) VerifyIntegrity()
    {
        var previousHash = new string('0', 64);
        foreach (var entry in _entries)
        {
            var payload = $"{entry.Index}|{entry.Timestamp}|{entry.AgentId}|{entry.EventType}|{entry.Action}|{entry.Detail}|{previousHash}";
            var expected = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload))).ToLowerInvariant();
            if (!string.Equals(expected, entry.Hash, StringComparison.Ordinal))
            {
                return (false, entry.Index);
            }

            previousHash = entry.Hash;
        }

        return (true, _entries.Count);
    }
}

public record ToolCallPlan(string Prompt, string ToolName, Dictionary<string, object?> Arguments);

public sealed class DeterministicScenarioChatClient : IChatClient
{
    private readonly Dictionary<string, string> _directResponses;
    private readonly Dictionary<string, ToolCallPlan> _toolPlans;

    public DeterministicScenarioChatClient(
        IEnumerable<KeyValuePair<string, string>> directResponses,
        IEnumerable<ToolCallPlan> toolPlans)
    {
        _directResponses = new Dictionary<string, string>(directResponses, StringComparer.Ordinal);
        _toolPlans = toolPlans.ToDictionary(plan => plan.Prompt, StringComparer.Ordinal);
    }

    public Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var transcript = messages.ToList();
        var lastMessage = transcript.LastOrDefault();
        if (lastMessage is not null)
        {
            var toolResult = lastMessage.Contents.OfType<FunctionResultContent>().LastOrDefault();
            if (toolResult is not null)
            {
                var resultText = toolResult.Result?.ToString() ?? "Tool completed with no output.";
                return Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, resultText)));
            }
        }

        var prompt = transcript.LastOrDefault(message => message.Role == ChatRole.User)?.Text ?? string.Empty;
        if (_toolPlans.TryGetValue(prompt, out var plan))
        {
            var callId = Guid.NewGuid().ToString("N");
            var message = new ChatMessage(
                ChatRole.Assistant,
                [new FunctionCallContent(callId, plan.ToolName, plan.Arguments)]);
            return Task.FromResult(new ChatResponse(message));
        }

        if (_directResponses.TryGetValue(prompt, out var response))
        {
            return Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, response)));
        }

        return Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, "I can help within the scenario's governed operating boundaries.")));
    }

    public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var response = await GetResponseAsync(messages, options, cancellationToken).ConfigureAwait(false);
        foreach (var update in response.ToChatResponseUpdates())
        {
            yield return update;
        }
    }

    public object? GetService(Type serviceType, object? serviceKey = null)
        => serviceType.IsInstanceOfType(this) ? this : null;

    public void Dispose()
    {
    }
}

public sealed record PolicyDecision(bool Allowed, string RuleName, string Reason);

internal sealed class PolicyDocument
{
    public string DefaultAction { get; set; } = "allow";
    public List<PolicyRuleDocument> Rules { get; set; } = [];
}

internal sealed class PolicyRuleDocument
{
    public string Name { get; set; } = string.Empty;
    public string Condition { get; set; } = string.Empty;
    public string Action { get; set; } = "allow";
    public int Priority { get; set; }
}

public sealed class ExpressionPolicyEngine
{
    private static readonly Regex EqualityPattern =
        new(@"^(?<field>[a-zA-Z_][a-zA-Z0-9_]*)\s*==\s*'(?<value>.*)'$", RegexOptions.Compiled);

    private readonly string _defaultAction;
    private readonly IReadOnlyList<PolicyRuleDocument> _rules;

    public ExpressionPolicyEngine(string policyPath)
    {
        using var reader = File.OpenText(policyPath);
        var deserializer = new DeserializerBuilder()
            .IgnoreUnmatchedProperties()
            .Build();
        var document = deserializer.Deserialize<PolicyDocument>(reader) ?? new PolicyDocument();
        _defaultAction = document.DefaultAction;
        _rules = document.Rules.OrderByDescending(rule => rule.Priority).ToList();
    }

    public PolicyDecision EvaluateMessage(string message) => Evaluate("message", message);
    public PolicyDecision EvaluateTool(string toolName) => Evaluate("tool_name", toolName);

    private PolicyDecision Evaluate(string fieldName, string value)
    {
        foreach (var rule in _rules)
        {
            if (!Matches(rule.Condition, fieldName, value))
            {
                continue;
            }

            var allowed = !string.Equals(rule.Action, "deny", StringComparison.OrdinalIgnoreCase);
            var reason = allowed ? $"Allowed by {rule.Name}" : $"Blocked by governance policy: {rule.Name}";
            return new PolicyDecision(allowed, rule.Name, reason);
        }

        var defaultAllowed = !string.Equals(_defaultAction, "deny", StringComparison.OrdinalIgnoreCase);
        return new PolicyDecision(defaultAllowed, "default", defaultAllowed ? "Allowed by default policy" : "Blocked by default policy");
    }

    private static bool Matches(string condition, string expectedFieldName, string actualValue)
    {
        foreach (var orClause in Regex.Split(condition, @"\s+or\s+", RegexOptions.IgnoreCase))
        {
            var andMatched = true;
            foreach (var andClause in Regex.Split(orClause, @"\s+and\s+", RegexOptions.IgnoreCase))
            {
                var clause = andClause.Trim();
                var match = EqualityPattern.Match(clause);
                if (!match.Success)
                {
                    andMatched = false;
                    break;
                }

                var fieldName = match.Groups["field"].Value;
                var expectedValue = match.Groups["value"].Value.Replace("\\'", "'");
                if (!string.Equals(fieldName, expectedFieldName, StringComparison.Ordinal) ||
                    !string.Equals(expectedValue, actualValue, StringComparison.Ordinal))
                {
                    andMatched = false;
                    break;
                }
            }

            if (andMatched)
            {
                return true;
            }
        }

        return false;
    }
}

public sealed class NativeGovernanceMiddleware
{
    private readonly ExpressionPolicyEngine _policyEngine;
    private readonly AuditTrail _audit;
    private readonly string _agentId;

    public NativeGovernanceMiddleware(ExpressionPolicyEngine policyEngine, AuditTrail audit, string agentId)
    {
        _policyEngine = policyEngine;
        _audit = audit;
        _agentId = agentId;
    }

    public async Task<AgentResponse> RunAsync(
        IEnumerable<ChatMessage> messages,
        AgentSession? session,
        AgentRunOptions? options,
        AIAgent innerAgent,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(messages);
        ArgumentNullException.ThrowIfNull(innerAgent);

        var prompt = messages.LastOrDefault(message => message.Role == ChatRole.User)?.Text ?? string.Empty;
        var decision = _policyEngine.EvaluateMessage(prompt);
        _audit.Log(_agentId, "policy_check", decision.Allowed ? "allow" : "deny", prompt);

        if (!decision.Allowed)
        {
            return new AgentResponse(
            [
                new ChatMessage(ChatRole.Assistant, $"Blocked by governance policy: {decision.RuleName}")
            ]);
        }

        return await innerAgent.RunAsync(messages, session, options, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<object?> InvokeFunctionAsync(
        AIAgent agent,
        FunctionInvocationContext context,
        Func<FunctionInvocationContext, CancellationToken, ValueTask<object?>> next,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        var toolName = context.Function.Name;
        var decision = _policyEngine.EvaluateTool(toolName);
        _audit.Log(_agentId, "tool_policy", decision.Allowed ? "allow" : "deny", toolName);

        if (!decision.Allowed)
        {
            context.Terminate = true;
            return $"Blocked by governance policy: {decision.RuleName}";
        }

        return await next(context, cancellationToken).ConfigureAwait(false);
    }
}

public static class DemoCommon
{
    public static bool IsBlockedResponse(AgentResponse response) =>
        response.Text.Contains("Blocked by governance policy", StringComparison.OrdinalIgnoreCase) ||
        response.Messages.SelectMany(message => message.Contents)
            .OfType<FunctionResultContent>()
            .Any(content => content.Result?.ToString()?.Contains("Blocked by governance policy", StringComparison.OrdinalIgnoreCase) == true);

    public static void PrintResponseDetails(AgentResponse response, AuditTrail audit, string agentName, ref int allowedCount, ref int deniedCount)
    {
        var blocked = IsBlockedResponse(response);

        foreach (var functionCall in response.Messages.SelectMany(message => message.Contents).OfType<FunctionCallContent>())
        {
            Display.ToolCall(functionCall.Name, functionCall.Arguments);
        }

        foreach (var functionResult in response.Messages.SelectMany(message => message.Contents).OfType<FunctionResultContent>())
        {
            var resultText = functionResult.Result?.ToString() ?? "(no output)";
            Display.ToolResult(resultText, blocked);
        }

        var assistantText = response.Messages
            .Where(message => message.Role == ChatRole.Assistant)
            .Select(message => message.Text)
            .LastOrDefault(text => !string.IsNullOrWhiteSpace(text));

        if (!string.IsNullOrWhiteSpace(assistantText))
        {
            if (blocked)
            {
                Display.Denied(assistantText);
                deniedCount++;
                audit.Log(agentName, "tool_decision", "deny", assistantText);
            }
            else
            {
                Display.Allowed("Tool execution completed");
                Display.LlmResponse(assistantText);
                allowedCount++;
                audit.Log(agentName, "tool_decision", "allow", assistantText);
            }
        }
    }
}
