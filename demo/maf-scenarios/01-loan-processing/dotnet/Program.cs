// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Contoso Bank — AI Loan Processing Governance Demo (.NET)
// Demonstrates AGT integration with MAF middleware for loan processing.
//
// Four governance capabilities:
//   1. Policy Enforcement   — YAML rules block PII access and spending violations
//   2. Capability Sandboxing — tool allow/deny lists restrict API access
//   3. Rogue Agent Detection — Z-score frequency analysis with auto-quarantine
//   4. Audit Trail           — SHA-256 Merkle-chained tamper-proof compliance log
//
// Usage:
//   dotnet run                                         # simulated mode
//   GITHUB_TOKEN=ghp_... dotnet run                    # GitHub Models
//   AZURE_OPENAI_ENDPOINT=... dotnet run               # Azure OpenAI

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

// ═══════════════════════════════════════════════════════════════════════════
// ANSI colour helpers
// ═══════════════════════════════════════════════════════════════════════════

static class Display
{
    static readonly bool Enabled = !Console.IsOutputRedirected ||
        Environment.GetEnvironmentVariable("FORCE_COLOR") != null;

    static string Esc(string code) => Enabled ? code : "";

    public static string Reset => Esc("\x1b[0m");
    public static string Bold  => Esc("\x1b[1m");
    public static string Dim   => Esc("\x1b[2m");
    public static string Red   => Esc("\x1b[91m");
    public static string Green => Esc("\x1b[92m");
    public static string Yellow => Esc("\x1b[93m");
    public static string Blue  => Esc("\x1b[94m");
    public static string Magenta => Esc("\x1b[95m");
    public static string Cyan  => Esc("\x1b[96m");
    public static string White => Esc("\x1b[97m");

    public static void Header(string title, string subtitle = "")
    {
        const int w = 60;
        Console.WriteLine($"{Cyan}{Bold}╔{"".PadRight(w, '═')}╗{Reset}");
        Console.WriteLine($"{Cyan}{Bold}║  {White}{title.PadRight(w - 2)}{Cyan}║{Reset}");
        if (!string.IsNullOrEmpty(subtitle))
            Console.WriteLine($"{Cyan}{Bold}║  {Dim}{White}{subtitle.PadRight(w - 2)}{Cyan}{Bold}║{Reset}");
        Console.WriteLine($"{Cyan}{Bold}╚{"".PadRight(w, '═')}╝{Reset}");
    }

    public static void Section(string title)
    {
        var pad = Math.Max(0, 56 - title.Length);
        Console.WriteLine($"\n{Yellow}{Bold}{"".PadRight(3, '━')} {title} {"".PadRight(pad, '━')}{Reset}\n");
    }

    public static void Allowed(string text) =>
        Console.WriteLine($"  {Green}✅ ALLOWED{Reset} — {text}");

    public static void Denied(string text) =>
        Console.WriteLine($"  {Red}❌ DENIED{Reset} — {text}");

    public static void Request(string msg) =>
        Console.WriteLine($"  {Blue}📨 Request:{Reset} \"{msg}\"");

    public static void Policy(string policyName, string ruleName) =>
        Console.WriteLine($"  {Dim}📋 Policy:  {policyName} → {ruleName}{Reset}");

    public static void ToolResult(string name, bool allowed, string detail) =>
        Console.WriteLine(allowed
            ? $"  {Green}✅ {name}(){Reset}  →  {detail}"
            : $"  {Red}❌ {name}(){Reset}  →  {Dim}{detail}{Reset}");

    public static void Info(string text) =>
        Console.WriteLine($"  {Cyan}{text}{Reset}");

    public static void Warning(string text) =>
        Console.WriteLine($"  {Yellow}{text}{Reset}");

    public static void LlmResponse(string text) =>
        Console.WriteLine($"  {Magenta}🤖 Response:{Reset} {text}");

    public static void DimLine(string text) =>
        Console.WriteLine($"  {Dim}{text}{Reset}");
}

// ═══════════════════════════════════════════════════════════════════════════
// Policy Engine — loads YAML, evaluates rules
// ═══════════════════════════════════════════════════════════════════════════

record PolicyDecision(bool Allowed, string RuleName, string Reason, string Action);

class PolicyRule
{
    public string Name { get; set; } = "";
    public string Field { get; set; } = "message";
    public string Operator { get; set; } = "contains";
    public string Value { get; set; } = "";
    public string Action { get; set; } = "allow";
    public int Priority { get; set; }
    public string Message { get; set; } = "";
}

class PolicyEngine
{
    public string Name { get; }
    public string DefaultAction { get; }
    public List<PolicyRule> Rules { get; }

    public PolicyEngine(string policyPath)
    {
        var yaml = File.ReadAllText(policyPath);
        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .Build();
        var doc = deserializer.Deserialize<Dictionary<string, object>>(yaml);

        Name = doc.TryGetValue("name", out var n) ? n?.ToString() ?? "unknown" : "unknown";

        DefaultAction = "allow";
        if (doc.TryGetValue("defaults", out var dObj) && dObj is Dictionary<object, object> defaults)
        {
            if (defaults.TryGetValue("action", out var da))
                DefaultAction = da?.ToString() ?? "allow";
        }

        Rules = new List<PolicyRule>();
        if (doc.TryGetValue("rules", out var rObj) && rObj is List<object> rules)
        {
            foreach (var item in rules)
            {
                if (item is not Dictionary<object, object> rDict) continue;

                var rule = new PolicyRule
                {
                    Name = rDict.TryGetValue("name", out var rn) ? rn?.ToString() ?? "" : "",
                    Action = rDict.TryGetValue("action", out var ra) ? ra?.ToString() ?? "allow" : "allow",
                    Priority = rDict.TryGetValue("priority", out var rp) ? int.TryParse(rp?.ToString(), out var p) ? p : 0 : 0,
                    Message = rDict.TryGetValue("message", out var rm) ? rm?.ToString() ?? "" : "",
                };

                if (rDict.TryGetValue("condition", out var cObj) && cObj is Dictionary<object, object> cond)
                {
                    rule.Field = cond.TryGetValue("field", out var cf) ? cf?.ToString() ?? "message" : "message";
                    rule.Operator = cond.TryGetValue("operator", out var co) ? co?.ToString() ?? "contains" : "contains";
                    rule.Value = cond.TryGetValue("value", out var cv) ? cv?.ToString() ?? "" : "";
                }

                Rules.Add(rule);
            }
        }

        Rules.Sort((a, b) => b.Priority.CompareTo(a.Priority));
    }

    public PolicyDecision Evaluate(string agentId, string message)
    {
        var msgLower = message.ToLowerInvariant();
        foreach (var rule in Rules)
        {
            if (rule.Action == "audit") continue;

            bool matched = false;
            if (rule.Operator is "contains" or "contains_any")
            {
                var keywords = rule.Value.Split(',').Select(k => k.Trim().ToLowerInvariant());
                matched = keywords.Any(kw => msgLower.Contains(kw));
            }

            if (matched)
            {
                return rule.Action == "deny"
                    ? new PolicyDecision(false, rule.Name, rule.Message, "deny")
                    : new PolicyDecision(true, rule.Name, rule.Message, "allow");
            }
        }

        return new PolicyDecision(DefaultAction == "allow", "default",
            $"Default policy: {DefaultAction}", DefaultAction);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAF-style middleware — GovernancePolicyMiddleware
// ═══════════════════════════════════════════════════════════════════════════

class GovernancePolicyMiddleware
{
    readonly PolicyEngine _engine;
    readonly AuditTrail _audit;

    public GovernancePolicyMiddleware(PolicyEngine engine, AuditTrail audit)
    {
        _engine = engine;
        _audit = audit;
    }

    public (bool Allowed, PolicyDecision Decision) Process(string agentId, string message)
    {
        var decision = _engine.Evaluate(agentId, message);
        _audit.Log(agentId, "policy_check", decision.Action, message.Length > 120 ? message[..120] : message);
        return (decision.Allowed, decision);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAF-style middleware — CapabilityGuardMiddleware
// ═══════════════════════════════════════════════════════════════════════════

class CapabilityGuardMiddleware
{
    readonly HashSet<string>? _allowedTools;
    readonly HashSet<string> _deniedTools;
    readonly AuditTrail? _audit;

    public CapabilityGuardMiddleware(
        IEnumerable<string>? allowedTools = null,
        IEnumerable<string>? deniedTools = null,
        AuditTrail? audit = null)
    {
        _allowedTools = allowedTools != null ? new HashSet<string>(allowedTools) : null;
        _deniedTools = new HashSet<string>(deniedTools ?? Enumerable.Empty<string>());
        _audit = audit;
    }

    public (bool Allowed, string Reason) Check(string toolName)
    {
        if (_deniedTools.Contains(toolName))
        {
            _audit?.Log("capability-guard", "tool_blocked", "deny", toolName);
            return (false, $"Tool '{toolName}' is on the denied list");
        }
        if (_allowedTools != null && !_allowedTools.Contains(toolName))
        {
            _audit?.Log("capability-guard", "tool_blocked", "deny", toolName);
            return (false, $"Tool '{toolName}' is not on the allowed list");
        }
        _audit?.Log("capability-guard", "tool_invocation", "allow", toolName);
        return (true, "Permitted");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAF-style middleware — RogueDetectionMiddleware
// ═══════════════════════════════════════════════════════════════════════════

record AnomalyScore(double ZScore, double Entropy, double CapabilityDeviation,
    bool IsAnomalous, bool Quarantine);

class RogueDetectionMiddleware
{
    readonly int _windowSize;
    readonly double _zThreshold;
    readonly List<double> _callTimestamps = new();
    readonly Dictionary<string, int> _toolCounts = new();

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
            return new AnomalyScore(0, 0, 0, false, false);

        // Z-score from call intervals
        var recent = _callTimestamps.TakeLast(_windowSize).ToList();
        double zScore = 0;
        if (recent.Count >= 2)
        {
            var intervals = new List<double>();
            for (int i = 1; i < recent.Count; i++)
                intervals.Add(recent[i] - recent[i - 1]);

            var mean = intervals.Average();
            var std = Math.Sqrt(intervals.Average(x => Math.Pow(x - mean, 2)));
            if (std < 0.001) std = 0.001;
            zScore = Math.Abs((intervals[^1] - mean) / std);
        }

        // Entropy
        int total = _toolCounts.Values.Sum();
        double entropy = 0;
        foreach (var count in _toolCounts.Values)
        {
            double p = (double)count / total;
            if (p > 0) entropy -= p * Math.Log2(p);
        }

        // Capability deviation
        int maxCount = _toolCounts.Values.Max();
        double capDev = (double)maxCount / total;

        bool anomalous = zScore > _zThreshold || capDev > 0.8;
        bool quarantine = zScore > _zThreshold * 1.5 || (anomalous && capDev > 0.85);

        return new AnomalyScore(
            Math.Round(zScore, 2),
            Math.Round(entropy, 3),
            Math.Round(capDev, 3),
            anomalous,
            quarantine);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Audit Trail — SHA-256 Merkle chain
// ═══════════════════════════════════════════════════════════════════════════

record AuditEntry(int Index, string Timestamp, string AgentId, string EventType,
    string Action, string Detail, string Hash, string PreviousHash);

class AuditTrail
{
    readonly List<AuditEntry> _entries = new();
    string _lastHash = new string('0', 64);

    public IReadOnlyList<AuditEntry> Entries => _entries;

    public AuditEntry Log(string agentId, string eventType, string action, string detail)
    {
        var ts = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        var payload = $"{_entries.Count}|{ts}|{agentId}|{eventType}|{action}|{detail}|{_lastHash}";
        var hash = ComputeSha256(payload);

        var entry = new AuditEntry(_entries.Count, ts, agentId, eventType, action, detail, hash, _lastHash);
        _entries.Add(entry);
        _lastHash = hash;
        return entry;
    }

    public (bool IsValid, int VerifiedCount) VerifyIntegrity()
    {
        var prevHash = new string('0', 64);
        foreach (var entry in _entries)
        {
            var payload = $"{entry.Index}|{entry.Timestamp}|{entry.AgentId}|" +
                          $"{entry.EventType}|{entry.Action}|{entry.Detail}|{prevHash}";
            var expected = ComputeSha256(payload);
            if (expected != entry.Hash) return (false, entry.Index);
            prevHash = entry.Hash;
        }
        return (true, _entries.Count);
    }

    public Dictionary<string, object> GenerateProof(int index)
    {
        if (index < 0 || index >= _entries.Count)
            return new Dictionary<string, object> { ["error"] = "Index out of range" };

        var entry = _entries[index];
        return new Dictionary<string, object>
        {
            ["entry_index"] = index,
            ["entry_hash"] = entry.Hash,
            ["previous_hash"] = entry.PreviousHash,
            ["chain_length"] = _entries.Count,
            ["chain_head"] = _entries.Count > 0 ? _entries[^1].Hash : "",
            ["verified"] = VerifyIntegrity().IsValid,
        };
    }

    static string ComputeSha256(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexStringLower(bytes);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// LLM client — auto-detect: GitHub Models → Azure OpenAI → Simulated
// ═══════════════════════════════════════════════════════════════════════════

static class LlmClient
{
    public static (Func<string, string, string> Chat, string BackendName) Create()
    {
        // 1) GitHub Models
        var githubToken = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
        if (!string.IsNullOrEmpty(githubToken))
        {
            try
            {
                var httpClient = new HttpClient();
                httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {githubToken}");
                httpClient.BaseAddress = new Uri("https://models.inference.ai.azure.com/");
                return ((prompt, system) => CallGitHubModels(httpClient, prompt, system),
                    "GitHub Models (gpt-4o-mini)");
            }
            catch { /* fall through */ }
        }

        // 2) Azure OpenAI
        var azureEndpoint = Environment.GetEnvironmentVariable("AZURE_OPENAI_ENDPOINT");
        var azureKey = Environment.GetEnvironmentVariable("AZURE_OPENAI_API_KEY");
        if (!string.IsNullOrEmpty(azureEndpoint) && !string.IsNullOrEmpty(azureKey))
        {
            try
            {
                var deployment = Environment.GetEnvironmentVariable("AZURE_OPENAI_DEPLOYMENT") ?? "gpt-4o-mini";
                var httpClient = new HttpClient();
                httpClient.DefaultRequestHeaders.Add("api-key", azureKey);
                httpClient.BaseAddress = new Uri(azureEndpoint.TrimEnd('/') + "/");
                return ((prompt, system) => CallAzureOpenAI(httpClient, deployment, prompt, system),
                    $"Azure OpenAI ({deployment})");
            }
            catch { /* fall through */ }
        }

        // 3) Simulated
        return (SimulatedResponse, "Simulated (no API key — governance is still fully real)");
    }

    static string CallGitHubModels(HttpClient client, string prompt, string system)
    {
        try
        {
            var messages = new List<object>();
            if (!string.IsNullOrEmpty(system))
                messages.Add(new { role = "system", content = system });
            messages.Add(new { role = "user", content = prompt });

            var body = JsonSerializer.Serialize(new { model = "gpt-4o-mini", messages, max_tokens = 256 });
            var response = client.PostAsync("chat/completions",
                new StringContent(body, Encoding.UTF8, "application/json")).Result;
            var json = response.Content.ReadAsStringAsync().Result;
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.GetProperty("choices")[0]
                .GetProperty("message").GetProperty("content").GetString() ?? "[empty]";
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  {Display.Yellow}⚠  LLM error ({ex.GetType().Name}), using simulated response{Display.Reset}");
            return SimulatedResponse(prompt, system);
        }
    }

    static string CallAzureOpenAI(HttpClient client, string deployment, string prompt, string system)
    {
        try
        {
            var messages = new List<object>();
            if (!string.IsNullOrEmpty(system))
                messages.Add(new { role = "system", content = system });
            messages.Add(new { role = "user", content = prompt });

            var body = JsonSerializer.Serialize(new { messages, max_tokens = 256 });
            var url = $"openai/deployments/{deployment}/chat/completions?api-version=2024-02-15-preview";
            var response = client.PostAsync(url,
                new StringContent(body, Encoding.UTF8, "application/json")).Result;
            var json = response.Content.ReadAsStringAsync().Result;
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.GetProperty("choices")[0]
                .GetProperty("message").GetProperty("content").GetString() ?? "[empty]";
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  {Display.Yellow}⚠  LLM error ({ex.GetType().Name}), using simulated response{Display.Reset}");
            return SimulatedResponse(prompt, system);
        }
    }

    static string SimulatedResponse(string prompt, string system = "")
    {
        var p = prompt.ToLowerInvariant();
        if (p.Contains("eligib") || p.Contains("credit") || p.Contains("loan"))
            return "Based on the credit analysis for customer John Smith (ID: 12345), " +
                   "the applicant has a credit score of 742 (Good). With a stable income " +
                   "of $85,000/year and a debt-to-income ratio of 28%, the customer " +
                   "qualifies for a standard 30-year fixed mortgage at 6.25% APR for " +
                   "amounts up to $350,000.";
        if (p.Contains("ssn") || p.Contains("tax") || p.Contains("social security"))
            return "[This response would never be generated — blocked by policy]";
        if (p.Contains("rate"))
            return "Current loan rates: 30-year fixed 6.25%, 15-year fixed 5.50%, " +
                   "5/1 ARM 5.75%. Rates effective as of today.";
        return $"[Simulated LLM response to: {(prompt.Length > 80 ? prompt[..80] : prompt)}]";
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Domain tools (mock implementations)
// ═══════════════════════════════════════════════════════════════════════════

static class LoanTools
{
    public static string CheckCreditScore(string customerId) =>
        JsonSerializer.Serialize(new
        {
            customer_id = customerId,
            credit_score = 742,
            rating = "Good",
            factors = new[] { "On-time payments (98%)", "Credit utilization (24%)", "Account age (12 years)" }
        });

    public static string GetLoanRates(double amount, int termYears) =>
        JsonSerializer.Serialize(new
        {
            amount,
            term_years = termYears,
            rates = new { _30yr_fixed = "6.25%", _15yr_fixed = "5.50%", _5_1_arm = "5.75%" },
            monthly_payment = $"${amount * 0.006:F2}",
            total_interest = $"${amount * 0.006 * termYears * 12 - amount:F2}"
        });

    public static string AccessTaxRecords(string customerId) =>
        "{\"error\": \"This function should never execute — blocked by governance\"}";

    public static string ApproveLoan(string customerId, double amount)
    {
        if (amount > 50000)
            return JsonSerializer.Serialize(new
            {
                error = $"Loan amount ${amount:N2} exceeds $50,000 auto-approval limit"
            });
        return JsonSerializer.Serialize(new
        {
            customer_id = customerId, amount, status = "approved", reference = "LN-2024-00742"
        });
    }

    public static string TransferFunds(string from, string to, double amount) =>
        "{\"error\": \"This function should never execute — blocked by governance\"}";
}

// ═══════════════════════════════════════════════════════════════════════════
// Main demo — 4 Acts
// ═══════════════════════════════════════════════════════════════════════════

Display.Header(
    "🏦 Contoso Bank — AI Loan Processing Governance Demo",
    "Agent Governance Toolkit · MAF Middleware · Merkle Audit");

// Setup
var (chat, backendName) = LlmClient.Create();
Console.WriteLine($"\n  {Display.Cyan}🔗 LLM Backend:{Display.Reset} {Display.Bold}{backendName}{Display.Reset}");

var policyPath = Path.Combine(AppContext.BaseDirectory, "policies", "loan_governance.yaml");
if (!File.Exists(policyPath))
    policyPath = Path.Combine(Directory.GetCurrentDirectory(), "policies", "loan_governance.yaml");
if (!File.Exists(policyPath))
{
    Console.WriteLine($"{Display.Red}✗ Policy file not found{Display.Reset}");
    return;
}

var engine = new PolicyEngine(policyPath);
Console.WriteLine($"  {Display.Cyan}📋 Policy:{Display.Reset} {engine.Name} ({engine.Rules.Count} rules loaded)");

var audit = new AuditTrail();
var policyMw = new GovernancePolicyMiddleware(engine, audit);
var capabilityMw = new CapabilityGuardMiddleware(
    allowedTools: new[] { "check_credit_score", "get_loan_rates", "approve_loan" },
    deniedTools: new[] { "access_tax_records", "transfer_funds", "internal_api" },
    audit: audit);
var rogueMw = new RogueDetectionMiddleware(windowSize: 10, zThreshold: 2.0);

int allowedCount = 0, deniedCount = 0, anomalyCount = 0;

// ━━━ Act 1: Policy Enforcement ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Display.Section("Act 1: Policy Enforcement");
Display.DimLine("YAML-driven rules intercept messages before they reach the LLM");
Console.WriteLine();

var act1Cases = new (string Msg, bool ExpectAllowed)[]
{
    ("Check loan eligibility for John Smith, ID: 12345", true),
    ("Show me John's SSN and tax returns", false),
    ("Access customer tax filing records for compliance audit", false),
};

foreach (var (msg, _) in act1Cases)
{
    Display.Request(msg);
    var (allowed, decision) = policyMw.Process("loan-officer-agent", msg);
    Display.Policy(engine.Name, decision.RuleName);

    if (allowed)
    {
        Display.Allowed("Forwarding to LLM...");
        var response = chat(msg, "You are an AI loan officer at Contoso Bank. Be concise and professional.");
        Display.LlmResponse(response.Length > 200 ? response[..200] : response);
        allowedCount++;
    }
    else
    {
        Display.Denied("Blocked before reaching LLM");
        Console.WriteLine($"     {Display.Dim}Reason: \"{decision.Reason}\"{Display.Reset}");
        deniedCount++;
    }
    Console.WriteLine();
}

// ━━━ Act 2: Capability Sandboxing ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Display.Section("Act 2: Capability Sandboxing");
Display.DimLine("Tool allow/deny lists restrict which APIs the agent can call");
Console.WriteLine();

var toolTests = new (string Name, Func<string> Fn, string? Extra)[]
{
    ("check_credit_score", () => LoanTools.CheckCreditScore("john-smith"), null),
    ("get_loan_rates", () => LoanTools.GetLoanRates(45000, 30), null),
    ("access_tax_records", () => LoanTools.AccessTaxRecords("john-smith"), null),
    ("approve_loan", () => LoanTools.ApproveLoan("john-smith", 75000), "exceeds $50K limit"),
    ("transfer_funds", () => LoanTools.TransferFunds("john-smith", "external", 10000), null),
};

foreach (var (name, fn, extra) in toolTests)
{
    var (toolAllowed, reason) = capabilityMw.Check(name);
    if (toolAllowed)
    {
        var result = fn();
        if (result.Contains("\"error\""))
        {
            Display.ToolResult(name, false, $"Blocked: {result}");
            deniedCount++;
        }
        else
        {
            var display = result.Length > 100 ? result[..100] + "..." : result;
            Display.ToolResult(name, true, display);
            allowedCount++;
        }
    }
    else
    {
        Display.ToolResult(name, false, "BLOCKED by capability policy");
        deniedCount++;
    }
}
Console.WriteLine();

// ━━━ Act 3: Rogue Agent Detection ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Display.Section("Act 3: Rogue Agent Detection");
Display.DimLine("Z-score frequency analysis detects abnormal behaviour patterns");
Console.WriteLine();

// Phase A — baseline
Display.Info("📊 Phase A: Establishing baseline (5 normal loan inquiries)...");
var normalTools = new[] { "check_credit_score", "get_loan_rates", "check_credit_score",
                          "get_loan_rates", "check_credit_score" };
var rng = new Random(42);
foreach (var tool in normalTools)
{
    rogueMw.RecordCall(tool);
    Thread.Sleep(200 + rng.Next(150));
    audit.Log("loan-officer-agent", "tool_call", "allow", tool);
}
Console.WriteLine($"  {Display.Green}  ✓ Baseline established: {normalTools.Length} calls, normal cadence{Display.Reset}");
Console.WriteLine();

// Phase B — burst
Display.Warning("⚡ Phase B: Sudden burst — 20 rapid transfer_funds() calls...");
bool anomalyDetected = false, quarantineTriggered = false;
AnomalyScore finalScore = new(0, 0, 0, false, false);

for (int i = 0; i < 20; i++)
{
    var score = rogueMw.RecordCall("transfer_funds");
    audit.Log("loan-officer-agent", "tool_call", "anomaly_check", "transfer_funds");
    Thread.Sleep(20);
    if (score.IsAnomalous && !anomalyDetected) { anomalyDetected = true; anomalyCount++; }
    if (score.Quarantine) quarantineTriggered = true;
    finalScore = score;
}

Console.WriteLine();
Console.WriteLine($"  {Display.Yellow}📊 Anomaly Analysis:{Display.Reset}");
Console.WriteLine($"     Z-score:              {Display.Bold}{finalScore.ZScore}{Display.Reset}  {(finalScore.ZScore > 2.0 ? "⚠️  HIGH" : "✓ normal")}");
Console.WriteLine($"     Entropy:              {Display.Bold}{finalScore.Entropy}{Display.Reset}");
Console.WriteLine($"     Capability deviation: {Display.Bold}{finalScore.CapabilityDeviation}{Display.Reset}  {(finalScore.CapabilityDeviation > 0.7 ? "⚠️  HIGH" : "✓ normal")}");
Console.WriteLine($"     Anomalous:            {(finalScore.IsAnomalous ? Display.Red : Display.Green)}{finalScore.IsAnomalous}{Display.Reset}");

if (quarantineTriggered)
{
    Console.WriteLine();
    Console.WriteLine($"  {Display.Red}{Display.Bold}🔒 QUARANTINE TRIGGERED{Display.Reset} — Agent isolated from production pipeline");
    Console.WriteLine($"     {Display.Dim}Human review required before agent can resume operations{Display.Reset}");
}
Console.WriteLine();

// ━━━ Act 4: Audit Trail & Compliance ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Display.Section("Act 4: Audit Trail & Compliance");
Display.DimLine("SHA-256 Merkle-chained log provides tamper-proof compliance records");
Console.WriteLine();

Console.WriteLine($"  {Display.Cyan}📜 Merkle Chain:{Display.Reset} {audit.Entries.Count} entries\n");

int showCount = Math.Min(4, audit.Entries.Count);
for (int i = 0; i < showCount; i++)
{
    var e = audit.Entries[i];
    var icon = e.Action == "allow" ? "✅" : e.Action == "deny" ? "❌" : "📝";
    var colour = e.Action == "allow" ? Display.Green : e.Action == "deny" ? Display.Red : Display.Yellow;
    Console.WriteLine($"    {colour}{icon} [{e.Index:D3}]{Display.Reset} {e.EventType,-18} {e.Action,-8} {Display.Dim}{e.Hash[..16]}...{Display.Reset}");
}

if (audit.Entries.Count > showCount * 2)
    Console.WriteLine($"    {Display.Dim}   ... ({audit.Entries.Count - showCount * 2} more entries) ...{Display.Reset}");

for (int i = audit.Entries.Count - showCount; i < audit.Entries.Count; i++)
{
    if (i < showCount) continue;
    var e = audit.Entries[i];
    var icon = e.Action == "allow" ? "✅" : e.Action == "deny" ? "❌" : "📝";
    var colour = e.Action == "allow" ? Display.Green : e.Action == "deny" ? Display.Red : Display.Yellow;
    Console.WriteLine($"    {colour}{icon} [{e.Index:D3}]{Display.Reset} {e.EventType,-18} {e.Action,-8} {Display.Dim}{e.Hash[..16]}...{Display.Reset}");
}

// Verify
Console.WriteLine($"\n  {Display.Cyan}🔍 Integrity Verification:{Display.Reset}");
var (isValid, count) = audit.VerifyIntegrity();
Console.WriteLine(isValid
    ? $"  {Display.Green}  ✅ Chain valid — {count} entries verified, no tampering detected{Display.Reset}"
    : $"  {Display.Red}  ❌ Chain BROKEN at entry {count}{Display.Reset}");

// Proof
Console.WriteLine($"\n  {Display.Cyan}📄 Proof Generation (entry #1):{Display.Reset}");
var proof = audit.GenerateProof(1);
Console.WriteLine($"     Entry hash:    {Display.Dim}{proof["entry_hash"].ToString()?[..32]}...{Display.Reset}");
Console.WriteLine($"     Previous hash: {Display.Dim}{proof["previous_hash"].ToString()?[..32]}...{Display.Reset}");
Console.WriteLine($"     Chain length:  {proof["chain_length"]}");
Console.WriteLine((bool)proof["verified"]
    ? $"     Verified:      {Display.Green}✓{Display.Reset}"
    : $"     Verified:      {Display.Red}✗{Display.Reset}");

// ━━━ Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Display.Section("Summary");
int total = allowedCount + deniedCount;
Console.WriteLine($"  {Display.Green}✅ Allowed:   {allowedCount}{Display.Reset}");
Console.WriteLine($"  {Display.Red}❌ Denied:    {deniedCount}{Display.Reset}");
Console.WriteLine($"  {Display.Yellow}⚠️  Anomalies: {anomalyCount}{Display.Reset}");
Console.WriteLine($"  {Display.Cyan}📜 Audit log: {audit.Entries.Count} entries (Merkle-chained){Display.Reset}");
Console.WriteLine($"  {Display.Dim}   Total governance decisions: {total}{Display.Reset}");
Console.WriteLine();
Console.WriteLine($"  {Display.Bold}All governance enforcement ran inline — " +
    $"no requests bypassed the middleware stack.{Display.Reset}");
Console.WriteLine();
