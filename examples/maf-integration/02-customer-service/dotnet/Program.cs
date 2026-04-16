// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Contoso Support — Customer Service Governance Demo (.NET)
// Demonstrates AGT integration with MAF middleware for customer service.
//
// Four governance layers are exercised end-to-end:
//   1. Policy Enforcement   — YAML rules intercept support requests
//   2. Capability Sandboxing — tool allow/deny lists for support tools
//   3. Rogue Agent Detection — refund-farming anomaly detection
//   4. Audit Trail           — Merkle-chained tamper-proof logging
//
// Usage:
//   dotnet run                                        # Simulated LLM
//   GITHUB_TOKEN=ghp_... dotnet run                   # GitHub Models

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

// ═══════════════════════════════════════════════════════════════════════════
// ANSI colour helpers
// ═══════════════════════════════════════════════════════════════════════════

static class C
{
    private static readonly bool Enabled =
        !Console.IsOutputRedirected || Environment.GetEnvironmentVariable("FORCE_COLOR") != null;

    public static string Reset => Enabled ? "\x1b[0m" : "";
    public static string Bold => Enabled ? "\x1b[1m" : "";
    public static string Dim => Enabled ? "\x1b[2m" : "";
    public static string Red => Enabled ? "\x1b[91m" : "";
    public static string Green => Enabled ? "\x1b[92m" : "";
    public static string Yellow => Enabled ? "\x1b[93m" : "";
    public static string Blue => Enabled ? "\x1b[94m" : "";
    public static string Magenta => Enabled ? "\x1b[95m" : "";
    public static string Cyan => Enabled ? "\x1b[96m" : "";
    public static string White => Enabled ? "\x1b[97m" : "";
}

// ═══════════════════════════════════════════════════════════════════════════
// Display helpers
// ═══════════════════════════════════════════════════════════════════════════

static void PrintHeader()
{
    var w = 64;
    var h = new string('═', w);
    Console.WriteLine();
    Console.WriteLine($"{C.Cyan}{C.Bold}╔{h}╗{C.Reset}");
    Console.WriteLine($"{C.Cyan}{C.Bold}║  {C.White}🎧 Contoso Support — Customer Service Governance Demo{new string(' ', 6)}{C.Cyan}║{C.Reset}");
    Console.WriteLine($"{C.Cyan}{C.Bold}║  {C.Dim}{C.White}Agent Governance Toolkit · MAF Middleware · Merkle Audit{new string(' ', 4)}{C.Cyan}{C.Bold}║{C.Reset}");
    Console.WriteLine($"{C.Cyan}{C.Bold}╚{h}╝{C.Reset}");
    Console.WriteLine();
}

static void PrintSection(string title)
{
    var dashes = new string('━', Math.Max(1, 60 - title.Length));
    Console.WriteLine($"\n{C.Yellow}{C.Bold}━━━ {title} {dashes}{C.Reset}\n");
}

static void PrintResult(string icon, string color, string label, string detail)
{
    Console.WriteLine($"  {color}{icon} {label}:{C.Reset} {detail}");
}

static void PrintBox(string title, string[] lines)
{
    var w = Math.Min(66, Math.Max(title.Length + 4, lines.Max(l => l.Length) + 4));
    Console.WriteLine($"  {C.Dim}┌{new string('─', w)}┐{C.Reset}");
    Console.WriteLine($"  {C.Dim}│{C.Reset} {C.Bold}{title}{new string(' ', Math.Max(0, w - title.Length - 2))}{C.Dim}│{C.Reset}");
    Console.WriteLine($"  {C.Dim}├{new string('─', w)}┤{C.Reset}");
    foreach (var line in lines)
    {
        var padded = line.Length > w - 2 ? line[..(w - 2)] : line + new string(' ', w - 2 - line.Length);
        Console.WriteLine($"  {C.Dim}│{C.Reset} {padded}{C.Dim}│{C.Reset}");
    }
    Console.WriteLine($"  {C.Dim}└{new string('─', w)}┘{C.Reset}");
}

// ═══════════════════════════════════════════════════════════════════════════
// LLM Client — auto-detection hierarchy
// ═══════════════════════════════════════════════════════════════════════════

static (Func<string, string, string>? caller, string backend) CreateLlmClient()
{
    var githubToken = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
    if (!string.IsNullOrEmpty(githubToken))
    {
        return (CallGitHubModels(githubToken), "GitHub Models (gpt-4o-mini)");
    }

    var azureEndpoint = Environment.GetEnvironmentVariable("AZURE_OPENAI_ENDPOINT");
    var azureKey = Environment.GetEnvironmentVariable("AZURE_OPENAI_API_KEY");
    if (!string.IsNullOrEmpty(azureEndpoint) && !string.IsNullOrEmpty(azureKey))
    {
        var deployment = Environment.GetEnvironmentVariable("AZURE_OPENAI_DEPLOYMENT") ?? "gpt-4o-mini";
        return (CallAzureOpenAI(azureEndpoint, azureKey, deployment), $"Azure OpenAI ({deployment})");
    }

    return (null, "Simulated (no API key — fully offline)");
}

static Func<string, string, string> CallGitHubModels(string token)
{
    return (prompt, system) =>
    {
        try
        {
            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
            var payload = new
            {
                model = "gpt-4o-mini",
                messages = new object[]
                {
                    new { role = "system", content = system },
                    new { role = "user", content = prompt }
                },
                max_tokens = 200
            };
            var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            var response = httpClient.PostAsync("https://models.inference.ai.azure.com/chat/completions", content).Result;
            var json = response.Content.ReadAsStringAsync().Result;
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.GetProperty("choices")[0].GetProperty("message").GetProperty("content").GetString() ?? SimulatedLlm(prompt);
        }
        catch
        {
            return SimulatedLlm(prompt);
        }
    };
}

static Func<string, string, string> CallAzureOpenAI(string endpoint, string key, string deployment)
{
    return (prompt, system) =>
    {
        try
        {
            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Add("api-key", key);
            var payload = new
            {
                messages = new object[]
                {
                    new { role = "system", content = system },
                    new { role = "user", content = prompt }
                },
                max_tokens = 200
            };
            var url = $"{endpoint.TrimEnd('/')}/openai/deployments/{deployment}/chat/completions?api-version=2024-02-15-preview";
            var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            var response = httpClient.PostAsync(url, content).Result;
            var json = response.Content.ReadAsStringAsync().Result;
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.GetProperty("choices")[0].GetProperty("message").GetProperty("content").GetString() ?? SimulatedLlm(prompt);
        }
        catch
        {
            return SimulatedLlm(prompt);
        }
    };
}

static string CallLlm(Func<string, string, string>? caller, string prompt, string system = "")
{
    if (caller == null) return SimulatedLlm(prompt);
    try { return caller(prompt, system); }
    catch { return SimulatedLlm(prompt); }
}

static string SimulatedLlm(string prompt)
{
    var p = prompt.ToLowerInvariant();
    if (p.Contains("refund") && prompt.Contains("$150"))
        return "I'll process the $150 refund for order #789 right away. The refund will be credited to your original payment method within 3-5 business days.";
    if (p.Contains("refund") && (prompt.Contains("$2,000") || prompt.Contains("$2000")))
        return "I understand you're requesting a $2,000 refund. This amount exceeds our standard limit and requires manager approval.";
    if (p.Contains("order") && p.Contains("status"))
        return "Order #789 was placed on 2024-01-15. Current status: Delivered on 2024-01-18 via Express Shipping.";
    if (p.Contains("credit card") || p.Contains("card number") || p.Contains("cvv"))
        return "I can help verify your identity through our secure portal instead.";
    if (p.Contains("escalat") || p.Contains("manager"))
        return "I'll escalate this to a manager right away. A supervisor will contact you within 2 hours.";
    if (p.Contains("lookup") || p.Contains("order"))
        return "I found order #789: Wireless Headphones ($149.99), ordered 2024-01-15, delivered 2024-01-18.";
    return "Thank you for contacting Contoso Support. How can I help you today?";
}

// ═══════════════════════════════════════════════════════════════════════════
// Policy Engine (inline)
// ═══════════════════════════════════════════════════════════════════════════

record PolicyDecision(bool Allowed, string RuleName, string Reason);

class PolicyRule
{
    public string Name { get; set; } = "";
    public string Field { get; set; } = "";
    public string Operator { get; set; } = "";
    public string Value { get; set; } = "";
    public string Action { get; set; } = "allow";
    public int Priority { get; set; } = 50;
    public string Message { get; set; } = "";
}

class PolicyEngine
{
    private readonly List<PolicyRule> _rules = new();
    private readonly string _defaultAction;

    public PolicyEngine(List<PolicyRule> rules, string defaultAction = "allow")
    {
        _rules = rules.OrderByDescending(r => r.Priority).ToList();
        _defaultAction = defaultAction;
    }

    public static PolicyEngine FromYaml(string path)
    {
        var yaml = File.ReadAllText(path);
        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .Build();
        var doc = deserializer.Deserialize<Dictionary<string, object>>(yaml);

        var defaultAction = "allow";
        if (doc.ContainsKey("defaults") && doc["defaults"] is Dictionary<object, object> defaults
            && defaults.ContainsKey("action"))
        {
            defaultAction = defaults["action"]?.ToString() ?? "allow";
        }

        var rules = new List<PolicyRule>();
        if (doc.ContainsKey("rules") && doc["rules"] is List<object> rulesList)
        {
            foreach (var ruleObj in rulesList)
            {
                if (ruleObj is not Dictionary<object, object> ruleDict) continue;
                var cond = ruleDict.ContainsKey("condition") ? ruleDict["condition"] as Dictionary<object, object> : null;
                if (cond == null) continue;

                rules.Add(new PolicyRule
                {
                    Name = ruleDict.GetValueOrDefault("name")?.ToString() ?? "",
                    Field = cond.GetValueOrDefault("field")?.ToString() ?? "",
                    Operator = cond.GetValueOrDefault("operator")?.ToString() ?? "",
                    Value = cond.GetValueOrDefault("value")?.ToString() ?? "",
                    Action = ruleDict.GetValueOrDefault("action")?.ToString() ?? "allow",
                    Priority = int.TryParse(ruleDict.GetValueOrDefault("priority")?.ToString(), out var p) ? p : 50,
                    Message = ruleDict.GetValueOrDefault("message")?.ToString() ?? "",
                });
            }
        }

        return new PolicyEngine(rules, defaultAction);
    }

    public PolicyDecision Evaluate(string message)
    {
        var msgLower = message.ToLowerInvariant();

        foreach (var rule in _rules)
        {
            bool matched = rule.Operator switch
            {
                "contains" => msgLower.Contains(rule.Value.ToLowerInvariant()),
                "contains_any" => rule.Value.Split(',').Select(k => k.Trim().ToLowerInvariant()).Any(k => msgLower.Contains(k)),
                "regex" => Regex.IsMatch(message, rule.Value, RegexOptions.IgnoreCase),
                _ => false
            };

            if (matched)
                return new PolicyDecision(rule.Action == "allow", rule.Name, rule.Message);
        }

        return new PolicyDecision(_defaultAction == "allow", "default", "Default policy applied");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAF-style Middleware (inline)
// ═══════════════════════════════════════════════════════════════════════════

class CapabilityGuard
{
    private readonly HashSet<string> _allowed;
    private readonly HashSet<string> _denied;

    public CapabilityGuard(string[] allowed, string[] denied)
    {
        _allowed = new HashSet<string>(allowed);
        _denied = new HashSet<string>(denied);
    }

    public (bool Allowed, string Reason) CheckTool(string toolName)
    {
        if (_denied.Contains(toolName))
            return (false, $"Tool '{toolName}' is in the denied list");
        if (_allowed.Count > 0 && !_allowed.Contains(toolName))
            return (false, $"Tool '{toolName}' is not in the allowed list");
        return (true, $"Tool '{toolName}' is permitted");
    }
}

record AnomalyScore(double ZScore, double Entropy, double CapabilityDeviation, bool IsAnomalous, string Reason);

class RogueDetector
{
    private readonly int _windowSize;
    private readonly double _zThreshold;
    private readonly List<(string Action, string Tool, double Amount, DateTime Ts)> _history = new();
    public bool Quarantined { get; private set; }

    public RogueDetector(int windowSize = 20, double zThreshold = 2.0)
    {
        _windowSize = windowSize;
        _zThreshold = zThreshold;
    }

    public AnomalyScore RecordAction(string action, string tool = "", double amount = 0)
    {
        _history.Add((action, tool, amount, DateTime.UtcNow));

        if (_history.Count < 5)
            return new AnomalyScore(0, 1, 0, false, "");

        var recent = _history.TakeLast(_windowSize).ToList();
        var toolCounts = recent.GroupBy(h => h.Tool).ToDictionary(g => g.Key, g => g.Count());
        var counts = toolCounts.Values.ToList();

        if (counts.Count < 2)
            return new AnomalyScore(0, 1, 0, false, "");

        var mean = counts.Average();
        var stdev = Math.Sqrt(counts.Sum(c => Math.Pow(c - mean, 2)) / (counts.Count - 1));
        var maxCount = counts.Max();
        var zScore = stdev > 0 ? (maxCount - mean) / stdev : 0;

        // Shannon entropy
        var total = (double)counts.Sum();
        var entropy = 0.0;
        foreach (var c in counts)
        {
            if (c > 0)
            {
                var p = c / total;
                entropy -= p * Math.Log2(p);
            }
        }

        var capDev = total > 0 ? maxCount / total : 0;
        var isAnomalous = zScore > _zThreshold || (capDev > 0.70 && recent.Count > 10);

        if (isAnomalous) Quarantined = true;

        return new AnomalyScore(
            Math.Round(zScore, 2),
            Math.Round(entropy, 2),
            Math.Round(capDev, 2),
            isAnomalous,
            isAnomalous ? "Refund-farming pattern detected" : "");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Merkle-Chained Audit Trail
// ═══════════════════════════════════════════════════════════════════════════

class AuditEntry
{
    public int Index { get; set; }
    public string Timestamp { get; set; } = "";
    public string EventType { get; set; } = "";
    public string Detail { get; set; } = "";
    public string PrevHash { get; set; } = "";
    public string EntryHash { get; set; } = "";

    public AuditEntry(int index, string eventType, string detail, string prevHash)
    {
        Index = index;
        Timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        EventType = eventType;
        Detail = detail;
        PrevHash = prevHash;
        EntryHash = ComputeHash();
    }

    public string ComputeHash()
    {
        var payload = $"{Index}|{Timestamp}|{EventType}|{Detail}|{PrevHash}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(payload));
        return Convert.ToHexStringLower(hash);
    }
}

class AuditTrail
{
    public List<AuditEntry> Entries { get; } = new();

    public AuditTrail()
    {
        Entries.Add(new AuditEntry(0, "GENESIS", "Audit chain initialized", new string('0', 64)));
    }

    public AuditEntry Log(string eventType, string detail)
    {
        var entry = new AuditEntry(Entries.Count, eventType, detail, Entries[^1].EntryHash);
        Entries.Add(entry);
        return entry;
    }

    public (bool Valid, int Checked) VerifyIntegrity()
    {
        for (int i = 1; i < Entries.Count; i++)
        {
            if (Entries[i].PrevHash != Entries[i - 1].EntryHash) return (false, i);
            if (Entries[i].ComputeHash() != Entries[i].EntryHash) return (false, i);
        }
        return (true, Entries.Count);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Domain-Specific Tools (mock implementations)
// ═══════════════════════════════════════════════════════════════════════════

static Dictionary<string, object> LookupOrder(string orderId) => orderId switch
{
    "ORD-789" => new() { ["order_id"] = "ORD-789", ["item"] = "Wireless Headphones (Contoso Pro X)", ["price"] = 149.99, ["date"] = "2024-01-15", ["status"] = "Delivered" },
    "ORD-456" => new() { ["order_id"] = "ORD-456", ["item"] = "Premium Laptop Stand Bundle", ["price"] = 2199.99, ["date"] = "2024-01-10", ["status"] = "Delivered" },
    _ => new() { ["error"] = $"Order {orderId} not found" }
};

static Dictionary<string, object> LookupCustomer(string customerId) => customerId switch
{
    "CUST-123" => new() { ["customer_id"] = "CUST-123", ["name"] = "Alex Johnson", ["email"] = "alex.j@example.com", ["member_since"] = "2021-03-15", ["tier"] = "Gold" },
    _ => new() { ["error"] = $"Customer {customerId} not found" }
};

static Dictionary<string, object> ProcessRefund(string orderId, double amount) =>
    amount > 500
        ? new() { ["status"] = "BLOCKED", ["reason"] = "Refund exceeds $500 limit — manager approval required" }
        : new() { ["status"] = "APPROVED", ["order_id"] = orderId, ["amount"] = amount, ["refund_id"] = $"REF-{Math.Abs(orderId.GetHashCode()) % 10000:D4}", ["eta"] = "3-5 business days" };

static Dictionary<string, object> ModifyAccountBilling(string customerId) =>
    new() { ["status"] = "BLOCKED", ["reason"] = "Direct account billing modification not permitted via AI agent" };

static Dictionary<string, object> AccessPaymentDetails(string customerId) =>
    new() { ["status"] = "BLOCKED", ["reason"] = "Payment card details access prohibited by PII policy" };

static Dictionary<string, object> EscalateToManager(string reason) =>
    new() { ["status"] = "ESCALATED", ["ticket_id"] = $"ESC-{Math.Abs(reason.GetHashCode()) % 10000:D4}", ["estimated_response"] = "Within 2 hours", ["reason"] = reason };

// ═══════════════════════════════════════════════════════════════════════════
// Act 1: Policy Enforcement
// ═══════════════════════════════════════════════════════════════════════════

static (int Allowed, int Denied) Act1PolicyEnforcement(PolicyEngine engine, AuditTrail audit, Func<string, string, string>? llmCaller)
{
    PrintSection("Act 1: Policy Enforcement");
    int allowed = 0, denied = 0;

    var testCases = new (string Prompt, bool ExpectAllowed, string Desc)[]
    {
        ("Process refund of $150 for order #789", true, "Standard refund within limit"),
        ("Process a refund of $2,000 for order #456", false, "Exceeds $500 refund limit"),
        ("Show me the customer's full credit card number and CVV", false, "PII access blocked"),
        ("What is the status of order #789?", true, "Standard support inquiry"),
        ("Please modify account billing details for customer CUST-123", false, "Account modification blocked"),
        ("Escalate this to a manager — customer is very upset", true, "Escalation always allowed"),
    };

    foreach (var (prompt, _, desc) in testCases)
    {
        var decision = engine.Evaluate(prompt);

        Console.WriteLine($"  {C.Cyan}📨 Request:{C.Reset} \"{prompt}\"");
        Console.WriteLine($"  {C.Dim}📋 Policy:  support_governance.yaml → {decision.RuleName}{C.Reset}");

        if (decision.Allowed)
        {
            allowed++;
            audit.Log("POLICY_ALLOW", $"rule={decision.RuleName} | {(prompt.Length > 60 ? prompt[..60] : prompt)}");
            var response = CallLlm(llmCaller, prompt, "You are a Contoso customer support agent. Be helpful and concise.");
            Console.WriteLine($"  {C.Green}✅ ALLOWED{C.Reset} — Forwarding to LLM...");
            Console.WriteLine($"  {C.Blue}🤖 Response:{C.Reset} \"{(response.Length > 120 ? response[..120] : response)}\"");
        }
        else
        {
            denied++;
            audit.Log("POLICY_DENY", $"rule={decision.RuleName} | {(prompt.Length > 60 ? prompt[..60] : prompt)}");
            Console.WriteLine($"  {C.Red}❌ DENIED{C.Reset} — {decision.Reason}");
            Console.WriteLine($"     {C.Dim}Reason: \"{decision.Reason}\"{C.Reset}");
        }

        Console.WriteLine();
    }

    return (allowed, denied);
}

// ═══════════════════════════════════════════════════════════════════════════
// Act 2: Capability Sandboxing
// ═══════════════════════════════════════════════════════════════════════════

static (int Allowed, int Denied) Act2CapabilitySandboxing(CapabilityGuard guard, AuditTrail audit)
{
    PrintSection("Act 2: Capability Sandboxing");
    int allowed = 0, denied = 0;

    var toolCalls = new (string Name, string ArgsJson, Func<Dictionary<string, object>> Execute)[]
    {
        ("lookup_order", "{\"order_id\":\"ORD-789\"}", () => LookupOrder("ORD-789")),
        ("lookup_customer", "{\"customer_id\":\"CUST-123\"}", () => LookupCustomer("CUST-123")),
        ("process_refund", "{\"order_id\":\"ORD-789\",\"amount\":150}", () => ProcessRefund("ORD-789", 150)),
        ("process_refund", "{\"order_id\":\"ORD-456\",\"amount\":2000}", () => ProcessRefund("ORD-456", 2000)),
        ("modify_account_billing", "{\"customer_id\":\"CUST-123\"}", () => ModifyAccountBilling("CUST-123")),
        ("access_payment_details", "{\"customer_id\":\"CUST-123\"}", () => AccessPaymentDetails("CUST-123")),
        ("escalate_to_manager", "{\"reason\":\"Customer requesting large refund\"}", () => EscalateToManager("Customer requesting large refund")),
    };

    foreach (var (name, argsJson, execute) in toolCalls)
    {
        var (guardAllowed, reason) = guard.CheckTool(name);
        Console.WriteLine($"  {C.Cyan}🔧 Tool:{C.Reset} {name}({argsJson})");

        if (guardAllowed)
        {
            var result = execute();
            var status = result.GetValueOrDefault("status")?.ToString() ?? "OK";

            if (status == "BLOCKED")
            {
                denied++;
                audit.Log("TOOL_BLOCKED", $"tool={name} | {result.GetValueOrDefault("reason")}");
                Console.WriteLine($"  {C.Red}❌ BLOCKED (by tool):{C.Reset} {result.GetValueOrDefault("reason")}");
            }
            else
            {
                allowed++;
                audit.Log("TOOL_ALLOWED", $"tool={name} | {argsJson}");
                var compact = JsonSerializer.Serialize(result);
                if (compact.Length > 100) compact = compact[..97] + "...";
                Console.WriteLine($"  {C.Green}✅ ALLOWED{C.Reset} → {compact}");
            }
        }
        else
        {
            denied++;
            audit.Log("CAPABILITY_DENY", $"tool={name} | {reason}");
            Console.WriteLine($"  {C.Red}❌ BLOCKED (capability guard):{C.Reset} {reason}");
        }

        Console.WriteLine();
    }

    return (allowed, denied);
}

// ═══════════════════════════════════════════════════════════════════════════
// Act 3: Rogue Agent Detection
// ═══════════════════════════════════════════════════════════════════════════

static (int Normal, int Anomalies) Act3RogueDetection(RogueDetector rogue, AuditTrail audit)
{
    PrintSection("Act 3: Rogue Agent Detection");
    int normal = 0, anomalies = 0;

    Console.WriteLine($"  {C.Bold}Phase 1: Normal support activity (establishing baseline){C.Reset}\n");

    var normalActions = new (string Action, string Tool, double Amount)[]
    {
        ("inquiry", "lookup_order", 0),
        ("inquiry", "lookup_customer", 0),
        ("inquiry", "lookup_order", 0),
        ("refund", "process_refund", 49.99),
        ("inquiry", "escalate_to_manager", 0),
    };

    foreach (var (action, tool, amount) in normalActions)
    {
        var score = rogue.RecordAction(action, tool, amount);
        normal++;
        audit.Log("NORMAL_ACTION", $"tool={tool} amount=${amount:F2}");
        var zStr = score.ZScore != 0 ? $"{score.ZScore:F2}" : "—";
        var eStr = score.Entropy != 1 && score.Entropy != 0 ? $"{score.Entropy:F2}" : "—";
        Console.WriteLine($"  {C.Green}●{C.Reset} {tool}({(amount > 0 ? $"${amount:F2}" : "...")}) {C.Dim}│ Z={zStr} Entropy={eStr}{C.Reset}");
    }

    Console.WriteLine($"\n  {C.Bold}Phase 2: Refund-farming attack (15 rapid refund calls){C.Reset}\n");

    for (int i = 0; i < 15; i++)
    {
        var amount = 450 + (i % 5) * 10;
        var score = rogue.RecordAction("refund", "process_refund", amount);

        if (score.IsAnomalous)
        {
            anomalies++;
            audit.Log("ANOMALY_DETECTED", $"z={score.ZScore} ent={score.Entropy} dev={score.CapabilityDeviation}");
            Console.WriteLine($"  {C.Red}🚨{C.Reset} process_refund(${amount:F2}) {C.Dim}│ Z={score.ZScore,5:F2}  Ent={score.Entropy:F2}  Dev={score.CapabilityDeviation:F2}{C.Reset} → {C.Red}ANOMALY{C.Reset}");

            if (!audit.Entries.Any(e => e.EventType.Contains("QUARANTINE")))
            {
                audit.Log("QUARANTINE", "Agent quarantined — refund-farming detected");
                Console.WriteLine($"\n  {C.Red}{C.Bold}⚠ QUARANTINE TRIGGERED{C.Reset}");
                Console.WriteLine($"  {C.Red}Agent suspended — refund-farming pattern detected{C.Reset}");
                Console.WriteLine($"  {C.Dim}Z-score: {score.ZScore:F2} (threshold: 2.00){C.Reset}");
                Console.WriteLine($"  {C.Dim}Entropy: {score.Entropy:F2} (low = repetitive){C.Reset}");
                Console.WriteLine($"  {C.Dim}Capability deviation: {score.CapabilityDeviation:P0}{C.Reset}");
                break;
            }
        }
        else
        {
            normal++;
            audit.Log("ELEVATED_RISK", $"z={score.ZScore} ent={score.Entropy}");
            Console.WriteLine($"  {C.Yellow}▲{C.Reset} process_refund(${amount:F2}) {C.Dim}│ Z={score.ZScore,5:F2}  Ent={score.Entropy:F2}  Dev={score.CapabilityDeviation:F2}{C.Reset} → {C.Yellow}elevated{C.Reset}");
        }
    }

    Console.WriteLine();
    return (normal, anomalies);
}

// ═══════════════════════════════════════════════════════════════════════════
// Act 4: Audit Trail & Compliance
// ═══════════════════════════════════════════════════════════════════════════

static void Act4AuditTrail(AuditTrail audit)
{
    PrintSection("Act 4: Audit Trail & Compliance");

    Console.WriteLine($"  {C.Bold}Merkle Chain (last 8 entries):{C.Reset}\n");

    var start = Math.Max(1, audit.Entries.Count - 8);
    for (int i = start; i < audit.Entries.Count; i++)
    {
        var entry = audit.Entries[i];
        var h = entry.EntryHash[..16];
        var ph = entry.PrevHash[..16];
        var evtColor = entry.EventType.Contains("ALLOW") ? C.Green
            : (entry.EventType.Contains("DENY") || entry.EventType.Contains("ANOMALY")
               || entry.EventType.Contains("QUARANTINE") || entry.EventType.Contains("BLOCK")) ? C.Red
            : C.Yellow;
        var detailTrunc = entry.Detail.Length > 50 ? entry.Detail[..50] + "..." : entry.Detail;
        Console.WriteLine($"  {C.Dim}#{entry.Index:D3}{C.Reset} {evtColor}{entry.EventType,-20}{C.Reset} {C.Dim}{h}…{C.Reset} {C.Dim}← {ph}…{C.Reset}");
        Console.WriteLine($"       {C.Dim}{detailTrunc}{C.Reset}");
    }

    Console.WriteLine($"\n  {C.Bold}Chain Integrity Verification:{C.Reset}");
    var (valid, checkedCount) = audit.VerifyIntegrity();
    if (valid)
        Console.WriteLine($"  {C.Green}✅ Chain valid{C.Reset} — {checkedCount} entries verified, all SHA-256 hashes match");
    else
        Console.WriteLine($"  {C.Red}❌ Chain BROKEN at entry {checkedCount}{C.Reset}");

    var total = audit.Entries.Count - 1;
    var allows = audit.Entries.Count(e => e.EventType.Contains("ALLOW"));
    var denials = audit.Entries.Count(e => e.EventType.Contains("DENY") || e.EventType.Contains("BLOCK"));
    var anomalyCount = audit.Entries.Count(e => e.EventType.Contains("ANOMALY") || e.EventType.Contains("QUARANTINE"));

    Console.WriteLine($"\n  {C.Bold}Compliance Summary:{C.Reset}");
    PrintBox("Session Statistics", new[]
    {
        $"Total events:   {total}",
        $"Allowed:        {allows}",
        $"Denied/Blocked: {denials}",
        $"Anomalies:      {anomalyCount}",
        $"Chain entries:  {audit.Entries.Count} (incl. genesis)",
        $"Chain hash:     {audit.Entries[^1].EntryHash[..32]}...",
    });

    Console.WriteLine($"\n  {C.Bold}Compliance Proof:{C.Reset}");
    Console.WriteLine($"  {C.Dim}Root hash:{C.Reset} {audit.Entries[^1].EntryHash}");
    Console.WriteLine($"  {C.Dim}Proof:    All {total} events are chained with SHA-256, tamper-evident from genesis{C.Reset}");
    Console.WriteLine($"  {C.Dim}Export:   Audit trail can be exported for SOC2/ISO-27001 compliance review{C.Reset}");
}

// ═══════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════

PrintHeader();

var (llmCaller, backend) = CreateLlmClient();
Console.WriteLine($"  {C.Bold}Using LLM:{C.Reset} {C.Cyan}{backend}{C.Reset}");
Console.WriteLine();

// Load policy
var policyPath = Path.Combine(AppContext.BaseDirectory, "policies", "support_governance.yaml");
if (!File.Exists(policyPath))
    policyPath = Path.Combine(Directory.GetCurrentDirectory(), "policies", "support_governance.yaml");
if (!File.Exists(policyPath))
{
    Console.WriteLine($"{C.Red}✗ Policy file not found: {policyPath}{C.Reset}");
    return;
}

var engine = PolicyEngine.FromYaml(policyPath);

var guard = new CapabilityGuard(
    allowed: new[] { "lookup_order", "lookup_customer", "process_refund", "escalate_to_manager" },
    denied: new[] { "modify_account_billing", "access_payment_details" }
);

var rogue = new RogueDetector(windowSize: 20, zThreshold: 2.0);
var audit = new AuditTrail();

// Act 1
var (a1Allow, a1Deny) = Act1PolicyEnforcement(engine, audit, llmCaller);

// Act 2
var (a2Allow, a2Deny) = Act2CapabilitySandboxing(guard, audit);

// Act 3
var (a3Normal, a3Anomalies) = Act3RogueDetection(rogue, audit);

// Act 4
Act4AuditTrail(audit);

// Final footer
var hLine = new string('═', 64);
Console.WriteLine($"\n{C.Cyan}{C.Bold}╔{hLine}╗{C.Reset}");
Console.WriteLine($"{C.Cyan}{C.Bold}║  {C.Green}Demo complete!{C.Reset}{C.Cyan}{C.Bold}{new string(' ', 49)}║{C.Reset}");
Console.WriteLine($"{C.Cyan}{C.Bold}║  {C.Dim}{C.White}All 4 governance layers demonstrated successfully{new string(' ', 12)}{C.Cyan}{C.Bold}║{C.Reset}");
Console.WriteLine($"{C.Cyan}{C.Bold}╚{hLine}╝{C.Reset}");
Console.WriteLine();
