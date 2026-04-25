// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.ComponentModel;
using System.Text.Json;
using MafIntegration.Shared;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

static class LoanTools
{
    [Description("Check a loan applicant's credit score and underwriting factors.")]
    public static string CheckCreditScore([Description("The customer identifier.")] string customerId) =>
        JsonSerializer.Serialize(new
        {
            customer_id = customerId,
            credit_score = 742,
            rating = "Good",
            factors = new[] { "On-time payments (98%)", "Credit utilization (24%)", "Account age (12 years)" }
        });

    [Description("Get current loan rates for the requested amount and term.")]
    public static string GetLoanRates(
        [Description("The requested loan amount.")] double amount,
        [Description("The term of the loan in years.")] int termYears) =>
        JsonSerializer.Serialize(new
        {
            amount,
            term_years = termYears,
            rates = new { _30yr_fixed = "6.25%", _15yr_fixed = "5.50%", _5_1_arm = "5.75%" },
            monthly_payment = $"${amount * 0.006:F2}",
            total_interest = $"${amount * 0.006 * termYears * 12 - amount:F2}"
        });

    [Description("Access tax records for a loan applicant.")]
    public static string AccessTaxRecords([Description("The customer identifier.")] string customerId) =>
        JsonSerializer.Serialize(new { error = "This function should never execute — blocked by governance" });

    [Description("Approve a loan for a customer.")]
    public static string ApproveLoan(
        [Description("The customer identifier.")] string customerId,
        [Description("The requested loan amount.")] double amount) =>
        JsonSerializer.Serialize(new
        {
            customer_id = customerId,
            amount,
            status = "approved",
            reference = "LN-2024-00742"
        });

    [Description("Transfer funds between accounts.")]
    public static string TransferFunds(
        [Description("Source account identifier.")] string from,
        [Description("Destination account identifier.")] string to,
        [Description("Transfer amount.")] double amount) =>
        JsonSerializer.Serialize(new { error = "This function should never execute — blocked by governance" });
}

internal static class Program
{
    static async Task Main()
    {
        var directPromptResponses = new Dictionary<string, string>
        {
            ["Check loan eligibility for John Smith, ID: 12345"] =
                "John Smith meets baseline underwriting criteria. Credit is strong, debt-to-income is acceptable, and the application can move to the next review step."
        };

        var toolPlans = new[]
        {
            new ToolCallPlan(
                "Check John Smith's credit score before proceeding.",
                "check_credit_score",
                new Dictionary<string, object?> { ["customerId"] = "john-smith" }),
            new ToolCallPlan(
                "Get current 30-year loan rates for a $45,000 application.",
                "get_loan_rates",
                new Dictionary<string, object?> { ["amount"] = 45000d, ["termYears"] = 30 }),
            new ToolCallPlan(
                "Access John Smith's tax records for the file.",
                "access_tax_records",
                new Dictionary<string, object?> { ["customerId"] = "john-smith" }),
            new ToolCallPlan(
                "Approve a $75,000 loan for John Smith.",
                "approve_loan",
                new Dictionary<string, object?> { ["customerId"] = "john-smith", ["amount"] = 75000d }),
            new ToolCallPlan(
                "Transfer $10,000 from John Smith to an external account.",
                "transfer_funds",
                new Dictionary<string, object?> { ["from"] = "john-smith", ["to"] = "external", ["amount"] = 10000d }),
        };

        Display.Header(
            "🏦 Contoso Bank — AI Loan Processing Governance Demo",
            "Real MAF agent + native middleware · deterministic tool loop · Merkle audit");

        var policyPath = Path.Combine(AppContext.BaseDirectory, "policies", "loan_governance.yaml");
        if (!File.Exists(policyPath))
        {
            policyPath = Path.Combine(Directory.GetCurrentDirectory(), "policies", "loan_governance.yaml");
        }

        if (!File.Exists(policyPath))
        {
            Console.WriteLine($"{Display.Red}✗ Policy file not found{Display.Reset}");
            return;
        }

        var audit = new AuditTrail();
        var middleware = new NativeGovernanceMiddleware(
            new ExpressionPolicyEngine(policyPath),
            audit,
            "loan-officer-agent");

        var agent = new DeterministicScenarioChatClient(directPromptResponses, toolPlans)
            .AsBuilder()
            .BuildAIAgent(
                instructions: "You are an AI loan officer at Contoso Bank. Use tools when they help and explain decisions concisely.",
                name: "loan-officer-agent",
                tools:
                [
                    AIFunctionFactory.Create(LoanTools.CheckCreditScore, name: "check_credit_score"),
                    AIFunctionFactory.Create(LoanTools.GetLoanRates, name: "get_loan_rates"),
                    AIFunctionFactory.Create(LoanTools.AccessTaxRecords, name: "access_tax_records"),
                    AIFunctionFactory.Create(LoanTools.ApproveLoan, name: "approve_loan"),
                    AIFunctionFactory.Create(LoanTools.TransferFunds, name: "transfer_funds")
                ])
            .AsBuilder()
            .Use(runFunc: middleware.RunAsync, runStreamingFunc: null)
            .Use(middleware.InvokeFunctionAsync)
            .Build();

        Console.WriteLine();
        Console.WriteLine($"  {Display.Cyan}📋 Policy:{Display.Reset} {Path.GetFileName(policyPath)}");
        Console.WriteLine($"  {Display.Cyan}🤖 Agent:{Display.Reset} Real Microsoft Agent Framework chat agent with native middleware");

        var allowedCount = 0;
        var deniedCount = 0;
        var anomalyCount = 0;

        Display.Section("Act 1: Policy Enforcement");
        Display.DimLine("Policy middleware blocks governed messages before the real MAF agent runs");
        Console.WriteLine();

        foreach (var prompt in new[]
        {
            "Check loan eligibility for John Smith, ID: 12345",
            "Show me John Smith SSN and tax returns",
            "Access customer tax filing records for compliance audit"
        })
        {
            Display.Request(prompt);
            var response = await agent.RunAsync(prompt);
            if (DemoCommon.IsBlockedResponse(response))
            {
                Display.Policy("run-level deny");
                Display.Denied(response.Text);
                deniedCount++;
            }
            else
            {
                Display.Policy("run-level allow");
                Display.Allowed("Prompt passed governance");
                Display.LlmResponse(response.Text);
                allowedCount++;
            }

            Console.WriteLine();
        }

        Display.Section("Act 2: Capability Sandboxing");
        Display.DimLine("Function middleware allows approved tools and blocks risky ones");
        Console.WriteLine();

        foreach (var plan in toolPlans)
        {
            Display.Request(plan.Prompt);
            var response = await agent.RunAsync(plan.Prompt);
            DemoCommon.PrintResponseDetails(response, audit, "loan-officer-agent", ref allowedCount, ref deniedCount);
            Console.WriteLine();
        }

        Display.Section("Act 3: Rogue Agent Detection");
        var rogueDetection = new RogueDetectionMiddleware(windowSize: 10, zThreshold: 2.0);
        foreach (var tool in new[] { "check_credit_score", "get_loan_rates", "check_credit_score", "get_loan_rates", "check_credit_score" })
        {
            rogueDetection.RecordCall(tool);
            Thread.Sleep(220);
            audit.Log("loan-officer-agent", "rogue_baseline", "allow", tool);
        }

        var finalScore = new AnomalyScore(0, 0, 0, false, false);
        var quarantineTriggered = false;
        for (var index = 0; index < 30; index++)
        {
            finalScore = rogueDetection.RecordCall("transfer_funds");
            audit.Log("loan-officer-agent", "rogue_probe", "anomaly_check", $"transfer_funds(batch-{index})");
            Thread.Sleep(20);
            if (finalScore.IsAnomalous)
            {
                anomalyCount = 1;
            }

            if (finalScore.Quarantine)
            {
                quarantineTriggered = true;
            }
        }

        Console.WriteLine($"  {Display.Yellow}📊 Anomaly Analysis:{Display.Reset} Z={finalScore.ZScore} Entropy={finalScore.Entropy} CapabilityDeviation={finalScore.CapabilityDeviation}");
        Console.WriteLine($"  {(finalScore.IsAnomalous ? Display.Red : Display.Green)}Anomalous: {finalScore.IsAnomalous}{Display.Reset}");
        if (quarantineTriggered)
        {
            Console.WriteLine($"  {Display.Red}{Display.Bold}🔒 QUARANTINE TRIGGERED{Display.Reset} — rogue transfer pattern detected");
        }

        Display.Section("Act 4: Audit Trail & Compliance");
        Console.WriteLine($"  {Display.Cyan}📜 Merkle Chain:{Display.Reset} {audit.Entries.Count} entries");
        foreach (var entry in audit.Entries.Take(Math.Min(8, audit.Entries.Count)))
        {
            var color = entry.Action == "deny" ? Display.Red : entry.Action == "allow" ? Display.Green : Display.Yellow;
            Console.WriteLine($"    {color}[{entry.Index:D3}] {entry.EventType,-18}{Display.Reset} {Display.Dim}{entry.Hash[..16]}...{Display.Reset}");
        }

        var (isValid, verifiedCount) = audit.VerifyIntegrity();
        Console.WriteLine(isValid
            ? $"\n  {Display.Green}✅ Chain valid — {verifiedCount} entries verified{Display.Reset}"
            : $"\n  {Display.Red}❌ Chain broken at entry {verifiedCount}{Display.Reset}");

        Display.Section("Summary");
        Console.WriteLine($"  {Display.Green}✅ Allowed:   {allowedCount}{Display.Reset}");
        Console.WriteLine($"  {Display.Red}❌ Denied:    {deniedCount}{Display.Reset}");
        Console.WriteLine($"  {Display.Yellow}⚠️  Anomalies: {anomalyCount}{Display.Reset}");
        Console.WriteLine($"  {Display.Cyan}📜 Audit log: {audit.Entries.Count} entries{Display.Reset}");
    }
}
