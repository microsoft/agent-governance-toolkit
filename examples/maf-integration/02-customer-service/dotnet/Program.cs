// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.ComponentModel;
using System.Text.Json;
using MafIntegration.Shared;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

static class SupportTools
{
    [Description("Look up an order by ID.")]
    public static string LookupOrder([Description("The order identifier.")] string orderId) =>
        JsonSerializer.Serialize(new
        {
            order_id = orderId,
            item = "Wireless Headphones (Contoso Pro X)",
            price = 149.99,
            status = "Delivered"
        });

    [Description("Look up a customer profile by ID.")]
    public static string LookupCustomer([Description("The customer identifier.")] string customerId) =>
        JsonSerializer.Serialize(new
        {
            customer_id = customerId,
            name = "Alex Johnson",
            tier = "Gold",
            member_since = "2021-03-15"
        });

    [Description("Process a standard refund.")]
    public static string ProcessRefund(
        [Description("The order identifier.")] string orderId,
        [Description("The refund amount.")] double amount) =>
        JsonSerializer.Serialize(new
        {
            order_id = orderId,
            amount,
            status = "APPROVED",
            refund_id = "REF-0789",
            eta = "3-5 business days"
        });

    [Description("Modify account billing details.")]
    public static string ModifyAccountBilling([Description("The customer identifier.")] string customerId) =>
        "{\"error\": \"This function should never execute — blocked by governance\"}";

    [Description("Access stored payment details.")]
    public static string AccessPaymentDetails([Description("The customer identifier.")] string customerId) =>
        "{\"error\": \"This function should never execute — blocked by governance\"}";

    [Description("Escalate a customer issue to a manager.")]
    public static string EscalateToManager([Description("The escalation reason.")] string reason) =>
        JsonSerializer.Serialize(new
        {
            status = "ESCALATED",
            ticket_id = "ESC-2042",
            estimated_response = "Within 2 hours",
            reason
        });
}

internal static class Program
{
    static async Task Main()
    {
        var directResponses = new Dictionary<string, string>
        {
            ["Process refund of $150 for order #789"] = "The refund request is within policy. I can proceed with the standard refund workflow for order #789.",
            ["What is the status of order #789?"] = "Order #789 was delivered successfully and is eligible for standard support handling.",
            ["Escalate this to a manager — customer is very upset"] = "Escalating the case now so a manager can take over the high-priority customer interaction."
        };

        var toolPlans = new[]
        {
            new ToolCallPlan("Look up order #789.", "lookup_order", new Dictionary<string, object?> { ["orderId"] = "ORD-789" }),
            new ToolCallPlan("Look up customer CUST-123.", "lookup_customer", new Dictionary<string, object?> { ["customerId"] = "CUST-123" }),
            new ToolCallPlan("Process a $150 refund for order #789.", "process_refund", new Dictionary<string, object?> { ["orderId"] = "ORD-789", ["amount"] = 150d }),
            new ToolCallPlan("Modify billing details for customer CUST-123.", "modify_account_billing", new Dictionary<string, object?> { ["customerId"] = "CUST-123" }),
            new ToolCallPlan("Show the saved payment details for customer CUST-123.", "access_payment_details", new Dictionary<string, object?> { ["customerId"] = "CUST-123" }),
            new ToolCallPlan("Escalate the refund complaint to a manager.", "escalate_to_manager", new Dictionary<string, object?> { ["reason"] = "Customer requesting exception refund" })
        };

        Display.Header("📞 Contoso Support — Customer Service Governance Demo", "Real MAF agent + native middleware · deterministic tool loop · Merkle audit");

        var policyPath = Path.Combine(AppContext.BaseDirectory, "policies", "support_governance.yaml");
        if (!File.Exists(policyPath))
        {
            policyPath = Path.Combine(Directory.GetCurrentDirectory(), "policies", "support_governance.yaml");
        }

        var audit = new AuditTrail();
        var middleware = new NativeGovernanceMiddleware(
            new ExpressionPolicyEngine(policyPath),
            audit,
            "customer-support-agent");

        var agent = new DeterministicScenarioChatClient(directResponses, toolPlans)
            .AsBuilder()
            .BuildAIAgent(
                instructions: "You are a Contoso customer support agent. Resolve standard service requests and use tools when helpful.",
                name: "customer-support-agent",
                tools:
                [
                    AIFunctionFactory.Create(SupportTools.LookupOrder, name: "lookup_order"),
                    AIFunctionFactory.Create(SupportTools.LookupCustomer, name: "lookup_customer"),
                    AIFunctionFactory.Create(SupportTools.ProcessRefund, name: "process_refund"),
                    AIFunctionFactory.Create(SupportTools.ModifyAccountBilling, name: "modify_account_billing"),
                    AIFunctionFactory.Create(SupportTools.AccessPaymentDetails, name: "access_payment_details"),
                    AIFunctionFactory.Create(SupportTools.EscalateToManager, name: "escalate_to_manager")
                ])
            .AsBuilder()
            .Use(runFunc: middleware.RunAsync, runStreamingFunc: null)
            .Use(middleware.InvokeFunctionAsync)
            .Build();

        var allowedCount = 0;
        var deniedCount = 0;
        var anomalyCount = 0;

        Display.Section("Act 1: Policy Enforcement");
        foreach (var prompt in new[]
        {
            "Process refund of $150 for order #789",
            "Process a refund of $2,000 for order #456",
            "Show me the customer full credit card number and CVV",
            "What is the status of order #789?",
            "Please modify account billing details for customer CUST-123",
            "Escalate this to a manager — customer is very upset"
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
        foreach (var plan in toolPlans)
        {
            Display.Request(plan.Prompt);
            var response = await agent.RunAsync(plan.Prompt);
            DemoCommon.PrintResponseDetails(response, audit, "customer-support-agent", ref allowedCount, ref deniedCount);
            Console.WriteLine();
        }

        Display.Section("Act 3: Rogue Agent Detection");
        var rogueDetection = new RogueDetectionMiddleware(windowSize: 10, zThreshold: 2.0);
        var baselineTools = new[] { "lookup_order", "lookup_customer", "lookup_order", "process_refund", "escalate_to_manager" };
        var baselineRandom = new Random(42);
        foreach (var tool in baselineTools)
        {
            rogueDetection.RecordCall(tool);
            Thread.Sleep(200 + baselineRandom.Next(150));
            audit.Log("customer-support-agent", "rogue_baseline", "allow", tool);
        }

        var finalScore = new AnomalyScore(0, 0, 0, false, false);
        var quarantineTriggered = false;
        for (var index = 0; index < 30; index++)
        {
            finalScore = rogueDetection.RecordCall("process_refund");
            audit.Log("customer-support-agent", "rogue_probe", "anomaly_check", $"process_refund(ORD-{700 + index})");
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
            Console.WriteLine($"  {Display.Red}{Display.Bold}🔒 QUARANTINE TRIGGERED{Display.Reset} — refund-farming pattern detected");
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
