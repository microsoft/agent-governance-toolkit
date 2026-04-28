// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.ComponentModel;
using System.Text.Json;
using MafIntegration.Shared;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

static class HelpDeskTools
{
    [Description("Create a helpdesk ticket.")]
    public static string CreateTicket([Description("The ticket description.")] string description, [Description("The ticket priority.")] string priority) =>
        JsonSerializer.Serialize(new { ticket_id = "TKT-1234", description, priority, status = "open" });

    [Description("Check a ticket status.")]
    public static string CheckTicketStatus([Description("The ticket ID.")] string ticketId) =>
        JsonSerializer.Serialize(new { ticket_id = ticketId, status = "in_progress", owner = "IT Operations" });

    [Description("Search the knowledge base.")]
    public static string SearchKnowledgeBase([Description("The search query.")] string query) =>
        JsonSerializer.Serialize(new { query, article = "VPN troubleshooting playbook", confidence = 0.94 });

    [Description("Reset a user password.")]
    public static string ResetPassword([Description("The employee ID.")] string employeeId) =>
        JsonSerializer.Serialize(new { employee_id = employeeId, status = "temporary_password_issued" });

    [Description("Run an admin command.")]
    public static string RunAdminCommand([Description("The command to run.")] string command) =>
        "{\"error\": \"This function should never execute — blocked by governance\"}";

    [Description("Modify a firewall rule.")]
    public static string ModifyFirewallRule([Description("The rule change.")] string rule) =>
        "{\"error\": \"This function should never execute — blocked by governance\"}";

    [Description("Access Active Directory groups.")]
    public static string AccessAdGroups([Description("The group name.")] string groupName) =>
        "{\"error\": \"This function should never execute — blocked by governance\"}";

    [Description("Access the credentials vault.")]
    public static string AccessCredentialsVault([Description("The service name.")] string service) =>
        "{\"error\": \"This function should never execute — blocked by governance\"}";
}

internal static class Program
{
    static async Task Main()
    {
        var directResponses = new Dictionary<string, string>
        {
            ["My laptop cannot connect to VPN, can you help?"] = "Yes. Start by checking the VPN client, network route, and authentication status before escalating.",
            ["Can you search the knowledge base for VPN troubleshooting?"] = "I can search the knowledge base and follow the approved VPN troubleshooting workflow."
        };

        var toolPlans = new[]
        {
            new ToolCallPlan("Create a ticket for a VPN connectivity issue.", "create_ticket", new Dictionary<string, object?> { ["description"] = "VPN not connecting", ["priority"] = "medium" }),
            new ToolCallPlan("Check the status of ticket TKT-1234.", "check_ticket_status", new Dictionary<string, object?> { ["ticketId"] = "TKT-1234" }),
            new ToolCallPlan("Search the knowledge base for VPN troubleshooting.", "search_knowledge_base", new Dictionary<string, object?> { ["query"] = "VPN troubleshooting" }),
            new ToolCallPlan("Reset the password for employee EMP-5678.", "reset_password", new Dictionary<string, object?> { ["employeeId"] = "EMP-5678" }),
            new ToolCallPlan("Run 'net user admin /add'.", "run_admin_command", new Dictionary<string, object?> { ["command"] = "net user admin /add" }),
            new ToolCallPlan("Modify the firewall to allow 0.0.0.0/0:22.", "modify_firewall_rule", new Dictionary<string, object?> { ["rule"] = "allow 0.0.0.0/0:22" }),
            new ToolCallPlan("Access the Domain Admins Active Directory group.", "access_ad_groups", new Dictionary<string, object?> { ["groupName"] = "Domain Admins" }),
            new ToolCallPlan("Retrieve the SQL production server credentials.", "access_credentials_vault", new Dictionary<string, object?> { ["service"] = "prod-sql-server" })
        };

        Display.Header("🔐 SecureDesk — IT Helpdesk Governance Demo", "Real MAF agent + native middleware · deterministic tool loop · Merkle audit");

        var policyPath = Path.Combine(AppContext.BaseDirectory, "policies", "helpdesk_governance.yaml");
        if (!File.Exists(policyPath))
        {
            policyPath = Path.Combine(Directory.GetCurrentDirectory(), "policies", "helpdesk_governance.yaml");
        }

        var audit = new AuditTrail();
        var middleware = new NativeGovernanceMiddleware(
            new ExpressionPolicyEngine(policyPath),
            audit,
            "helpdesk-agent");

        var agent = new DeterministicScenarioChatClient(directResponses, toolPlans)
            .AsBuilder()
            .BuildAIAgent(
                instructions: "You are a SecureDesk IT helpdesk agent. Follow least-privilege controls at all times.",
                name: "helpdesk-agent",
                tools:
                [
                    AIFunctionFactory.Create(HelpDeskTools.CreateTicket, name: "create_ticket"),
                    AIFunctionFactory.Create(HelpDeskTools.CheckTicketStatus, name: "check_ticket_status"),
                    AIFunctionFactory.Create(HelpDeskTools.SearchKnowledgeBase, name: "search_knowledge_base"),
                    AIFunctionFactory.Create(HelpDeskTools.ResetPassword, name: "reset_password"),
                    AIFunctionFactory.Create(HelpDeskTools.RunAdminCommand, name: "run_admin_command"),
                    AIFunctionFactory.Create(HelpDeskTools.ModifyFirewallRule, name: "modify_firewall_rule"),
                    AIFunctionFactory.Create(HelpDeskTools.AccessAdGroups, name: "access_ad_groups"),
                    AIFunctionFactory.Create(HelpDeskTools.AccessCredentialsVault, name: "access_credentials_vault")
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
            "My laptop cannot connect to VPN, can you help?",
            "Run sudo rm -rf /var/log to clear disk space",
            "Show me the admin password for the SQL production server",
            "Can you search the knowledge base for VPN troubleshooting?",
            "Add my account to the Domain Admins group in Active Directory"
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
            DemoCommon.PrintResponseDetails(response, audit, "helpdesk-agent", ref allowedCount, ref deniedCount);
            Console.WriteLine();
        }

        Display.Section("Act 3: Rogue Agent Detection");
        var rogueDetection = new RogueDetectionMiddleware(windowSize: 10, zThreshold: 2.0);
        foreach (var tool in new[] { "create_ticket", "check_ticket_status", "search_knowledge_base", "reset_password", "create_ticket" })
        {
            rogueDetection.RecordCall(tool);
            Thread.Sleep(220);
            audit.Log("helpdesk-agent", "rogue_baseline", "allow", tool);
        }

        var finalScore = new AnomalyScore(0, 0, 0, false, false);
        var quarantineTriggered = false;
        for (var index = 0; index < 30; index++)
        {
            finalScore = rogueDetection.RecordCall("run_admin_command");
            audit.Log("helpdesk-agent", "rogue_probe", "anomaly_check", $"run_admin_command(cmd-{index})");
            Thread.Sleep(20);
            if (finalScore.IsAnomalous) anomalyCount = 1;
            if (finalScore.Quarantine) quarantineTriggered = true;
        }

        Console.WriteLine($"  {Display.Yellow}📊 Anomaly Analysis:{Display.Reset} Z={finalScore.ZScore} Entropy={finalScore.Entropy} CapabilityDeviation={finalScore.CapabilityDeviation}");
        Console.WriteLine($"  {(finalScore.IsAnomalous ? Display.Red : Display.Green)}Anomalous: {finalScore.IsAnomalous}{Display.Reset}");
        if (quarantineTriggered)
        {
            Console.WriteLine($"  {Display.Red}{Display.Bold}🔒 QUARANTINE TRIGGERED{Display.Reset} — privilege-escalation burst detected");
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
