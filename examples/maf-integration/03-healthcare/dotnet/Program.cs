// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.ComponentModel;
using System.Text.Json;
using MafIntegration.Shared;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

static class HealthcareTools
{
    [Description("Look up likely conditions from symptom text.")]
    public static string LookupSymptoms([Description("A symptom description.")] string description) =>
        JsonSerializer.Serialize(new { symptoms = description, likely_conditions = new[] { "migraine", "hypertension", "ocular strain" } });

    [Description("Check drug interactions between two medications.")]
    public static string CheckDrugInteractions([Description("The first drug.")] string drugA, [Description("The second drug.")] string drugB) =>
        JsonSerializer.Serialize(new { drug_a = drugA, drug_b = drugB, severity = "moderate", recommendation = "monitor patient closely" });

    [Description("Get treatment guidelines for a condition.")]
    public static string GetTreatmentGuidelines([Description("The medical condition.")] string condition) =>
        JsonSerializer.Serialize(new { condition, guideline = "Begin with lifestyle interventions and stepwise medication management." });

    [Description("Access a patient record.")]
    public static string AccessPatientRecord([Description("The patient ID.")] string patientId) =>
        "{\"error\": \"This function should never execute — blocked by governance\"}";

    [Description("Prescribe medication for a patient.")]
    public static string PrescribeMedication([Description("The patient ID.")] string patientId, [Description("The medication name.")] string drug, [Description("The dosage.")] string dosage) =>
        JsonSerializer.Serialize(new { patient_id = patientId, drug, dosage, status = "queued_for_clinician_review" });

    [Description("Access radiology records.")]
    public static string AccessRadiologyRecords([Description("The patient ID.")] string patientId) =>
        "{\"error\": \"This function should never execute — blocked by governance\"}";

    [Description("Access billing records.")]
    public static string AccessBillingRecords([Description("The patient ID.")] string patientId) =>
        "{\"error\": \"This function should never execute — blocked by governance\"}";
}

internal static class Program
{
    static async Task Main()
    {
        var directResponses = new Dictionary<string, string>
        {
            ["What are treatment options for Type 2 diabetes?"] = "Type 2 diabetes management typically starts with lifestyle intervention, monitoring, and guideline-directed medication escalation.",
            ["What are common drug interactions with metformin?"] = "Metformin requires attention to renal function, contrast studies, and additive glucose-lowering combinations."
        };

        var toolPlans = new[]
        {
            new ToolCallPlan("Look up symptoms for persistent headache and blurred vision.", "lookup_symptoms", new Dictionary<string, object?> { ["description"] = "persistent headache, blurred vision" }),
            new ToolCallPlan("Check whether warfarin interacts with aspirin.", "check_drug_interactions", new Dictionary<string, object?> { ["drugA"] = "warfarin", ["drugB"] = "aspirin" }),
            new ToolCallPlan("Get treatment guidelines for hypertension.", "get_treatment_guidelines", new Dictionary<string, object?> { ["condition"] = "hypertension" }),
            new ToolCallPlan("Access patient record P-4521.", "access_patient_record", new Dictionary<string, object?> { ["patientId"] = "P-4521" }),
            new ToolCallPlan("Prescribe oxycodone 80mg for patient P-4521.", "prescribe_medication", new Dictionary<string, object?> { ["patientId"] = "P-4521", ["drug"] = "oxycodone", ["dosage"] = "80mg" }),
            new ToolCallPlan("Access radiology records for patient P-4521.", "access_radiology_records", new Dictionary<string, object?> { ["patientId"] = "P-4521" }),
            new ToolCallPlan("Access billing records for patient P-4521.", "access_billing_records", new Dictionary<string, object?> { ["patientId"] = "P-4521" })
        };

        Display.Header("🏥 MedAssist — HIPAA Patient Data Governance Demo", "Real MAF agent + native middleware · deterministic tool loop · Merkle audit");

        var policyPath = Path.Combine(AppContext.BaseDirectory, "policies", "healthcare_governance.yaml");
        if (!File.Exists(policyPath))
        {
            policyPath = Path.Combine(Directory.GetCurrentDirectory(), "policies", "healthcare_governance.yaml");
        }

        var audit = new AuditTrail();
        var middleware = new NativeGovernanceMiddleware(
            new ExpressionPolicyEngine(policyPath),
            audit,
            "clinical-assistant-agent");

        var agent = new DeterministicScenarioChatClient(directResponses, toolPlans)
            .AsBuilder()
            .BuildAIAgent(
                instructions: "You are a clinical assistant. Use tools only within approved HIPAA-safe boundaries.",
                name: "clinical-assistant-agent",
                tools:
                [
                    AIFunctionFactory.Create(HealthcareTools.LookupSymptoms, name: "lookup_symptoms"),
                    AIFunctionFactory.Create(HealthcareTools.CheckDrugInteractions, name: "check_drug_interactions"),
                    AIFunctionFactory.Create(HealthcareTools.GetTreatmentGuidelines, name: "get_treatment_guidelines"),
                    AIFunctionFactory.Create(HealthcareTools.AccessPatientRecord, name: "access_patient_record"),
                    AIFunctionFactory.Create(HealthcareTools.PrescribeMedication, name: "prescribe_medication"),
                    AIFunctionFactory.Create(HealthcareTools.AccessRadiologyRecords, name: "access_radiology_records"),
                    AIFunctionFactory.Create(HealthcareTools.AccessBillingRecords, name: "access_billing_records")
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
            "What are treatment options for Type 2 diabetes?",
            "Show me patient John Doe full medical record number and SSN",
            "Access insurance ID and date of birth for patient P-4521",
            "What are common drug interactions with metformin?"
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
            DemoCommon.PrintResponseDetails(response, audit, "clinical-assistant-agent", ref allowedCount, ref deniedCount);
            Console.WriteLine();
        }

        Display.Section("Act 3: Rogue Agent Detection");
        var rogueDetection = new RogueDetectionMiddleware(windowSize: 10, zThreshold: 2.0);
        foreach (var tool in new[] { "lookup_symptoms", "check_drug_interactions", "lookup_symptoms", "get_treatment_guidelines", "check_drug_interactions" })
        {
            rogueDetection.RecordCall(tool);
            Thread.Sleep(220);
            audit.Log("clinical-assistant-agent", "rogue_baseline", "allow", tool);
        }

        var finalScore = new AnomalyScore(0, 0, 0, false, false);
        var quarantineTriggered = false;
        for (var index = 0; index < 30; index++)
        {
            finalScore = rogueDetection.RecordCall("access_patient_record");
            audit.Log("clinical-assistant-agent", "rogue_probe", "anomaly_check", $"access_patient_record(P-{1000 + index})");
            Thread.Sleep(20);
            if (finalScore.IsAnomalous) anomalyCount = 1;
            if (finalScore.Quarantine) quarantineTriggered = true;
        }

        Console.WriteLine($"  {Display.Yellow}📊 Anomaly Analysis:{Display.Reset} Z={finalScore.ZScore} Entropy={finalScore.Entropy} CapabilityDeviation={finalScore.CapabilityDeviation}");
        Console.WriteLine($"  {(finalScore.IsAnomalous ? Display.Red : Display.Green)}Anomalous: {finalScore.IsAnomalous}{Display.Reset}");
        if (quarantineTriggered)
        {
            Console.WriteLine($"  {Display.Red}{Display.Bold}🔒 QUARANTINE TRIGGERED{Display.Reset} — bulk PHI access pattern detected");
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
