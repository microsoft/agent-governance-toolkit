// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"fmt"
	"log"
	"time"

	agentmesh "github.com/microsoft/agent-governance-toolkit/agent-governance-golang/packages/agentmesh"
)

func main() {
	// 1. Identity — every governed agent starts with a DID.
	identity, err := agentmesh.GenerateIdentity("worker-001", []string{"data.read", "data.write"})
	if err != nil {
		log.Fatalf("identity: %v", err)
	}
	agentID := identity.DID
	fmt.Printf("agent identity: %s\n", agentID)

	// 2. Rings — the agent is granted standard-ring permissions.
	rings := agentmesh.NewRingEnforcer()
	rings.SetRingPermissions(agentmesh.RingStandard, []string{"data.read"})
	rings.Assign(agentID, agentmesh.RingStandard)

	// 3. Trust — start at default, will record outcomes as operations run.
	trust := agentmesh.NewTrustManager(agentmesh.DefaultTrustConfig())

	// 4. Policy — allow data.read, review data.write, deny everything else.
	policy := agentmesh.NewPolicyEngine([]agentmesh.PolicyRule{
		{Action: "data.read", Effect: agentmesh.Allow},
		{Action: "data.write", Effect: agentmesh.Review},
		{Action: "*", Effect: agentmesh.Deny},
	})

	// 5. Kill switches — registry with no scopes active to start.
	killSwitches := agentmesh.NewKillSwitchRegistry()

	// 6. SLO — track availability over a 5-minute window with a 99% target.
	sloEngine, err := agentmesh.NewSLOEngine([]agentmesh.SLOObjective{{
		Name:      "data-read-availability",
		Indicator: agentmesh.SLOAvailability,
		Target:    0.99,
		Window:    5 * time.Minute,
	}})
	if err != nil {
		log.Fatalf("slo: %v", err)
	}

	// 7. Audit — tamper-evident log of every governed operation.
	audit := agentmesh.NewAuditLogger()

	// Drive the pipeline. GovernOperation composes the same middleware
	// stack used by the HTTP middleware example, but synchronously.
	run := func(label, action string) {
		ctx := map[string]interface{}{
			"agent_id":  agentID,
			"tool_name": action,
		}
		err := agentmesh.GovernOperation(
			action,
			ctx,
			policy,
			audit,
			sloEngine,
			"data-read-availability",
			func() error {
				if !rings.CheckAccess(agentID, action) {
					return fmt.Errorf("ring enforcer denied %s", action)
				}
				// Simulated work.
				return nil
			},
			agentmesh.WithGovernOperationKillSwitches(killSwitches),
		)
		decision := "allow"
		if err != nil {
			decision = err.Error()
			trust.RecordFailure(agentID, 0.1)
		} else {
			trust.RecordSuccess(agentID, 0.05)
		}
		score := trust.GetTrustScore(agentID)
		fmt.Printf("  %-20s action=%-12s -> %s | trust=%.3f (%s)\n",
			label, action, decision, score.Overall, score.Tier)
	}

	fmt.Println("\n-- ordinary operation --")
	run("read (allowed)", "data.read")
	run("write (review)", "data.write")
	run("escalate (deny)", "system.shutdown")

	fmt.Println("\n-- activate capability kill switch --")
	if _, err := killSwitches.Activate(
		agentmesh.CapabilityKillSwitchScope("data.read"),
		agentmesh.KillSwitchReasonSecurityIncident,
		"investigation in progress",
	); err != nil {
		log.Fatalf("activate kill switch: %v", err)
	}
	run("read after kill", "data.read")

	fmt.Println("\n-- summary --")
	report, err := sloEngine.Evaluate("data-read-availability")
	if err != nil {
		log.Fatalf("slo evaluate: %v", err)
	}
	fmt.Printf("  SLO %s: actual=%.2f target=%.2f met=%v error_budget_remaining=%.2f\n",
		report.Name, report.Actual, report.Target, report.Met, report.ErrorBudgetRemaining)
	fmt.Printf("  Audit chain intact: %v\n", audit.Verify())
	fmt.Printf("  Audit entries logged: %d\n", len(audit.GetEntries(agentmesh.AuditFilter{})))
	finalScore := trust.GetTrustScore(agentID)
	fmt.Printf("  Final trust score: %.3f (%s)\n", finalScore.Overall, finalScore.Tier)
}
