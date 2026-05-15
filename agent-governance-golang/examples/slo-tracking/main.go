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
	engine, err := agentmesh.NewSLOEngine([]agentmesh.SLOObjective{{
		Name:      "agent-availability",
		Indicator: agentmesh.SLOAvailability,
		Target:    0.95,
		Window:    time.Hour,
	}})
	if err != nil {
		log.Fatal(err)
	}

	for _, success := range []bool{true, true, true, false, true} {
		if err := engine.RecordEvent("agent-availability", success, 25*time.Millisecond); err != nil {
			log.Fatal(err)
		}
	}

	report, err := engine.Evaluate("agent-availability")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("SLO: %s\n", report.Name)
	fmt.Printf("Actual availability: %.0f%%\n", report.Actual*100)
	fmt.Printf("Target availability: %.0f%%\n", report.Target*100)
	fmt.Printf("Events: %d, met: %t\n", report.TotalEvents, report.Met)
	fmt.Printf("Error budget remaining: %.2f\n", report.ErrorBudgetRemaining)
}
